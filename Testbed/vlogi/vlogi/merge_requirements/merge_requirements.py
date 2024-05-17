import xml.etree.ElementTree as ET

from ._helper_functions import *
from copy import deepcopy
from utils import FAS, FAS_MERGED, EXTRACTED_REQUIREMENTS


def merge_requirements():
    # TODO Consider using only the ReachabilityProperties within topology_properties for better efficiency during preprocessing
    # TODO Consider consolidating all preprocessing steps iterating over extracted_properties into a single step for improved efficiency
    topology_tree = ET.parse(FAS)
    topology_graph = topology_tree.find(".//graph")
    topology_properties = topology_tree.find(".//PropertyDefinition")

    extracted_properties = ET.parse(EXTRACTED_REQUIREMENTS).getroot()

    ##### Preprocessing step 1 #####

    # For each IP in extracted properties, refine 'src' and 'dst' IPs
    # to the most specific IP (or subnet) found in the topology, ranging from exact match to /8 subnet.
    for eprop in extracted_properties:
        for position in ["src", "dst"]:
            ip = eprop.attrib[position].split(".")

            for i in range(len(ip) - 1, 0, -1):
                if topology_graph.find(f'./node[@name="{".".join(ip)}"]'):
                    eprop.attrib[position] = ".".join(ip)
                    break
                ip[i] = "-1"

    ##### Preprocessing step 2 #####

    # Build a dictionary from the topology containing all NATs.
    # Keys are the public IPs of the NATs, and values are lists of private IPs behind the corresponding NAT
    nats = topology_graph.findall("./node[@functional_type='NAT']")

    nat_ips = {}

    for nat in nats:
        name = nat.attrib["name"]

        sources = nat.findall(".//nat/source")
        source_ips = [source.text for source in sources]

        nat_ips[name] = source_ips

    ##### Preprocessing step 3 #####

    # Build a dictionary from the topology containing all loadbalancers.
    # Keys are load balancer IPs, and values are the IPs within their respective pools
    loadbalancers = topology_graph.findall("./node[@functional_type='LOADBALANCER']")

    loadbalancer_ips = {}

    for lb in loadbalancers:
        name = lb.attrib["name"]

        pool = lb.findall(".//loadbalancer/pool")
        pool_ips = [pool_ip.text for pool_ip in pool]

        loadbalancer_ips[name] = pool_ips

    ##### Preprocessing step 4 #####

    # Ensure missing attributes are set to "null" to simplify subsequent checks
    for eprop in extracted_properties:
        add_null_attributes(eprop)

    for tprop in topology_properties:
        add_null_attributes(tprop)

    ##### Preprocessing step 5 #####

    # Resolve NAT public IPs to corresponding private networks.
    # Assumption: Properties involving NATs are expected to be defined using private IP addresses
    nat_properties = []

    for eprop in extracted_properties:
        src_nat = eprop.attrib["src"] in nat_ips.keys()
        dst_nat = eprop.attrib["dst"] in nat_ips.keys()

        if src_nat and not dst_nat:
            private_srcs = find_all_nat_private_ips(
                topology_properties, eprop, "src", nat_ips
            )
            for private_src in private_srcs:
                nat_properties.append(
                    create_property_with_attributes(eprop.attrib, src=private_src)
                )

        elif dst_nat and not src_nat:
            private_dsts = find_all_nat_private_ips(
                topology_properties, eprop, "dst", nat_ips
            )
            for private_dst in private_dsts:
                nat_properties.append(
                    create_property_with_attributes(eprop.attrib, dst=private_dst)
                )

        elif src_nat and dst_nat:
            for private_src in nat_ips[eprop.attrib["src"]]:
                for private_dst in nat_ips[eprop.attrib["dst"]]:
                    for tprop in topology_properties:
                        if match_attributes(
                            tprop,
                            eprop,
                            private_ip=private_src,
                            opposite_ip=private_dst,
                        ):
                            nat_properties.append(
                                create_property_with_attributes(
                                    eprop.attrib, src=private_src, dst=private_dst
                                )
                            )

    # remove properties containing public NAT IPs, they're not needed anymore
    extracted_properties = [
        p
        for p in extracted_properties
        if (p.attrib["src"] not in nat_ips.keys())
        and (p.attrib["dst"] not in nat_ips.keys())
    ]

    extracted_properties.extend(nat_properties)

    ##### Preprocessing step 6 #####

    # Expand each Property referencing a load balancer by creating new Properties
    # using IPs from the load balancer's pool while preserving the original Property
    lb_properties = []

    for eprop in extracted_properties:
        src_lb = eprop.attrib["src"] in loadbalancer_ips.keys()
        dst_lb = eprop.attrib["dst"] in loadbalancer_ips.keys()

        if src_lb and not dst_lb:
            for lb_src_ip in loadbalancer_ips[eprop.attrib["src"]]:
                lb_properties.append(
                    create_property_with_attributes(eprop.attrib, src=lb_src_ip)
                )
        elif dst_lb and not src_lb:
            for lb_dst_ip in loadbalancer_ips[eprop.attrib["dst"]]:
                lb_properties.append(
                    create_property_with_attributes(eprop.attrib, dst=lb_dst_ip)
                )
        elif src_lb and dst_lb:
            for lb_src_ip in loadbalancer_ips[eprop.attrib["src"]] + [
                eprop.attrib["src"]
            ]:
                for lb_dst_ip in loadbalancer_ips[eprop.attrib["dst"]] + [
                    eprop.attrib["dst"]
                ]:
                    if (
                        lb_src_ip == eprop.attrib["src"]
                        and lb_dst_ip == eprop.attrib["dst"]
                    ):
                        continue
                    lb_properties.append(
                        create_property_with_attributes(
                            eprop.attrib, src=lb_src_ip, dst=lb_dst_ip
                        )
                    )

    extracted_properties.extend(lb_properties)

    ##### Merge properties #####

    merged_properties_list = list(topology_properties)

    for eprop in extracted_properties:
        index = 0
        while index < len(merged_properties_list):
            mprop = merged_properties_list[index]
            if match_exact_attributes(mprop, eprop):
                merged_properties_list.pop(index)
                break

            if match_attributes(mprop, eprop):
                merged_properties_list.pop(index)
                to_append = derive_reachability_properties(mprop, eprop)

                for ta in to_append:
                    append_if_not_duplicate(merged_properties_list, ta)
                break
            index += 1
        append_if_not_duplicate(merged_properties_list, eprop)

    ##### Clean up and write to file #####

    # Merged policies        ---> PropertyDefinition
    # Old PropertyDefinition ---> InitialProperty

    initial_property = deepcopy(topology_properties)
    initial_property.tag = "InitialProperty"
    root = topology_tree.getroot()
    topology_properties_idx = list(root).index(topology_properties)
    root.insert(topology_properties_idx + 1, initial_property)

    # Remove unnecessary attributes before writing result to file

    topology_properties.clear()

    for mprop in merged_properties_list:
        remove_null_attributes(mprop)
        topology_properties.append(mprop)

    topology_tree.write(FAS_MERGED)

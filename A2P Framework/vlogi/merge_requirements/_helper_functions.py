import xml.etree.ElementTree as ET


def match_lv4proto(lv4proto1, lv4proto2):
    if lv4proto1 == lv4proto2 or lv4proto1 == "ANY" or lv4proto1 == "null":
        return True
    else:
        return False


def match_ports(port1, port2):
    if port1 == "null":
        return True
    if port2 == "null":
        return False

    if "-" in port1:
        start1, end1 = map(int, port1.split("-"))
    else:
        start1 = end1 = int(port1)

    if "-" in port2:
        start2, end2 = map(int, port2.split("-"))
    else:
        start2 = end2 = int(port2)

    return start1 <= start2 and end2 <= end1


def match_attributes(
    prop1,
    prop2,
    nat_position="src",
    private_ip=None,
    opposite_ip=None,
    match_property_name=False,
):
    opposite_position = "src" if nat_position == "dst" else "dst"
    private_ip = private_ip if private_ip else prop2.attrib["src"]
    opposite_ip = opposite_ip if opposite_ip else prop2.attrib["dst"]

    conditions = [
        prop1.attrib["name"] == prop2.attrib["name"]
        if match_property_name
        else prop1.attrib["name"] == "ReachabilityProperty",
        prop1.attrib[nat_position] == private_ip,
        prop1.attrib[opposite_position] == opposite_ip,
        match_lv4proto(prop1.attrib["lv4proto"], prop2.attrib["lv4proto"]),
        match_ports(prop1.attrib["src_port"], prop2.attrib["src_port"]),
        match_ports(prop1.attrib["dst_port"], prop2.attrib["dst_port"]),
    ]

    return all(conditions)


def match_exact_attributes(prop1, prop2):
    conditions = [
        prop1.attrib["name"] == "ReachabilityProperty",
        prop1.attrib["src"] == prop2.attrib["src"],
        prop1.attrib["dst"] == prop2.attrib["dst"],
        prop1.attrib["lv4proto"] == prop2.attrib["lv4proto"],
        prop1.attrib["src_port"] == prop2.attrib["src_port"],
        prop1.attrib["dst_port"] == prop2.attrib["dst_port"],
    ]

    return all(conditions)


def find_all_nat_private_ips(topology_properties, eprop, nat_position, nat_ips):
    opposite_position = "src" if nat_position == "dst" else "dst"
    private_ips = []

    for private_ip in nat_ips[eprop.attrib[nat_position]]:
        for tprop in topology_properties:
            if match_attributes(
                tprop,
                eprop,
                nat_position,
                private_ip,
                eprop.attrib[opposite_position],
            ):
                private_ips.append(private_ip)

    return private_ips


def create_ranges(port_value, port_range):
    port_value = int(port_value)

    (start, end) = (map(int, port_range.split("-"))) if port_range else (0, 65535)

    if port_value == start:
        return None, f"{start+1}-{end}"
    elif port_value == start + 1:
        return f"{start}", f"{port_value+1}-{end}"
    elif port_value == end - 1:
        return f"{start}-{port_value-1}", f"{end}"
    elif port_value == end:
        return f"{start}-{end-1}", None
    else:
        return f"{start}-{port_value-1}", f"{port_value+1}-{end}"


def create_property_with_attributes(base_attribs, **additional_attribs):
    prop = ET.Element("Property", **{**base_attribs, **additional_attribs})

    add_null_attributes(prop)

    return prop


def add_null_attributes(prop):
    if "lv4proto" not in prop.attrib:
        prop.set("lv4proto", "null")
    if "src_port" not in prop.attrib:
        prop.set("src_port", "null")
    if "dst_port" not in prop.attrib:
        prop.set("dst_port", "null")


def remove_null_attributes(prop):
    if "lv4proto" in prop.attrib and prop.attrib["lv4proto"] == "null":
        del prop.attrib["lv4proto"]
    if "src_port" in prop.attrib and prop.attrib["src_port"] == "null":
        del prop.attrib["src_port"]
    if "dst_port" in prop.attrib and prop.attrib["dst_port"] == "null":
        del prop.attrib["dst_port"]


def create_property_with_ports(base_attribs, port_type, port_value, port_range):
    properties = []
    range1, range2 = create_ranges(port_value, port_range)

    if range1:
        property1 = create_property_with_attributes(base_attribs, **{port_type: range1})
        properties.append(property1)

    if range2:
        property2 = create_property_with_attributes(base_attribs, **{port_type: range2})
        properties.append(property2)

    return properties


def derive_reachability_properties(mprop, eprop):
    mproto = mprop.attrib["lv4proto"]
    eproto = eprop.attrib["lv4proto"]
    msrc_port = mprop.attrib["src_port"]
    esrc_port = eprop.attrib["src_port"]
    mdst_port = mprop.attrib["dst_port"]
    edst_port = eprop.attrib["dst_port"]

    base_attribs = {
        "graph": "0",
        "name": "ReachabilityProperty",
        "src": eprop.attrib["src"],
        "dst": eprop.attrib["dst"],
        "lv4proto": eproto,
    }

    properties = []

    if eproto == "TCP" and mproto == "null":
        for p in ["UDP", "OTHER"]:
            properties.append(create_property_with_attributes(base_attribs, lv4proto=p))
    elif eproto == "UDP" and mproto == "null":
        for p in ["TCP", "OTHER"]:
            properties.append(create_property_with_attributes(base_attribs, lv4proto=p))
    elif eproto == "OTHER" and mproto == "null":
        for p in ["TCP", "UDP"]:
            properties.append(create_property_with_attributes(base_attribs, lv4proto=p))

    src_port_elements = []
    dst_port_elements = []

    if esrc_port != "null":
        src_port_elements.extend(
            create_property_with_ports(
                base_attribs,
                "src_port",
                esrc_port,
                None if msrc_port == "null" else msrc_port,
            )
        )

    if edst_port != "null":
        dst_port_elements.extend(
            create_property_with_ports(
                base_attribs,
                "dst_port",
                edst_port,
                None if mdst_port == "null" else mdst_port,
            )
        )

    if not src_port_elements:
        properties.extend(dst_port_elements)
    elif not dst_port_elements:
        properties.extend(src_port_elements)
    else:
        for spe in src_port_elements:
            for dpe in dst_port_elements:
                element = create_property_with_attributes(
                    base_attribs,
                    src_port=spe.attrib["src_port"],
                    dst_port=dpe.attrib["dst_port"],
                )
                properties.append(element)

    return properties


def append_if_not_duplicate(properties, property_to_append):
    for prop in properties:
        if match_attributes(prop, property_to_append, match_property_name=True):
            return
    properties.append(property_to_append)

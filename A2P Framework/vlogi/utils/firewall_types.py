from enum import Enum
from .paths import VNETWORK


class FirewallTypes(Enum):
    # FORTINET = "FORTINET"
    # IPFIREWALL = "IPFIREWALL"
    IPTABLES = "IPTABLES"
    # EBPF = "EBPF"
    # OPENVSWITCH = "OPENVSWITCH"


FIREWALL_CONFIG = f"{VNETWORK}/FirewallConfig"
BASE_URL = "http://localhost:8086/verefoo/fwd/deploy"

DOCKER_COMPOSE_FILES = {
    # "FORTINET": f"{VNETWORK_FOLDER}/docker-compose-fortinet.yml",
    # "IPFIREWALL": f"{VNETWORK_FOLDER}/docker-compose-ipfirewall.yml",
    "IPTABLES": f"{VNETWORK}/docker-compose-iptables.yml",
    # "EBPF": f"{VNETWORK_FOLDER}/docker-compose-ebpf.yml",
    # "OPENVSWITCH": f"{VNETWORK_FOLDER}/docker-compose-openvswitch.yml",
}
FWCONFIG_REQUEST_URLS = {
    # "FORTINET": f"{BASE_URL}/getFortinet/{{}}",
    # "IPFIREWALL": f"{BASE_URL}/getIpfw/{{}}",
    "IPTABLES": f"{BASE_URL}/getIptables/{{}}",
    # "EBPF": f"{BASE_URL}/getBpfFirewall/{{}}",
    # "OPENVSWITCH": f"{BASE_URL}/getOpenVswitch/{{}}"
}
FWCONFIG_FILES = {
    # "FORTINET": f"{FIREWALL_CONFIG}/fortinet/fortinetFirewall_{{}}_{{}}.sh",
    # "IPFIREWALL": f"{FIREWALL_CONFIG}/ipfirewall/ipFirewall_{{}}_{{}}.sh",
    "IPTABLES": f"{FIREWALL_CONFIG}/iptables/iptablesFirewall_{{}}_{{}}.sh",
    # "EBPF": f"{FIREWALL_CONFIG}/ebpf/ebpfFirewall_{{}}_{{}}.sh",
    # "OPENVSWITCH": f"{FIREWALL_CONFIG}/openvswitch/openvswitchFirewall_{{}}_{{}}.sh"
}

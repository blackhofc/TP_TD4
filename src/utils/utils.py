from scapy.all import conf

def get_interface_by_ipv4(ipv4_address):
    for iface in conf.ifaces.values():
        if iface.ip == ipv4_address:
            return iface.name
    return None
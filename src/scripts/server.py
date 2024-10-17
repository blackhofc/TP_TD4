from scapy.all import *

def listen(interface = 'Software Loopback Interface 1', listen_port = 8000):
    # Print available interfaces
    print(conf.ifaces)

    print(f'Listening for TCP packets on port {listen_port}.')

    filter_str = f'tcp port {listen_port}'

    # Listen incoming packets from port
    pkt_rcv = sniff(iface = interface, filter=filter_str, prn=lambda x: x.show(), count=1, timeout=60)
    
    print(f'\n Packet recived\n {pkt_rcv}')
    


def start():
    print('server.py')
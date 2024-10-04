from scapy.all import *
from utils.utils import insecure_packet_sending

# Set parameters
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 8000
src_port = 5000

def run():

    # Creamos la parte de IP
    ip = IP(dst=dest_ip,src =source_ip)

    # Creamos la parte de TCP
    tcp = TCP(dport=dest_port, sport =src_port)


    # Los combinamos
    packet = ip/tcp


    # Send packet
    insecure_packet_sending(packet)
    print('sent')
from scapy.all import *
from utils.utils import insecure_packet_sending

def send(src_ip = '127.0.0.1', dst_ip = '127.0.0.1', src_port = 5000, dst_port = 8000):

    # Make IP
    ip = IP(dst = dst_ip, src = src_ip)

    # Make TCP
    tcp = TCP(dport = dst_port, sport = src_port)

    # Create packet
    packet = ip/tcp

    # Send packet
    insecure_packet_sending(packet)

    print('1 Packet sent!')
    

def start():
    print('client.py')
    
    # Send syn
    # Wait for Syn + ACK
    # Send Ack
    
    # Wait max 20 secs to recive FIN
    # Send FIN+ACK
    # Wait ACK
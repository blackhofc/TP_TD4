from scapy.all import *
from utils.utils import print_error_stats
import canalruidoso as f
import time

class Client:
    def __init__(self, interface='Software Loopback Interface 1', src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=5000, dst_port=8000):
        self.interface = interface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 100  # Initial sequence number for the client
        self.ack_num = 0    # Acknowledgment number

    def handshake(self):
        # Send SYN
        self.send_syn()

        # Wait for SYN+ACK
        self.wait_for_syn_ack()

        # Send ACK to complete the handshake
        self.send_ack()

        # Wait for FIN or retransmit ACK
        self.wait_for_fin()

    def send_syn(self):
        syn = TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=self.seq_num)
        f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/syn)
        print("SYN sent!")

    def wait_for_syn_ack(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=10)
            
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'SA':  # Check for SYN+ACK
                ip_response = pkt[0][IP]
                tcp_response = pkt[0][TCP]
                print(f'SYN+ACK received! from {ip_response.src}:{tcp_response.sport}')
                self.ack_num = tcp_response.seq + 1
                break
            else:
                print("SYN+ACK not received, retransmitting SYN...")
                self.send_syn()

    def send_ack(self):
        ack = TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.seq_num + 1, ack=self.ack_num)
        f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/ack)
        print("ACK sent! Handshake complete.")

    def wait_for_fin(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=20)
            
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'F':  # Check for FIN
                ip_response = pkt[0][IP]
                tcp_response = pkt[0][TCP]
                print(f'FIN received! from {ip_response.src}:{tcp_response.sport}')
                self.ack_num = tcp_response.seq + 1
                break
            else:
                print("FIN not received, retransmitting ACK...")
                self.send_ack()

        self.send_fin_ack()

    def send_fin_ack(self):
        fin_ack = TCP(sport=self.src_port, dport=self.dst_port, flags='FA', seq=self.seq_num + 2, ack=self.ack_num)
        f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/fin_ack)
        print("FIN+ACK sent! Waiting for ACK...")

        self.wait_for_ack()

    def wait_for_ack(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=3)
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'A':  # Check for ACK
                print("ACK received! Connection closed.")
                break
            else:
                print("ACK not received, retransmitting FIN+ACK...")
                self.send_fin_ack()

    def start(self):
        print('Starting client...')
        self.handshake()

if __name__ == "__main__":
    client = Client()
    client.start()

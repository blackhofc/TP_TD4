from scapy.all import *
from utils.utils import print_stats, wrapper_send

class Server:
    def __init__(self, interface='Software Loopback Interface 1', src_ip='127.0.0.1', dst_ip='127.0.0.1', listen_port=8000, dst_port=5000):
        self.interface = interface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.listen_port = listen_port
        self.dst_port = dst_port
        self.seq_num = 100  # Initial sequence number for the server
        self.ack_num = 0    # Acknowledgment number
        self.state = "WAITING"

    def handle_state(self):
        while True:
            if self.state == "WAITING":
                self.wait_for_syn()
            elif self.state == "SYN_RECEIVED":
                self.wait_for_ack()
            elif self.state == "CLOSE_WAIT":
                self.close_connection()
                break

    def wait_for_syn(self):
        print(f'Listening on port {self.listen_port}...')
        pkt = sniff(iface=self.interface, filter=f'tcp port {self.listen_port}', count=1, timeout=60)
        if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'S':
            ip_request = pkt[0][IP]
            tcp_request = pkt[0][TCP]
            print(f'[SYN] received from {ip_request.src}:{tcp_request.sport}')
            self.ack_num = tcp_request.seq + 1
            
            syn_ack = TCP(sport=self.listen_port, dport=tcp_request.sport, flags='SA', seq=self.seq_num, ack=self.ack_num)
            wrapper_send(IP(dst=ip_request.src, src=self.src_ip)/syn_ack)
            print(f'[SYN+ACK] sent')
            self.state = "SYN_RECEIVED"  # Transition to next state

    def wait_for_ack(self):
        pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip}', count=1, timeout=6)
        if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'A':
            self.ack_num = pkt[0][TCP].seq + 1
            print(f'[ACK] received from {pkt[0][IP].src}:{pkt[0][TCP].sport} Handshake complete!')
            self.state = "CLOSE_WAIT"  # Transition to close wait
        else:
            print('[ACK] not received, waiting for ACK...')

    def close_connection(self):
        # Send FIN
        fin = TCP(dport=self.dst_port, sport=self.listen_port, flags='F', seq=self.seq_num + 1)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/fin)
        print(f'[FIN] sent, Waiting for [FIN+ACK]...')
        self.wait_for_fin_ack()

        # Send ACK to complete closure
        ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='A', seq=self.seq_num + 2)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/ack)
        print('[ACK] sent, Connection closed.')

    def wait_for_fin_ack(self):
        pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=6)
        if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'FA':
            print(f'[FIN+ACK] received from {pkt[0][IP].src}:{pkt[0][TCP].sport}')
        else:
            print('[FIN+ACK] not received, retransmitting [FIN]...')
            self.close_connection()

    def start(self):
        print('Starting server...')
        self.handle_state()


if __name__ == '__main__':
    server = Server()
    server.start()

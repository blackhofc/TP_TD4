import time
from scapy.all     import *
from utils.utils   import get_interface_by_ipv4
from utils.wrapper import print_stats, send

class Client:
    def __init__(self, src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=5000, dst_port=8000):
        self.interface = get_interface_by_ipv4('127.0.0.1')
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 100  # Initial sequence number for the client
        self.ack_num = 0    # Acknowledgment number
        self.state = 'INITIAL'

    def send_syn(self):
        syn = TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=self.seq_num)
        send(IP(dst=self.dst_ip, src=self.src_ip)/syn)
        print('[SYN] sent')
        self.state = 'SYN_SENT'

    def send_ack(self):
        ack = TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.seq_num + 1, ack=self.ack_num)
        send(IP(dst=self.dst_ip, src=self.src_ip)/ack)
        print('[ACK] sent')
        self.state = 'ACK_SENT'
        
    def send_fin_ack(self):
        fin_ack = TCP(sport=self.src_port, dport=self.dst_port, flags='FA', seq=self.seq_num + 1, ack=self.ack_num)
        send(IP(dst=self.dst_ip, src=self.src_ip)/fin_ack)
        print('[FIN+ACK] sent')
        self.state = 'FIN_ACK_SENT'
        

    def handle_state(self):
        while True:
            timeout = 6
            print('\nClient state:', self.state)
            
            if self.state == 'CLOSED':
                break

            if self.state in ['INITIAL', 'SYN_SENT']:
                self.send_syn()
            elif self.state in ['SYN_ACK_RECEIVED', 'ACK_SENT']:
                self.send_ack()
                timeout=20
            elif self.state in ['FIN_RECEIVED', 'FIN_ACK_SENT']:
                self.send_fin_ack()
            
            self.sniff(timeout)
    
    def sniff(self, timeout=6):
        pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=timeout)
        
        FLAG   = pkt[0][TCP].flags if pkt and TCP in pkt[0] else None
        IP_V   = pkt[0][IP]        if pkt and IP  in pkt[0] else None
        TCP_V  = pkt[0][TCP]       if pkt and TCP in pkt[0] else None

        # Case [SYN+ACK] server received my SYN, send ACK
        if FLAG == 'SA':
            print(f'[SYN+ACK] received from {IP_V.src}:{TCP_V.sport}')
            self.state = 'SYN_ACK_RECEIVED'
            self.ack_num = TCP_V.seq + 1
            
        # Case [FIN] server wants to close connection, send FIN+ACK
        elif FLAG == 'F':
            print(f'[FIN] received from {IP_V.src}:{TCP_V.sport}')
            self.state = 'FIN_RECEIVED'
            
        # Case [ACK] server acked my FIN+ACK
        elif FLAG == 'A':
            print(f'[ACK] received from {IP_V.src}:{TCP_V.sport} Connection closed.')
            self.state = 'CLOSED'
        
        else:
            print(f'Missed expected packet, retransmit')

    def start(self):
        print(f'Starting client, listening interface "{self.interface}"')

        self.handle_state()
        
        print_stats()

if __name__ == '__main__':
    client = Client()
    client.start()

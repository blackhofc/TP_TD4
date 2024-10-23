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
        self.state = 'WAITING'

    def send_syn_ack(self):
        syn_ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='SA', seq=self.seq_num, ack=self.ack_num)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/syn_ack)
        print(f'[SYN+ACK] sent')
        self.state = 'SYN_ACK_SENT'
        
    def send_fin(self):
        syn_ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='F', seq=self.seq_num, ack=self.ack_num)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/syn_ack)
        print(f'[FIN] sent')
        self.state = 'CLOSE_WAIT'
        
    def send_ack(self):
        syn_ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='A', seq=self.seq_num, ack=self.ack_num)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/syn_ack)
        print(f'[ACK] sent')
        self.state = 'TIME_WAIT'


    def handle_state(self):
        while True:
            timeout = 6
            print('\nServer state:', self.state)
            
            if self.state == 'TIME_WAIT':
                break

            if self.state == 'WAITING':
                timeout = 60
            elif self.state in ['SYN_RECEIVED', 'SYN_ACK_SENT']:
                self.send_syn_ack()
            elif self.state in ['ACK_RECEIVED', 'CLOSE_WAIT']:
                # time.sleep(20) 
                self.send_fin()
            elif self.state == 'FIN_ACK_RECEIVED':
                self.send_ack()
                timeout = 120
            
            self.sniff(timeout)

    def sniff(self, timeout=6):
        pkt = sniff(iface=self.interface, filter=f'tcp port {self.listen_port}', count=1, timeout=timeout)
        
        FLAG = pkt[0][TCP].flags if pkt and TCP in pkt[0] else None
        IP_V  = pkt[0][IP]       if pkt and IP  in pkt[0] else None
        TCP_V  = pkt[0][TCP]     if pkt and TCP in pkt[0] else None
        
        # Case [SYN] client sent connect
        if FLAG == 'S':
            print(f'[SYN] received from {IP_V.src}:{IP_V.sport}')
            self.state = 'SYN_RECEIVED'
            self.ack_num = TCP_V.seq + 1
            
        # Case [ACK] client acked my SYN+ACK
        elif FLAG == 'A':
            print(f'[ACK] received from {IP_V.src}:{IP_V.sport}')
            self.state = 'ACK_RECEIVED'
            
        # Case [FYN+ACK] client acked my FIN and sent FIN
        elif FLAG == 'FA':
            print(f'[FYN+ACK] received from {IP_V.src}:{IP_V.sport}')
            self.state = 'FIN_ACK_RECEIVED'
        else:
            print(f'Missed expected packet, retransmit')

    def start(self):
        print(f'Starting server, listening port {self.listen_port}...')
        self.handle_state()
        
        print_stats()
        

if __name__ == '__main__':
    server = Server()
    server.start()
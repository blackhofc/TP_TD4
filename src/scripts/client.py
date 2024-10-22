from scapy.all import *
from utils.utils import print_stats, wrapper_send
import time

'''
WAITING: The initial state where the server waits for a SYN packet.
SYN_RECEIVED: State after receiving a SYN packet.
SYN_ACK_SENT: State after sending SYN-ACK.
ACK_RECEIVED: State after receiving an ACK packet.
CLOSE_WAIT: State after sending FIN and waiting for a FIN-ACK.
FIN_RECEIVED: State after receiving a FIN packet.
Transitions:

From WAITING to SYN_RECEIVED on receiving SYN.
From SYN_RECEIVED to SYN_ACK_SENT after sending SYN-ACK.
From SYN_ACK_SENT to ACK_RECEIVED on receiving ACK.
From ACK_RECEIVED to CLOSE_WAIT on sending FIN.
From CLOSE_WAIT to FIN_RECEIVED on receiving FIN.
From FIN_RECEIVED to WAITING after sending final ACK.

'''


class Client:
    def __init__(self, interface='Software Loopback Interface 1', src_ip='127.0.0.1', dst_ip='127.0.0.1', src_port=5000, dst_port=8000):
        self.interface = interface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = 100  # Initial sequence number for the client
        self.ack_num = 0    # Acknowledgment number
        self.state = 'INITIAL'

    def send_syn(self):
        syn = TCP(sport=self.src_port, dport=self.dst_port, flags='S', seq=self.seq_num)
        wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/syn)
        print('[SYN] sent')
        self.state = "SYN_SENT"


    def send_ack(self):
        if self.state == "SYN_ACK_RECEIVED":
            ack = TCP(sport=self.src_port, dport=self.dst_port, flags='A', seq=self.seq_num + 1, ack=self.ack_num)
            wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/ack)
            print('[ACK] sent, Handshake complete.')
            self.state = "ACK_SENT"  # Update state after sending ACK
        else:
            print('Cannot send ACK: SYN+ACK not received.')

    def wait_for_fin(self):
        pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=26)
        if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'F':
            ip_response = pkt[0][IP]
            tcp_response = pkt[0][TCP]
            print(f'FIN received from {ip_response.src}:{tcp_response.sport}')
            self.ack_num = tcp_response.seq + 1
            self.send_fin_ack()
        else:
            print('FIN not received, retransmitting ACK...')
            self.send_ack()

    def send_fin_ack(self):
        if self.state == "ACK_SENT":
            fin_ack = TCP(sport=self.src_port, dport=self.dst_port, flags='FA', seq=self.seq_num + 2, ack=self.ack_num)
            wrapper_send(IP(dst=self.dst_ip, src=self.src_ip)/fin_ack)
            print('[FIN+ACK] sent, Waiting for ACK...')
            self.wait_for_ack()
        else:
            print('Cannot send FIN+ACK: ACK not sent.')

    def wait_for_ack(self):
        pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=6)
        if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'A':
            print(f'[ACK] received from {pkt[0][IP].src}:{pkt[0][TCP].sport} Connection closed.')
        else:
            print('[ACK] not received, retransmitting [FIN+ACK]...')
            self.send_fin_ack()


    def handle_state(self):
        while True:
            if self.state == "INITIAL":
                self.send_syn()
            elif self.state == "SYN_SENT":
                self.listen()
            elif self.state == "SYN_ACK_RECEIVED":
                self.send_ack()
            elif self.state == "ACK_SENT":
                self.listen()
            elif self.state == "FIN_WAIT":
                self.send_fin_ack()
            elif self.state == "CLOSED":
                break
    
    def listen(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=6)
            
            FLAG         = pkt[0][TCP].flags if pkt and TCP in pkt[0]  else None
            IP  = pkt[0][IP]        if pkt and IP  in pkt[0]  else None
            TCP = pkt[0][TCP]       if pkt and TCP in pkt[0]  else None
            
            # Case [SYN+ACK] server received my SYN, send ACK
            if FLAG == 'SA':
                self.state = 'SYN_ACK_RECEIVED'
                print(f'[SYN+ACK] received from {IP.src}:{TCP.sport}')
                
            # Case [FIN] server wants to close connection, send FIN+ACK
            elif FLAG == 'FIN':
                self.state = 'FIN_WAIT'
                print(f'[FIN] received from {IP.src}:{TCP.sport}')
                
            # Case [ACK] server acked my FIN+ACK
            elif FLAG == 'ACK':
                self.state = "CLOSED"
                print(f'[ACK] received from {IP.src}:{TCP.sport} Connection closed.')
                break
            
            else:
                print(f'Didnt recveived expected packet, retransmit {self.state}')
            
                
    def start(self):
        print('Starting client...')

        self.handle_state()
        
        print_stats()


if __name__ == '__main__':
    client = Client()
    client.start()
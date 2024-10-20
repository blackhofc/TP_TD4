from scapy.all import *
from utils.utils import print_error_stats
import canalruidoso as f


class Server:
    def __init__(self, interface='Software Loopback Interface 1', src_ip='127.0.0.1', dst_ip='127.0.0.1', listen_port=8000, dst_port=5000):
        self.interface = interface
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.listen_port = listen_port
        self.dst_port = dst_port
        self.seq_num = 100  # Initial sequence number for the server
        self.ack_num = 0    # Acknowledgment number

    def wait_for_syn(self):
        print(f'Listening for SYN on port {self.listen_port}...')
        
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp port {self.listen_port}', count=1, timeout=60)
            
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'S':  # Check for SYN
                ip_request = pkt[0][IP]
                tcp_request = pkt[0][TCP]
                print(f'SYN received! from {ip_request.src}:{tcp_request.sport}')

                # Send SYN+ACK
                self.ack_num = tcp_request.seq + 1
                syn_ack = TCP(sport=self.listen_port, dport=tcp_request.sport, flags='SA', seq=self.seq_num, ack=self.ack_num)
                f.envio_paquetes_inseguro(IP(dst=ip_request.src, src=self.src_ip)/syn_ack)
                print(f'SYN+ACK sent! to {ip_request.src}:{tcp_request.sport}')
                
                # Wait for ACK
                self.wait_for_ack()
                break

    def wait_for_ack(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip}', count=1, timeout=4)
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'A':  # Check for ACK
                self.ack_num = pkt[0][TCP].seq + 1
                print('ACK received! Handshake complete.')
                break
            else:
                print('ACK not received, retransmitting SYN+ACK...')
                syn_ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='SA', seq=self.seq_num, ack=self.ack_num)
                f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/syn_ack)
                print(f'SYN+ACK sent! to {self.dst_ip}:{self.dst_port}')

    def close_connection(self):
        print('Closing connection...')
        
        # Send FIN
        fin = TCP(dport=self.dst_port, sport=self.listen_port, flags='F', seq=self.seq_num + 1)
        f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/fin)
        print(f'FIN sent! to {self.dst_ip}:{self.dst_port} Waiting for FIN+ACK...')

        # Wait for FIN+ACK from the client
        self.wait_for_fin_ack()

        # Send ACK to complete closure
        ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='A', seq=self.seq_num + 2)
        f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/ack)
        print('ACK sent! Waiting 120 secs in wait_close before closing')

        # Wait for potential retransmissions of SYN+ACK
        self.wait_for_retransmission()

        print('Exit timeout state, Connection closed.')

    def wait_for_fin_ack(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=4)
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'FA':  # Check for FIN+ACK
                print('FIN+ACK received! Sending ACK.')
                break
            else:
                print('FIN+ACK not received, retransmitting FIN...')
                fin = TCP(dport=self.dst_port, sport=self.listen_port, flags='F', seq=self.seq_num + 1)
                f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/fin)

    def wait_for_retransmission(self):
        while True:
            pkt = sniff(iface=self.interface, filter=f'tcp and src {self.dst_ip} and port {self.dst_port}', count=1, timeout=120)
            if pkt and TCP in pkt[0] and pkt[0][TCP].flags == 'SA':  # Check for retransmitted SYN+ACK
                print('SYN+ACK received, retransmitting ACK...')
                ack = TCP(sport=self.listen_port, dport=self.dst_port, flags='A', seq=self.seq_num + 2)
                f.envio_paquetes_inseguro(IP(dst=self.dst_ip, src=self.src_ip)/ack)
                continue
            break

    def start(self):
        print('Starting server...')
        self.wait_for_syn()
        
        print('FIN in 20 secoonds')
        time.sleep(5)

        # Close connection
        self.close_connection()

if __name__ == '__main__':
    server = Server()
    server.start()
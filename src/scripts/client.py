import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import * # Correr pip install scapy en la terminal

# Elegimos parametros
source_ip = '127.0.0.1'
dest_ip = '127.0.0.1'
dest_port = 8000
src_port = 5000

# Creamos la parte de IP
ip = IP(dst=dest_ip,src =source_ip)

# Creamos la parte de TCP
tcp = TCP(dport=dest_port, sport =src_port)


# Los combinamos
packet = ip/tcp


# 'Enviamos' el paquete
f.envio_paquetes_inseguro(packet)

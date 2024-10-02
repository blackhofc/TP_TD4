from scapy.all import *
import canalruidoso as f

# Mostramos todas las interfaces
print(conf.ifaces)

interface = 'Software Loopback Interface 1' # Esto lo tienen que completar con el nombre de la interfaz que tenga el 127.0.0.1 si se recibe el paquete en la misma computadora que lo envio.

listen_port = 8000  # Elegir el puerto que esta escuchando

print(f'Listening for TCP packets on port {listen_port}...')
filter_str = f'tcp port {listen_port}'

# Escuchar en ese puerto
pkt_capturado = sniff(iface = interface, filter=filter_str, prn=lambda x: x.show(), count=1, timeout=60)




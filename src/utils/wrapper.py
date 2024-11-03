import random, time
import canalruidoso as f # Correr pip install canalruidoso en la terminal
from scapy.all import send, TCP

stats = {
    'total_packets': 0,
    'lost_packets': 0,
    'corrupted_packets': 0,
    'delayed_packets': 0,
    'total_delay_time': 0,
}

def print_stats():
    if stats['total_packets'] == 0:
        print('No se han enviado paquetes.')
        return
    
    print('\n----------Resultados----------')

    # Cálculo de los porcentajes
    loss_percent = (stats['lost_packets'] / stats['total_packets']) * 100
    corrupted_percent = (stats['corrupted_packets'] / stats['total_packets']) * 100
    delayed_percent = (stats['delayed_packets'] / stats['total_packets']) * 100
    normal_percent = 100 - (loss_percent + corrupted_percent + delayed_percent)
    
    # Cálculo del delay promedio (solo si hubo retrasos)
    delay_promedio = stats['total_delay_time'] / stats['delayed_packets'] if stats['delayed_packets'] > 0 else 0
    
    print(f'Total de paquetes enviados: {stats['total_packets']}')
    print(f'Paquetes perdidos: {loss_percent:.2f}%')
    print(f'Paquetes corruptos: {corrupted_percent:.2f}%')
    print(f'Paquetes retrasados: {delayed_percent:.2f}%')
    print(f'Paquetes normales: {normal_percent:.2f}%')
    print(f'Delay promedio (si hay retrasos): {delay_promedio:.4f} segundos')

    
def send(pkt):
    # Incrementar el total de paquetes enviados
    stats['total_packets'] += 1
    
    # Medir el tiempo antes de enviar el paquete
    initial_time  = time.time()

    # Llamar a la función envio_paquetes_inseguro
    result = f.envio_paquetes_inseguro(pkt)

    # Medir el tiempo después del envío para ver si hubo retraso
    end_time = time.time()
    elapsed = end_time - initial_time 

    # Si el paquete se perdió
    if result == 0:
        stats['lost_packets'] += 1
        return
    
    # Qué un paquete llegue con delay lo definimos como que tarde más de 3 segundos en llegar
    if elapsed > 3:
        stats['delayed_packets'] += 1
        stats['total_delay_time'] += (elapsed - 1)
        return
        
    # Si el paquete fue corrompido, se puede verificar con el checksum
    if pkt[TCP].chksum == 0x1234:
        stats['corrupted_packets'] += 1
        return
    
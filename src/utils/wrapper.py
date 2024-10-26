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
    porcentaje_perdida = (stats['lost_packets'] / stats['total_packets']) * 100
    porcentaje_corrupcion = (stats['corrupted_packets'] / stats['total_packets']) * 100
    porcentaje_retraso = (stats['delayed_packets'] / stats['total_packets']) * 100
    porcentaje_normal = 100 - (porcentaje_perdida + porcentaje_corrupcion + porcentaje_retraso)
    
    # Cálculo del delay promedio (solo si hubo retrasos)
    delay_promedio = stats['total_delay_time'] / stats['delayed_packets'] if stats['delayed_packets'] > 0 else 0
    
    print(f'Total de paquetes enviados: {stats['total_packets']}')
    print(f'Paquetes perdidos: {porcentaje_perdida:.2f}%')
    print(f'Paquetes corruptos: {porcentaje_corrupcion:.2f}%')
    print(f'Paquetes retrasados: {porcentaje_retraso:.2f}%')
    print(f'Paquetes normales: {porcentaje_normal:.2f}%')
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

    # Si el paquete se perdió, actualizamos el contador de pérdidas
    if result == 0:
        stats['lost_packets'] += 1
        return
    
    # Si hubo retraso (se asume un tiempo normal de envío de 1 segundo)
    if elapsed > 4:
        stats['delayed_packets'] += 1
        stats['total_delay_time'] += (elapsed - 1)
        return
        
    # Si el paquete fue corrompido, se puede verificar con el checksum
    if pkt[TCP].chksum == 0x1234:
        stats['corrupted_packets'] += 1
        return
    
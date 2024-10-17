import random, time
from scapy.all import send

error_stats = {
    'normal': 0,
    'delay': 0,
    'corrupt': 0,
    'loss': 0,
    'total': 0,
    'total_delay': 0
}


def print_error_stats():
    global error_stats
    total_packets = error_stats['total']
    loss_rate = (error_stats['loss'] / total_packets) * 100 if total_packets > 0 else 0
    corrupt_rate = (error_stats['corrupt'] / total_packets) * 100 if total_packets > 0 else 0
    delay_rate = (error_stats['delay'] / total_packets) * 100 if total_packets > 0 else 0
    avg_delay = error_stats['total_delay'] / error_stats['delay'] if error_stats['delay'] > 0 else 0

    print(f"Total packets sent: {total_packets}")
    print(f"Packet loss rate: {loss_rate:.2f}%")
    print(f"Packet corruption rate: {corrupt_rate:.2f}%")
    print(f"Delay rate: {delay_rate:.2f}%")
    print(f"Average delay (seconds): {avg_delay:.2f}")
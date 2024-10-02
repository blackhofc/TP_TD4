from scapy.all import *
from threading import Thread
import random, time

def insecure_packet_sending(pkt):
    # Define probabilities for packet handling
    packet_handling_probs = {
        'Normal': 65,
        'Delay': 14,
        'Corrupt': 12,
        'Loss': 9
    }
    
    # Define constants
    delay_time = 4
    base_time_value = 1
    
    # Randomly select a packet handling outcome based on probabilities
    outcome = random.choices(
        list(packet_handling_probs.keys()), 
        list(packet_handling_probs.values())
    )[0]
    
    # Handle packet outcomes
    if outcome == 'Loss':  # Packet is lost
        return
    
    if outcome == 'Corrupt':  # Packet gets corrupted
        pkt[TCP].chksum = 0x1234
        
    if outcome == 'Delay':  # Packet is delayed
        base_time_value += delay_time
    
    # Apply the delay before sending the packet
    time.sleep(base_time_value)
    
    # Send the packet
    send(pkt, count=1)
import random
import time
from threading import Thread
from scapy.all import *

def insecure_packet_sending(pkt):

    delay_percentage = 14
    corruption_percentage = 12
    loss_percentage = 9
    normal_percentage = 65
    delay_time = 4
    time_value = 1
    
    issue = random.choices(["No", "Delay", "Corrupt", "Loss" ], [normal_percentage, delay_percentage, corruption_percentage, loss_percentage])[0]
    
    if issue == "Loss":  # Packet is lost
        return 0
    
    if issue == "Corrupt":  # Packet gets corrupted
        pkt[TCP].chksum = 0x1234
        
    if issue == "Delay":  # Packet is delayed
        time_value += delay_time
    
    time.sleep(time_value)  # Sending delay
    send(pkt, count=1)

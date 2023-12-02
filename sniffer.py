
from scapy.all import sniff, Ether, IP, TCP

def packet_callback(packet):
    if IP in packet and TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport

        print(f"Source IP: {ip_src}, Source Port: {sport}")
        print(f"Destination IP: {ip_dst}, Destination Port: {dport}")
        print("="*30)

# Sniff network traffic
sniff(prn=packet_callback, store=0, count=10)

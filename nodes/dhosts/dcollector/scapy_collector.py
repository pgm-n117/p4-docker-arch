from scapy.all import *
from scapy.layers.inet import IP, UDP


def packet_callback(packet):
    if packet.haslayer(UDP):
        print(f"Paquete UDP recibido: {packet[IP].src}:{packet[UDP].sport} -> {packet[IP].dst}:{packet[UDP].dport}")
        print(f"Contenido: {bytes(packet[UDP].payload)}")

# Capturar paquetes en la interfaz de red (ej: 'eth0', 'wlan0')
# Usa iface=None para capturar en todas las interfaces
sniff(prn=packet_callback, filter="udp", store=0, iface=None)
import os
from scapy.all import sniff, IP, TCP, UDP, ARP
from prometheus_client import start_http_server, Counter, Gauge

# 1. Define Prometheus metrics to track
TOTAL_PACKETS = Counter('netpulse_packets_total', 'Total packets captured')
PROTOCOL_COUNTER = Counter('netpulse_protocols_total', 'Packets by protocol', ['protocol'])
BANDWIDTH_GAUGE = Gauge('netpulse_bandwidth_bytes', 'Bandwidth usage in bytes by IP', ['ip_address'])

def analyze_packet(packet):
    TOTAL_PACKETS.inc()

    # Track Layer 3 / Layer 4 Protocols
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        # Record bandwidth metrics
        BANDWIDTH_GAUGE.labels(ip_address=src_ip).set(packet_size)

        if packet.haslayer(TCP):
            PROTOCOL_COUNTER.labels(protocol='TCP').inc()
        elif packet.haslayer(UDP):
            PROTOCOL_COUNTER.labels(protocol='UDP').inc()

    elif packet.haslayer(ARP):
        PROTOCOL_COUNTER.labels(protocol='ARP').inc()

if __name__ == "__main__":
    print("Starting NetPulse Metrics Server on port 8000...")
    start_http_server(8000)

    # Put your Wi-Fi interface name here (e.g., wlan0 or wlo1)
    interface = "wlan0" 
    print(f"Sniffing traffic on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=analyze_packet, store=0)

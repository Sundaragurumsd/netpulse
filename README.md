# netpulse
NetPulse: Automated Wireless Network Observability Engine
NetPulse is a lightweight, Python-driven network telemetry engine designed to sniff raw Wi-Fi traffic, parse core networking protocols, and stream real-time operational metrics into a containerized Prometheus and Grafana pipeline.

This project bridges traditional network engineering with modern NetDevOps principles, combining low-level packet processing with enterprise-grade infrastructure observability.

🛠️ Architecture & Tech Stack
OS Environment: Kali Linux (Wireless Interface Monitoring)

Core Scripting: Python 3 (Scapy, Prometheus Client)

Infrastructure: Docker & Docker Compose (Host Networking Mode)

Time-Series Database: Prometheus

Visualization Frontend: Grafana

📊 Key Telemetry Monitored
Total Packet Volume: A high-speed counter tracking raw frame processing (netpulse_packets_total).

Protocol Distribution: Live traffic breakdown isolating TCP, UDP, and ARP frames to identify network patterns or anomalies (netpulse_protocols_total).

Host Bandwidth Tracking: Real-time throughput (Bytes/sec) mapped dynamically per local IP address to catch bandwidth hogs (netpulse_bandwidth_bytes).

🚀 Repository File Layout
Plaintext
netpulse/
├── .gitignore
├── README.md
├── docker-compose.yml
├── prometheus.yml
├── requirements.txt
└── netpulse.py
1. docker-compose.yml
YAML
version: '3.8'
services:
  prometheus:
    image: prom/prometheus:latest
    network_mode: "host"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
  grafana:
    image: grafana/grafana:latest
    network_mode: "host"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
2. prometheus.yml
YAML
global:
  scrape_interval: 5s
scrape_configs:
  - job_name: 'netpulse'
    static_configs:
      - targets: ['localhost:8000']
3. requirements.txt
Plaintext
scapy
prometheus_client
4. netpulse.py
Python
import os
from scapy.all import sniff, IP, TCP, UDP, ARP
from prometheus_client import start_http_server, Counter, Gauge

TOTAL_PACKETS = Counter('netpulse_packets_total', 'Total packets captured')
PROTOCOL_COUNTER = Counter('netpulse_protocols_total', 'Packets by protocol', ['protocol'])
BANDWIDTH_GAUGE = Gauge('netpulse_bandwidth_bytes', 'Bandwidth usage in bytes by IP', ['ip_address'])

def analyze_packet(packet):
    TOTAL_PACKETS.inc()
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        packet_size = len(packet)
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
    
    interface = "wlan0" 
    print(f"Sniffing traffic on {interface}... Press Ctrl+C to stop.")
    sniff(iface=interface, prn=analyze_packet, store=0)
⚡ Deployment Instructions
Step 1: Spin Up the Infrastructure Stack
Launch the containerized Prometheus database backend and Grafana dashboard engine using the host network layer:

Bash
sudo docker-compose up -d
Step 2: Initialize the Isolated Python Environment
To comply with modern OS security constraints (PEP 668), establish a Python virtual environment to manage dependencies locally:

Bash
# Create and activate the environment
python3 -m venv venv
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
Step 3: Launch the Telemetry Sniffer Engine
Because the script interfaces directly with raw kernel sockets to capture live network interface traffic, execute using root privileges via the local virtual environment interpreter:

Bash
sudo ./venv/bin/python netpulse.py
📉 Grafana Dashboard Visualization Configuration
Open your browser and navigate to the monitoring control center: http://localhost:3000 (Default Credentials: admin / admin).

Head to Connections > Data Sources, click Add Data Source, and choose Prometheus.

Set the Connection URL to:

Plaintext
http://localhost:9090
Click Save & Test.

Create a new dashboard and construct your visual interface panels using these exact PromQL queries:

Total Packets Panel (Stat Visual): netpulse_packets_total

Protocol Breakdown (Pie/Donut Chart): sum(netpulse_protocols_total) by (protocol)

Bandwidth Timeline (Time-Series Graph): netpulse_bandwidth_bytes (Ensure you set the right-hand Y-axis unit selector to Data Rate > Bytes/sec)

🛡️ Future Roadmap Updates
[ ] Implement automated ARP spoofing and poisoning detection thresholds.

[ ] Incorporate passive DNS query string logging to parse domain anomalies.

[ ] Export the finalized dashboard JSON configuration directly into the source directory for instant deployment.

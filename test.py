from scapy.all import Ether, IP, UDP, sendp
import time

# Configuration
iface = "en3f0pf0sf10"  # Interface connected to s1
src_ip = "1.2.3.4"
dst_ip = "8.8.8.8"
src_port = 1234
dst_port = 80
src_mac = "aa:bb:cc:dd:ee:ff"  # Use p0's MAC here
dst_mac = "ff:ff:ff:ff:ff:ff"  # Or the actual MAC of the next hop
packet_len = 1500
stream_count = 10
inter_packet_delay = 0.1  # Seconds

# Build base packet
base_pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=src_port, dport=dst_port)
pad_len = max(0, packet_len - len(base_pkt))
base_pkt = base_pkt / ("X" * pad_len)

# Send the packets
for i in range(stream_count):
    sendp(base_pkt, iface=iface, verbose=False)
    time.sleep(inter_packet_delay)

print(f"Sent {stream_count} packets from {src_ip}:{src_port} to {dst_ip}:{dst_port} via {iface}")
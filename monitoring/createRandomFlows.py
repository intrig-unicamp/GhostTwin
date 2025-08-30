import argparse
import os
import random
import zlib
from scapy.all import Ether, IP, UDP, Raw, wrpcap

def generate_random_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

def compute_crc12(src_mac, dst_mac):
    src_bytes = bytes.fromhex(src_mac.replace(":", ""))
    dst_bytes = bytes.fromhex(dst_mac.replace(":", ""))
    combined = src_bytes + dst_bytes
    crc32 = zlib.crc32(combined) & 0xFFFFFFFF
    return crc32 & 0xFFF  # Truncar para 12 bits

def generate_udp_packets(src_mac, dst_mac, count=1000, pkt_size=1000):
    packets = []
    payload_size = pkt_size - 14 - 20 - 8  # Ethernet + IP + UDP
    payload = Raw(load=bytes([random.randint(0, 255) for _ in range(payload_size)]))
    for _ in range(count):
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1234, dport=4321) / payload
        packets.append(pkt)
    return packets

def main():
    parser = argparse.ArgumentParser(description="Generate PCAPs and replay flows with given Mbps rates.")
    parser.add_argument("-nFlows", nargs="+", type=int, required=True, help="Number of flows followed by Mbps values. Example: -nFlows 2 10 20")
    parser.add_argument("-intf", default="enp6s0f1", help="Network interface (default: enp6s0f1)")
    args = parser.parse_args()

    nflows = args.nFlows[0]
    throughputs = args.nFlows[1:]

    if len(throughputs) != nflows:
        print("❌ Error: Number of Mbps values must match number of flows")
        return

    for i in range(nflows):
        src_mac = generate_random_mac()
        dst_mac = "ff:ff:ff:ff:ff:ff"
        crc12 = compute_crc12(src_mac, dst_mac)
        print(f"[Flow {i+1}] SRC MAC: {src_mac}, DST MAC: {dst_mac}, CRC12 (12-bit): {crc12}")

        pcap_file = f"flow{i+1}.pcap"
        pkts = generate_udp_packets(src_mac, dst_mac)
        wrpcap(pcap_file, pkts)
        print(f"✅ Saved {pcap_file} with 1000 UDP packets")

    print("\n🚀 Starting tcpreplay...")
    for i in range(nflows):
        cmd = f"tcpreplay --intf1={args.intf} --loop=100000000000 --mbps={throughputs[i]} flow{i+1}.pcap &"
        print(f"Running: {cmd}")
        os.system(cmd)

if __name__ == "__main__":
    main()


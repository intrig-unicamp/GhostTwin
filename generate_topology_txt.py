import json
import os
import sys

TOPOLOGY_TXT_PATH = "/home/ubuntu/digital-twin/rss/build/topology.txt"
TOPOLOGY_JSON_PATH = "/home/ubuntu/digital-twin/topology.json"

def start_mode():
    # Delete topology.txt if it exists
    if os.path.exists(TOPOLOGY_TXT_PATH):
        os.remove(TOPOLOGY_TXT_PATH)

    # Load JSON
    with open(TOPOLOGY_JSON_PATH, 'r') as f:
        data = json.load(f)

    # Write topology.txt
    with open(TOPOLOGY_TXT_PATH, 'w') as out:
        for link in data.get("links", []):
            src = link.get("src")
            dst = link.get("dst")
            bandwidth = link.get("bandwidth") or 0
            latency = link.get("latency") or 0
            jitter = link.get("jitter") or 0
            packet_loss = link.get("packet_loss") or 0
            out.write(f"{src} {dst} {bandwidth} {latency} {jitter} {packet_loss}\n")
    
    print("topology.txt recreated.")

def change_mode(args):
    if len(args) != 6:
        print("Usage for 'change': python manage_topology.py change <src> <dst> <bandwidth> <latency> <jitter> <packet_loss>")
        return

    src, dst, bandwidth, latency, jitter, packet_loss = args
    updated = False
    lines = []

    # Read current lines
    with open(TOPOLOGY_TXT_PATH, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 6:
                lines.append(line)
                continue
            if parts[0] == src and parts[1] == dst:
                lines.append(f"{src} {dst} {bandwidth} {latency} {jitter} {packet_loss}\n")
                updated = True
            else:
                lines.append(line)

    if not updated:
        print(f"Link {src} -> {dst} not found. No changes made.")
        return

    # Write updated lines back
    with open(TOPOLOGY_TXT_PATH, 'w') as f:
        f.writelines(lines)

    print(f"Updated link {src} -> {dst}.")

def main():
    if len(sys.argv) < 2:
        print("Usage: python manage_topology.py <start|change> [...]")
        return

    mode = sys.argv[1]

    if mode == "start":
        start_mode()
    elif mode == "change":
        change_mode(sys.argv[2:])
    else:
        print("Unknown mode. Use 'start' or 'change'.")

if __name__ == "__main__":
    main()

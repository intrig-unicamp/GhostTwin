from scapy.all import *
from scapy.fields import *
from collections import defaultdict
import threading
import argparse
import time
import os
import paramiko
import logging
import getpass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('showInfo.log')
    ]
)
logger = logging.getLogger('showInfo')

hostname = "192.168.102.2"
username = "ubuntu"
password = None
sudo_password = None

# ====== Custom Headers ======
class MonitorInst(Packet):
    name = "MonitorInst"
    fields_desc = [
        IntField("index_flow", 0),
        IntField("index_port", 0),
        BitField("port", 0, 9),
        BitField("padding", 0, 7)
    ]

class Monitor(Packet):
    name = "Monitor"
    fields_desc = [
        LongField("bytes_flow", 0),
        LongField("bytes_port", 0),
        BitField("timestamp", 0, 48),
        BitField("port", 0, 9),
        BitField("padding", 0, 7),
        ShortField("pktLen", 0),
        IntField("qID_port", 0),
        IntField("qDepth_port", 0),
        IntField("qTime_port", 0),
        IntField("qID_flow", 0),
        IntField("qDepth_flow", 0),
        IntField("qTime_flow", 0)
    ]

bind_layers(Ether, MonitorInst, type=0x1234)
bind_layers(MonitorInst, Monitor)

# ====== Shared Data and Lock ======
lock = threading.Lock()
prev_data = {
    "flow": defaultdict(lambda: {"bytes": 0, "timestamp": 0}),
    "port": defaultdict(lambda: {"bytes": 0, "timestamp": 0})
}
throughputs = {
    "flow": defaultdict(float),
    "port": defaultdict(float)
}
last_seen = {
    "flow": defaultdict(lambda: 0),
    "port": defaultdict(lambda: 0)
}

# ====== Packet Processor ======
def process_packet(pkt):
    if Monitor in pkt:
        inst = pkt[MonitorInst]
        mon = pkt[Monitor]

        flow_id = inst.index_flow
        port_id = inst.index_port
        ts = mon.timestamp
        bf = mon.bytes_flow
        bp = mon.bytes_port
        now = time.time()

        with lock:
            if flow_id != 0:
                prev = prev_data["flow"][flow_id]
                if prev["timestamp"] and ts > prev["timestamp"]:
                    delta_bytes = bf - prev["bytes"]
                    delta_time = (ts - prev["timestamp"]) / 1e9
                    if delta_time > 0:
                        throughputs["flow"][flow_id] = (delta_bytes * 8) / (delta_time * 1e6)
                prev_data["flow"][flow_id] = {"bytes": bf, "timestamp": ts}
                last_seen["flow"][flow_id] = now

            if port_id != 0:
                prev = prev_data["port"][port_id]
                if prev["timestamp"] and ts > prev["timestamp"]:
                    delta_bytes = bp - prev["bytes"]
                    delta_time = (ts - prev["timestamp"]) / 1e9
                    if delta_time > 0:
                        throughputs["port"][port_id] = (delta_bytes * 8) / (delta_time * 1e6)
                prev_data["port"][port_id] = {"bytes": bp, "timestamp": ts}
                last_seen["port"][port_id] = now

# ====== Topology File Writer ======
def update_topology_file(client, port_id, mbps, latency=0, jitter=0, packet_loss=0):
    try:
        content = f"s1 s2 {int(mbps)} {latency} {jitter} {packet_loss}"
        
        if sudo_password:
            command = f"sudo -S python3 /home/ubuntu/digital-twin/generate_topology_txt.py change {content}"
            stdin, stdout, stderr = client.exec_command(command)
            stdin.write(sudo_password + '\n')
            stdin.flush()
        else:
            command = f"sudo python3 /home/ubuntu/digital-twin/generate_topology_txt.py change {content}"
            stdin, stdout, stderr = client.exec_command(command)

        err = stderr.read().decode().strip()
        if err and "password" not in err.lower():
            logger.error(f"Error writing file: {err}")
            return False

        logger.info(f"Updated topology file: {content}")
        return True

    except Exception as e:
        logger.error(f"Error updating topology file: {e}")
        return False

# ====== Monitoring Display Loop ======
def display_loop(client):
    try:
        client.connect(hostname, username=username)
        logger.info("Connected to remote server")
    except Exception as e:
        logger.error(f"SSH connection failed: {e}")
        return

    last_update_time = 0

    stdin, stdout, stderr = client.exec_command('sudo -n true')
    needs_password = stdout.channel.recv_exit_status() != 0
    if needs_password:
        logger.warning("Sudo requires a password. Consider setting up passwordless sudo.")

    while True:
        time.sleep(1)
        os.system("clear")
        now = time.time()

        with lock:
            print("\n=== [Throughput Report] ===")
            print("---- Flows ----")
            for fid in sorted(throughputs["flow"]):
                if now - last_seen["flow"][fid] <= 5:
                    throughput = throughputs["flow"][fid] if now - last_seen["flow"][fid] <= 1 else 0.0
                    print(f"Flow {fid}: {throughput:.2f} Mbps")

            print("---- Ports ----")
            for pid in sorted(throughputs["port"]):
                if now - last_seen["port"][pid] <= 5:
                    recent = now - last_seen["port"][pid] <= 1
                    mbps = throughputs["port"][pid] if recent else 0.0
                    print(f"Port {pid}: {mbps:.2f} Mbps")

                    if recent and now - last_update_time >= 2:
                        if update_topology_file(client, pid, mbps):
                            last_update_time = now

    client.close()

# ====== Main Entrypoint ======
def main():
    parser = argparse.ArgumentParser(description="Monitoring packet receiver")
    parser.add_argument("--iface", default="enp6s0f0", help="Interface to listen on")
    parser.add_argument("--sudo-password", default="123asd987lkj", help="Password for sudo operations on the remote machine")
    args = parser.parse_args()

    global sudo_password
    sudo_password = args.sudo_password if args.sudo_password else getpass.getpass("Remote sudo password (press Enter if none): ")
    if sudo_password == "":
        sudo_password = None

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    t = threading.Thread(target=display_loop, args=(client,), daemon=True)
    t.start()

    print(f"Listening on interface {args.iface} for ethertype 0x1234 packets")
    try:
        sniff(iface=args.iface, filter="ether proto 0x1234", prn=process_packet)
    except KeyboardInterrupt:
        print("Shutting down...")
    except Exception as e:
        logger.error(f"Error during packet sniffing: {e}")
    finally:
        if client.get_transport() and client.get_transport().is_active():
            client.close()

if __name__ == "__main__":
    main()

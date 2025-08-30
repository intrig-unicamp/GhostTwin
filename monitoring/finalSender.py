import argparse
import time
import threading
from scapy.all import *
from scapy.fields import BitField

# Definindo o header monitor_inst_h
class MonitorInst(Packet):
    name = "MonitorInst"
    fields_desc = [
        BitField("index_flow", 0, 32),
        BitField("index_port", 0, 32),
        BitField("port", 0, 9),
        BitField("padding", 0, 7),
    ]

# Definindo o header monitor_h
class Monitor(Packet):
    name = "Monitor"
    fields_desc = [
        BitField("bytes_flow", 0, 64),
        BitField("bytes_port", 0, 64),
        BitField("timestamp", 0, 48),
        BitField("port", 0, 9),
        BitField("padding", 0, 7),
        BitField("pktLen", 0, 16),
        BitField("qID_port", 0, 32),
        BitField("qDepth_port", 0, 32),
        BitField("qTime_port", 0, 32),
        BitField("qID_flow", 0, 32),
        BitField("qDepth_flow", 0, 32),
        BitField("qTime_flow", 0, 32),
    ]

# Ligando camadas
bind_layers(Ether, MonitorInst, type=0x1234)
bind_layers(MonitorInst, Monitor)

def build_packet(id_flow, id_port, dst_port):
    ether = Ether(dst="ff:ff:ff:ff:ff:ff", type=0x1234)
    monitor_inst = MonitorInst(index_flow=id_flow, index_port=id_port, port=dst_port)
    now_ns = int(time.time() * 1e9)
    monitor = Monitor(timestamp=now_ns)
    return ether / monitor_inst / monitor

def send_periodic(flow_id, port_id, dst_port, iface, interval):
    while True:
        pkt = build_packet(flow_id, port_id, dst_port)
        sendp(pkt, iface=iface, verbose=False)
        #print(f"[{time.time():.2f}] Enviado: flow={flow_id}, port={port_id}, dstPort={dst_port}")
        time.sleep(interval)

def parse_file(file_path):
    entries = []
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(',')
            entry = {}
            for part in parts:
                key, value = part.strip().split('=')
                key = key.strip()
                value = value.strip()
                if key == "period":
                    entry[key] = float(value)
                else:
                    entry[key] = int(value)
            if all(k in entry for k in ('flow', 'port', 'period', 'dstPort')):
                entries.append(entry)
    return entries

def start_sending_thread(id_flow, id_port, dst_port, period, iface):
    t = threading.Thread(target=send_periodic, args=(id_flow, id_port, dst_port, iface, period), daemon=True)
    t.start()
    return t

def main():
    parser = argparse.ArgumentParser(description="Envia pacotes monitor_inst_h + monitor_h via Ethernet")
    parser.add_argument("-i", dest="iface", default="enp6s0f1", help="Interface de envio")
    parser.add_argument("-dst_port", type=int, default=134, help="Campo 'port'")
    parser.add_argument("-id_flow", type=int, default=0, help="Campo 'index_flow'")
    parser.add_argument("-id_port", type=int, default=0, help="Campo 'index_port'")
    parser.add_argument("-t", dest="interval", type=float, default=1.0, help="Intervalo de envio (s)")
    parser.add_argument("-file", dest="file", help="Arquivo de configuração")

    args = parser.parse_args()

    if args.file:
        entries = parse_file(args.file)
        if not entries:
            print("Arquivo está vazio ou mal formatado.")
            return

        #print(f"Iniciando envio com base no arquivo '{args.file}' (Ctrl+C para parar)...")
        for entry in entries:
            #print(f"  > flow={entry['flow']} port={entry['port']} dstPort={entry['dstPort']} period={entry['period']}s")
            start_sending_thread(entry['flow'], entry['port'], entry['dstPort'], entry['period'], args.iface)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nEncerrando envio...")

    else:
        pkt = build_packet(args.id_flow, args.id_port, args.dst_port)
        #print(f"Enviando pacotes a cada {args.interval} segundo(s) pela interface {args.iface} (Ctrl+C para parar)...")
        pkt.show()
        try:
            while True:
                sendp(pkt, iface=args.iface, verbose=False)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nInterrompido pelo usuário.")

if __name__ == "__main__":
    main()


import os
import json
#import networkx as nx
#import matplotlib.pyplot as plt

class SFTopo:
    def __init__(self):
        self.topology = {
            "switches": [],
            "links": []
        }

    def add_switch(self, name):
        """Adds a switch to the topology."""
        if name not in self.topology["switches"]:
            self.topology["switches"].append(name)

    def add_link(self, src, dst, link_type="SF", bandwidth=None, latency=None, jitter=None, packet_loss=None):
        """
        Adds a link between two nodes with optional network settings.

        Parameters:
        - src (str): Source node
        - dst (str): Destination node
        - link_type (str): Type of link (default: "SF")
        - bandwidth (int): Bandwidth limit in kbps (e.g., 1000 for 1Mbps)
        - latency (int): Latency in milliseconds
        - jitter (int): Jitter in milliseconds
        - packet_loss (float): Packet loss percentage (e.g., 0.1 for 0.1%)
        """
        link = {
            "src": src,
            "dst": dst,
            "type": link_type,
            "bandwidth": bandwidth,
            "latency": latency,
            "jitter": jitter,
            "packet_loss": packet_loss
        }
        self.topology["links"].append(link)

    def to_json(self, file_path=None):
        """Converts the topology to JSON format."""
        json_data = json.dumps(self.topology, indent=4)
        if file_path:
            with open(file_path, "w") as f:
                f.write(json_data)
        return json_data

    def show_topology(self):
        """Prints the topology as text (e.g., s1 --> s2)."""
        print("\nStored Topology:")
        for link in self.topology["links"]:
            config = []
            if link["bandwidth"] is not None:
                config.append(f"Bandwidth: {link['bandwidth']}kbps")
            if link["latency"] is not None:
                config.append(f"Latency: {link['latency']}ms")
            if link["jitter"] is not None:
                config.append(f"Jitter: {link['jitter']}ms")
            if link["packet_loss"] is not None:
                config.append(f"Packet Loss: {link['packet_loss']}%")
            
            config_str = ", ".join(config) if config else "No config"
            print(f"{link['src']} --> {link['dst']} ({link['type']}, {config_str})")

    def visualize_topology(self):
        """Displays the topology graphically using NetworkX and Matplotlib."""
        G = nx.Graph()

        # Add nodes
        for switch in self.topology["switches"]:
            G.add_node(switch)

        # Add edges with labels for bandwidth, latency, jitter, and packet loss
        edge_labels = {}
        for link in self.topology["links"]:
            G.add_edge(link["src"], link["dst"])
            label = []
            if link["bandwidth"] is not None:
                label.append(f"BW: {link['bandwidth']}mbps")
            if link["latency"] is not None:
                label.append(f"Latency: {link['latency']}ms")
            if link["jitter"] is not None:
                label.append(f"Jitter: {link['jitter']}ms")
            if link["packet_loss"] is not None:
                label.append(f"Loss: {link['packet_loss']}%")
            
            edge_labels[(link["src"], link["dst"])] = "\n".join(label)

        # Draw the graph
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(G)  # Positioning algorithm for better visualization
        nx.draw(G, pos, with_labels=True, node_color="lightblue", edge_color="gray", node_size=3000, font_size=10)

        # Draw edge labels
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8, font_color="red")
        
        plt.title("SFTopo Network Topology with Network Parameters")
        plt.show()

    def start(self):
        self.to_json("topology.json")
        os.system("bash restart_environment.sh")
        os.system("python3 custom_topology.py")

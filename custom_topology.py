import os
import time
import argparse
import json
import subprocess
import itertools
from collections import defaultdict

def create_bridge(bridge_name):
    """Create an OVS bridge if it doesn't exist"""
    os.system(f"ovs-vsctl --may-exist add-br {bridge_name}")
    print(f"Created bridge: {bridge_name}")

def create_sf(pf_num, sf_num, sf_index, driver_counter):
    """Create a Scalable Function and return its interface name"""
    os.system(f"/opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.{pf_num} flavour pcisf pfnum {pf_num} sfnum {sf_num}")
    time.sleep(1)

    os.system(f"/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.{pf_num}/{sf_index} hw_addr 00:00:00:00:0{pf_num}:{sf_num} trust on state active")
    print(f"SF Index pci/0000:03:00.{pf_num}/{sf_index} created.")
    time.sleep(1)
    
    print(f"Binding driver for SF {sf_num}...")
    os.system(f"echo mlx5_core.sf.{driver_counter} > /sys/bus/auxiliary/drivers/mlx5_core.sf_cfg/unbind")
    time.sleep(0.5)
    os.system(f"echo mlx5_core.sf.{driver_counter} > /sys/bus/auxiliary/drivers/mlx5_core.sf/bind")
    print(f"Driver binded for SF Index pci/0000:03:00.{pf_num}/{sf_index}")
    
    interface_name = f"en3f{pf_num}pf{pf_num}sf{sf_num}"
    return interface_name, driver_counter

def add_port_to_bridge(bridge_name, port_name, bandwidth=None):
    """Add a port to an OVS bridge"""
    os.system(f"ovs-vsctl add-port {bridge_name} {port_name}")
    print(f"Added port {port_name} to bridge {bridge_name}")
    
    """ THE FOLLOWING CODE WILL LIMIT THE BANDWIDTH WITHIN THE OVS
    if bandwidth is not None:
        os.system(f"ovs-vsctl set interface {port_name} ingress_policing_rate={bandwidth}")
        print(f"Interface {port_name} set up with bandwidth = {bandwidth}")
    """
    
def generate_topology_txt():
    """Generates the topology.txt file on the rss/build/ folder"""
    os.system("python3 generate_topology_txt.py start")

def run_hairpin(driver1, driver2, hp_num):
    """Run the hairpin VNF between two SFs"""
    unique_prefix = f"hp{hp_num}_{int(time.time())}"
    cmd = f"./hairpin/build/doca_flow_hairpin_vnf -a auxiliary:mlx5_core.sf.{driver1},dv_flow_en=2 -a auxiliary:mlx5_core.sf.{driver2},dv_flow_en=2 --file-prefix={unique_prefix} &"
    print(f"Starting hairpin between drivers {driver1} and {driver2}: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def run_rss(driver1, driver2, hp_num, src, dst):
    unique_prefix = f"rss{hp_num}_{int(time.time())}"
    cmd = f"./rss/build/doca_flow_rss_meta {src} {dst} -a auxiliary:mlx5_core.sf.{driver1},dv_flow_en=2 -a auxiliary:mlx5_core.sf.{driver2},dv_flow_en=2 --file-prefix={unique_prefix} &"
    print(f"Starting rss between drivers {driver1} and {driver2}: {cmd}")
    subprocess.run(cmd, shell=True, check=True)


def set_bidirectional_flow(bridge_name, port1, port2):
    """Set bidirectional flow rules between two ports"""
    print("debugging... ") 
    print(f"ovs-ofctl add-flow {bridge_name} \"in_port={port1},actions=output:{port2}\"")
    os.system(f"ovs-ofctl add-flow {bridge_name} \"in_port={port1},actions=output:{port2}\"")
    os.system(f"ovs-ofctl add-flow {bridge_name} \"in_port={port2},actions=output:{port1}\"")
    print(f"Set bidirectional flow between {port1} and {port2} on {bridge_name}")

def add_physical_port(bridge_name, port_name):
    """Add physical port to a bridge"""
    os.system(f"ovs-vsctl add-port {bridge_name} {port_name}")
    #os.system(f"ovs-vsctl add-port {bridge_name} pf{port_name[-1]}hpf")
    print(f"Added physical port {port_name} and pf{port_name[-1]}hpf to {bridge_name}")


def get_port_numbers(bridge_name):    
    result = subprocess.run(f"ovs-vsctl list-ports {bridge_name}", shell=True, capture_output=True, text=True)
    output = result.stdout
    port_numbers = {}
    for port_name in output.split('\n'):
        result_port_number = subprocess.run(f"ovs-vsctl get Interface {port_name} ofport", shell=True, capture_output=True, text=True)
        output2 = result_port_number.stdout
        output2 = output2.replace("\n", "")
        if port_name != '': 
            port_numbers[port_name] = output2
    
    print("Port numbers")
    print(port_numbers)
    return port_numbers 

def main():
    parser = argparse.ArgumentParser(description="Create SF topology from JSON file")
    parser.add_argument("--topo", type=str, default="topology.json", help="Path to the topology JSON file")
    args = parser.parse_args()
    
    # Load the JSON topology
    with open(args.topo, 'r') as f:
        topology = json.load(f)
    
    switches = topology.get("switches", [])
    links = topology.get("links", [])
    
    # Initialize counters for SF creation
    sf_num_counter = 10
    driver_counter = 2
    pci_00_sf_index = 229408  # For PF 0
    pci_01_sf_index = 294944  # For PF 1
    
    # Create all bridges first
    for switch in switches:
        create_bridge(switch)
    
    # Track interfaces for each switch and ports that need hairpins
    switch_interfaces = defaultdict(list)
    link_pairs = []
    sf_drivers = {}  # Track driver counters for each SF interface
    
    # Add physical ports first
    for link in links:
        if link.get("type") == "physical":
            switch = link.get("src")
            port = link.get("dst")
            if port.startswith("p"):
                add_physical_port(switch, port)
                switch_interfaces[switch].append(port)
                switch_interfaces[switch].append(f"pf{port[-1]}hpf")
    
    # Process SF links
    sf_links = [link for link in links if link.get("type") == "SF"]
    
    # Use PF0 for first half of links and PF1 for second half
    half_point = len(sf_links) // 2
    
    # Generate the topology.txt file
    generate_topology_txt()
    
    for i, link in enumerate(sf_links):
        src_switch = link.get("src")
        dst_switch = link.get("dst")
        bandwidth = link.get("bandwidth")
        latency = link.get("latency")
        jitter = link.get("jitter")
        packet_loss = link.get("packet_loss")
        
        print(link)
        
        # Determine which PF to use based on the link position
        pf_num = 0 if i < half_point else 1
        sf_index = pci_00_sf_index if pf_num == 0 else pci_01_sf_index
        
        # Create SF for source switch
        sf_src_name, src_driver = create_sf(pf_num, sf_num_counter, sf_index, driver_counter)
        sf_drivers[sf_src_name] = src_driver
        add_port_to_bridge(src_switch, sf_src_name, bandwidth=bandwidth)
        switch_interfaces[src_switch].append(sf_src_name)
        
        # Increment counters
        sf_num_counter += 1
        sf_index += 1
        driver_counter += 1
        if pf_num == 0:
            pci_00_sf_index += 1
        else:
            pci_01_sf_index += 1
        
        
        # Create SF for destination switch
        sf_dst_name, dst_driver = create_sf(pf_num, sf_num_counter, sf_index, driver_counter)
        sf_drivers[sf_dst_name] = dst_driver
        
        add_port_to_bridge(dst_switch, sf_dst_name, bandwidth=bandwidth)
        
        switch_interfaces[dst_switch].append(sf_dst_name)
        
        # Increment counters again
        sf_num_counter += 1
        driver_counter += 1
        if pf_num == 0:
            pci_00_sf_index += 1
        else:
            pci_01_sf_index += 1
        
        # Record the link pair
        link_pairs.append((sf_src_name, sf_dst_name, src_switch, dst_switch))
    
    # Create hairpins between SF pairs
    for i, (sf1, sf2, src_switch, dst_switch) in enumerate(link_pairs):
        """if latency is None and jitter is None and packet_loss is None and bandwidth is None:
            run_hairpin(driver1=sf_drivers[sf1], driver2=sf_drivers[sf2], hp_num=i)
            time.sleep(1)
        else:"""
        run_rss(driver1=sf_drivers[sf1], driver2=sf_drivers[sf2], hp_num=i, src=src_switch, dst=dst_switch)
        time.sleep(1)
    
    # Get port numbers for all switches
    switch_port_numbers = {}
    for switch in switches:
        switch_port_numbers[switch] = get_port_numbers(switch)
    
    print(switch_port_numbers)
    
    for switch in switches:
       first_key, first_value = list(switch_port_numbers[switch].items())[0]
       second_key, second_value = list(switch_port_numbers[switch].items())[1]
       print(first_key + " <--> " + second_key)
       set_bidirectional_flow(switch, first_key, second_key)

    os.system("ovs-vsctl add-port s1 pf0hpf")
    os.system("ovs-vsctl add-port s2 pf1hpf")
    os.system("ovs-ofctl add-flow s1 \"in_port=p0,actions=output:pf0hpf\"")
    os.system("ovs-ofctl add-flow s2 \"in_port=pf1hpf,actions=output:p1\"")
    print("\nTopology setup complete!")

if __name__ == "__main__":
    main()

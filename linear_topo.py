import os
import time
import argparse
import subprocess
import re
import itertools


def setting_physical_ports(num_switches):
    # Add physical ports and HPF ports to first and last bridge
    print("\n\nAdding physical and HPF ports to first and last bridges...\n\n")
    os.system("ovs-vsctl add-port ovsbr0 p0")
    os.system("ovs-vsctl add-port ovsbr0 pf0hpf")

    os.system(f"ovs-vsctl add-port ovsbr{num_switches} p1")
    os.system(f"ovs-vsctl add-port ovsbr{num_switches} pf1hpf")
   
def create_sf(pf_num, sf_num, sf_index, driver_counter, switch):
    os.system(f"/opt/mellanox/iproute2/sbin/mlxdevm port add pci/0000:03:00.{pf_num} flavour pcisf pfnum {pf_num} sfnum {sf_num}")
    
    time.sleep(2)

    os.system(f"/opt/mellanox/iproute2/sbin/mlxdevm port function set pci/0000:03:00.{pf_num}/{sf_index} hw_addr 00:00:00:00:0{pf_num}:{sf_num} trust on state active")
    print(f"SF Index pci/0000:03:00.{pf_num}/{sf_index} created.")
    time.sleep(2)
    
    print("Binding drivers...")
    
    os.system(f"echo mlx5_core.sf.{driver_counter} > /sys/bus/auxiliary/drivers/mlx5_core.sf_cfg/unbind")
    time.sleep(0.5)
    os.system(f"echo mlx5_core.sf.{driver_counter} > /sys/bus/auxiliary/drivers/mlx5_core.sf/bind")
    print(f"Driver binded for SF Index pci/0000:03:00.{pf_num}/{sf_index}")
    
    time.sleep(0.5)
    os.system(f"ovs-vsctl add-port ovsbr{switch} en3f{pf_num}pf{pf_num}sf{sf_num}")
    print(f"\n\n Created SF Index pci/0000:03:00.{pf_num}/{sf_index}, bounded to driver mlx5_core.sf.{driver_counter} and connected to bridge ovsbr{switch}\n\n")
 

def run_hairpin(driver1, driver2, hp_num):
    unique_prefix = f"hp{hp_num}_{int(time.time())}"
    cmd = f"./flow_hairpin_vnf_marcelo/build/doca_flow_hairpin_vnf -a auxiliary:mlx5_core.sf.{driver1},dv_flow_en=2 -a auxiliary:mlx5_core.sf.{driver2},dv_flow_en=2 --file-prefix={unique_prefix} &"
    print(cmd)
    subprocess.run(cmd, shell=True, check=True)
    
    
def get_ovs_interfaces():
    # Run the ovs-vsctl show command and capture output
    result = subprocess.run("ovs-vsctl show", shell=True, capture_output=True, text=True)
    output = result.stdout

    bridges = {}
    current_bridge = None

    # Process each line
    for line in output.split("\n"):
        line = line.strip()

        # Detect bridge names
        if line.startswith("Bridge "):
            current_bridge = line.split(" ")[1]
            bridges[current_bridge] = []

        # Detect ports that match "p0", "p1", or start with "en"
        elif line.startswith("Port "):
            port_name = line.split(" ")[1]
            if re.match(r"^(p0|p1|en[\w\d]+)$", port_name):
                bridges[current_bridge].append(port_name)

    # Generate pairs of interfaces for each bridge
    bridge_pairs = {}
    for bridge, ports in bridges.items():
        bridge_pairs[bridge] = list(itertools.combinations(ports, 2))  # Generate pairs of interfaces

    return bridge_pairs

    
def set_bidirectional_flow(switch, port1, port2):
    os.system(f"ovs-ofctl add-flow {switch} \"in_port={port1},actions=output:{port2}\"")
    os.system(f"ovs-ofctl add-flow {switch} \"in_port={port2},actions=output:{port1}\"")
 
def main():
    parser = argparse.ArgumentParser(description="Create SF switch topology")
    parser.add_argument("--sw", type=int, required=True, help="Number of switches in the topology")
    parser.add_argument("--dir", type=int, required=False, default=0, help="If 0 bidirectional, If 1 direction p0->p1, If 2 direction p1->p0")
    args = parser.parse_args()
    
    num_switches = args.sw
    directional = args.dir    
    
    if num_switches < 2:
        print("Number of switches must be at least 2")
        return
    
    # Initialize SF counters
    pci_00_sf_index = 229408 
    pci_01_sf_index = 294944
    sf_num_counter = 10
    driver_counter = 2
    hp_num = 0
    
    # Create bridges if they don't exist
    for i in range(0, num_switches):
        os.system(f"ovs-vsctl --may-exist add-br ovsbr{i}")
        print(f"ovs-vsctl --may-exist add-br ovsbr{i}")
    
    setting_physical_ports(num_switches-1)
    
    for i in range(1, num_switches):
        if i < num_switches/2:
            create_sf(0, sf_num_counter, pci_00_sf_index, driver_counter, i-1)
            
            sf_num_counter += 1
            pci_00_sf_index += 1
            driver_counter += 1
            create_sf(0, sf_num_counter, pci_00_sf_index, driver_counter, i)
            sf_num_counter += 1
            pci_00_sf_index += 1
            driver_counter += 1
            
            run_hairpin(driver1=driver_counter-2, driver2=driver_counter-1, hp_num=hp_num)
            hp_num += 1
            
        else:
            create_sf(1, sf_num_counter, pci_01_sf_index, driver_counter, i-1)
            sf_num_counter += 1
            pci_01_sf_index += 1
            driver_counter += 1
            create_sf(1, sf_num_counter, pci_01_sf_index, driver_counter, i)
            sf_num_counter += 1
            pci_01_sf_index += 1
            driver_counter += 1
            
            run_hairpin(driver1=driver_counter-2, driver2=driver_counter-1, hp_num=hp_num)
            hp_num += 1
            
    # Run function and print result
    bridge_interface_pairs = get_ovs_interfaces()
    for bridge, pairs in bridge_interface_pairs.items():
        for pair in pairs:
            set_bidirectional_flow(bridge, pair[0], pair[1])
    
    
    exit(0)
        
if __name__ == "__main__":
    main()
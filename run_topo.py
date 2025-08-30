from sftopo import SFTopo

def main():
    topo = SFTopo()

    # Define topology
    topo.add_switch("s1")
    topo.add_switch("s2")
 
    # Add links
    topo.add_link("s1", "s2", bandwidth=10000, packet_loss=0, latency=0, jitter=0)


    topo.add_link("s1", "p0", link_type="physical")  # External connection
    topo.add_link("s2", "p1", link_type="physical")  # External connection

    # Show topology in console
    topo.show_topology()

    topo.start()

if __name__ == "__main__":
    main()

#!/bin/bash

build_hairpin_code() {
    echo "Building hairpin code..."
    
    # Build hairpin code
    export PKG_CONFIG_PATH=:/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox
    CURRENT_PATH=$(pwd)
    cd $CURRENT_PATH/hairpin
    meson build
    cd build
    ninja
    cd ../..
    
    echo "Hairpin code built successfully."
}

compile_hairpin_code() {
    CURRENT_PATH=$(pwd)
    cd $CURRENT_PATH/hairpin/build
    ninja
    cd ../..

    echo "Hairpin code compiled."
}

build_rss_code() {
    echo "Building hairpin code..."
    
    # Build hairpin code
    export PKG_CONFIG_PATH=:/opt/mellanox/doca/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox/dpdk/lib/aarch64-linux-gnu/pkgconfig:/opt/mellanox
    CURRENT_PATH=$(pwd)
    cd $CURRENT_PATH/rss
    meson build
    cd build
    ninja
    cd ../..
    
    echo "Hairpin code built successfully."
}

compile_rss_code() {
    CURRENT_PATH=$(pwd)
    cd $CURRENT_PATH/rss/build
    ninja
    cd ../..

    echo "RSS code compiled."
}


# Function to clean up OVS bridges
cleanup_bridges() {
    echo "Cleaning up all OVS bridges..."
    
    # Get all bridges and delete them
    for bridge in $(ovs-vsctl list-br); do
        echo "Deleting bridge: $bridge"
        ovs-vsctl del-br $bridge
    done
    
    echo "All bridges deleted."
}

# Function to clean up Scalable Functions
cleanup_sfs() {
    echo "Cleaning up all Scalable Functions..."
    
    # Delete all SFs
    for sf in $(mlnx-sf -a show | grep pci/ | awk '{print $3}'); do
        echo "Deleting SF: $sf"
        /opt/mellanox/iproute2/sbin/mlxdevm port del $sf
    done
    
    echo "All Scalable Functions deleted."
}

# Function to set up hugepages
setup_hugepages() {
    echo "Setting up hugepages..."
    
    # Unmount if already mounted
    umount /dev/hugepages 2>/dev/null || true
    
    # Create mount point and mount
    mkdir -p /mnt/huge
    mount -t hugetlbfs nodev /mnt/huge
    
    # Allocate hugepages
    echo 4096 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
    
    echo "Hugepages set up successfully."
}

# Function to enable hardware offload
enable_hw_offload() {
    echo "Enabling hardware offload..."
    
    ovs-vsctl set Open_vSwitch . Other_config:hw-offload=true
    systemctl restart openvswitch-switch
    
    echo "Hardware offload enabled."
}

# Main execution
echo "Starting environment setup..."

#kill any prev app
killall doca_flow_hairpin_vnf
killall doca_flow_rss_meta

# Step 1: Clean existing environment
cleanup_bridges
sleep 1
cleanup_sfs
sleep 2

# Step 2: Set up hugepages
setup_hugepages

# Step 3: Enable hardware offload
enable_hw_offload

# Step 4: Check if hairpin code needs to be built
if [ ! -f "hairpin/build/doca_flow_hairpin_vnf" ]; then
    build_hairpin_code
else
    echo "Hairpin code already built. Skipping build step."
fi

# Step 5: Check if rss code needs to be built
if [ ! -f "rss/build/doca_flow_rss_meta" ]; then
    build_rss_code
else
    echo "RSS code already built. Skipping built step."
fi

echo "Environment setup complete. Ready for topology creation."

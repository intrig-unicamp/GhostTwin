/* 
 * Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
 *
 * This software product is a proprietary product of NVIDIA CORPORATION &
 * AFFILIATES (the "Company") and all right, title, and interest in and to the
 * software product, including all associated intellectual property rights, are
 * and shall remain exclusively with the Company.
 *
 * This software product is governed by the End User License Agreement
 * provided with the software product.
 *
 */

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h> 

#include <doca_log.h>
#include <doca_flow.h>

#include "flow_common.h"
#include <rte_hash.h>
#include <rte_jhash.h>

#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <limits.h> // for PATH_MAX
#include <signal.h>  // For signal handling
#include <sys/file.h>  // For flock()
#include <fcntl.h>     // For open()


DOCA_LOG_REGISTER(FLOW_RSS_META);

#define PACKET_BURST 256  /* The number of packets in the rx queue */

/*
* Dequeue packets from DPDK queues
*
* @ingress_port [in]: port id for dequeue packets
*/

#define MAX_FLOW 1000
#define MAX_SERVICES 10

/*                  THREADING                        */

pthread_t topology_thread;
volatile int topology_thread_running = 1;
pthread_mutex_t topology_mutex = PTHREAD_MUTEX_INITIALIZER;


/*                  BANDWIDTH                        */

/*			BANDWIDTH				*/
uint64_t bandwidth;
uint64_t bandwidth_bytes_per_sec = 0;
static uint64_t bytes_sent_in_current_window = 0;
static struct timespec window_start_time = {0};
static int bandwidth_initialized = 0;

// Window size in milliseconds - smaller = smoother but more overhead
#define RATE_LIMIT_WINDOW_MS 100  // 100ms windows

// Initialize bandwidth limiter (input in MB/s)
void init_working_bandwidth_limiter(uint64_t bandwidth_mbps) {
    bandwidth_bytes_per_sec = bandwidth_mbps * 1024 * 1024 / 8;  // Convert MB/s to bits/s
    bytes_sent_in_current_window = 0;
    clock_gettime(CLOCK_MONOTONIC, &window_start_time);
    bandwidth_initialized = 1;
    
    printf("Bandwidth limiter initialized: %lu MB/s = %lu bytes/s\n", 
           bandwidth_mbps, bandwidth_bytes_per_sec);
}

void update_bandwidth_bytes_per_sec(uint64_t bandwidth_mbps){
    bandwidth_bytes_per_sec = bandwidth_mbps * 1024 * 1024 / 8;  // Convert MB/s to bits/s
}

// Check and update bandwidth limiting
int process_bandwidth_limit(uint16_t packet_size) {
    if (bandwidth_bytes_per_sec == 0) return 1; // No limit
    
    if (!bandwidth_initialized) {
        printf("ERROR: Bandwidth limiter not initialized!\n");
        return 1;
    }
    
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    
    // Calculate elapsed time in milliseconds
    double elapsed_ms = ((now.tv_sec - window_start_time.tv_sec) * 1000.0) + 
                       ((now.tv_nsec - window_start_time.tv_nsec) / 1000000.0);
    
    // Reset window when time threshold reached
    if (elapsed_ms >= RATE_LIMIT_WINDOW_MS) {
        bytes_sent_in_current_window = 0;
        window_start_time = now;
        elapsed_ms = 0;
    }
    
    // Calculate how many bytes we can send in this window
    uint64_t bytes_allowed_in_window = (bandwidth_bytes_per_sec * RATE_LIMIT_WINDOW_MS) / 1000;
    
    // Check if sending this packet would exceed the window limit
    if (bytes_sent_in_current_window + packet_size <= bytes_allowed_in_window) {
        bytes_sent_in_current_window += packet_size;
        return 1; // Can send
    }
    
    return 0; // Would exceed limit
}


/*                 LATENCY/JITTER                       */

struct delayed_packet {
    struct rte_mbuf *pkt;
    struct timespec send_time;
};

int latency;  // in ms
int jitter; // the maximum value of jitter

#define MAX_DELAYED_PACKETS 4096
static struct delayed_packet delay_queue[MAX_DELAYED_PACKETS];
static int delay_queue_head = 0;
static int delay_queue_tail = 0;

struct flow_jitter_state {
	uint64_t flow_id;     // hash key for the flow
	int jitter_offset_ms; // current offset for correlated jitter
};

static struct rte_hash *flow_table = NULL;

void init_flow_table(void) {
    struct rte_hash_parameters hash_params = {
        .name = "flow_table",
        .entries = 1024,   // adjust for number of flows
        .key_len = sizeof(uint64_t),
        .hash_func = rte_jhash,
        .hash_func_init_val = 0,
    };

    flow_table = rte_hash_create(&hash_params);
    if (flow_table == NULL) {
        rte_exit(EXIT_FAILURE, "Unable to create flow table\n");
    }
}

void update_latency_and_jitter(int new_latency, int new_jitter) {
    // Update global latency value
    latency = new_latency;
    jitter = new_jitter;
    
    // Clear all existing flow jitter states since jitter range changed
    if (flow_table != NULL) {

        const void *key;
        void *data;
        uint32_t iter = 0;
        
        // Iterate through all existing flows
        while (rte_hash_iterate(flow_table, &key, &data, &iter) >= 0) {
            struct flow_jitter_state *state = (struct flow_jitter_state *)data;
            if (state != NULL) {
                // Reset jitter offset for this flow with new range
                state->jitter_offset_ms = (rand() % (2 * new_jitter + 1)) - new_jitter;
            }
        }
    }
}


uint64_t get_flow_id(struct rte_mbuf *pkt) {
	struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
		return 0; // non-IPv4 flows get ID=0

	struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
	uint32_t src = rte_be_to_cpu_32(ip->src_addr);
	uint32_t dst = rte_be_to_cpu_32(ip->dst_addr);

	uint16_t src_port = 0, dst_port = 0;
	if (ip->next_proto_id == IPPROTO_UDP || ip->next_proto_id == IPPROTO_TCP) {
		struct rte_udp_hdr *l4 = (struct rte_udp_hdr *)((unsigned char *)ip + (ip->ihl * 4));
		src_port = rte_be_to_cpu_16(l4->src_port);
		dst_port = rte_be_to_cpu_16(l4->dst_port);
	}

	uint64_t key = ((uint64_t)src << 32) ^ dst ^ ((uint64_t)src_port << 16) ^ dst_port ^ ip->next_proto_id;
	return key;
}


/**
 * Compute the per-flow delay including latency + jitter
 *
 * @flow_id: unique 64-bit key for the flow
 * @base_latency: base latency in milliseconds
 * @jitter_range: maximum jitter in ms (will vary ±jitter_range)
 * @return: total delay in ms
 */
int compute_per_flow_delay(uint64_t flow_id, int base_latency, int jitter_range) {
    struct flow_jitter_state *state = NULL;

    // Lookup flow in hash table
    int ret = rte_hash_lookup_data(flow_table, &flow_id, (void **)&state);
    if (ret < 0) {
        // New flow → allocate and insert into hash table
        state = malloc(sizeof(*state));
        if (!state) {
            // Memory allocation failed; fallback to base latency
            return base_latency;
        }
        state->flow_id = flow_id;
        state->jitter_offset_ms = (rand() % (2 * jitter_range + 1)) - jitter_range;
        
        ret = rte_hash_add_key_data(flow_table, &flow_id, state);
        if (ret < 0) {
            // Failed to insert; free memory and fallback
            free(state);
            return base_latency;
        }
    } else {
        // Existing flow → update offset gradually using EMA
        int sample = (rand() % (2 * jitter_range + 1)) - jitter_range;
        double alpha = 0.9; // smoothing factor (0.0 = rapid change, 1.0 = no change)
        state->jitter_offset_ms = (int)(alpha * state->jitter_offset_ms + (1.0 - alpha) * sample);
    }

    int delay_ms = base_latency + state->jitter_offset_ms;
    if (delay_ms < 0) delay_ms = 0; // avoid negative delays

    return delay_ms;
}

void enqueue_with_delay(struct rte_mbuf *pkt) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t flow_id = get_flow_id(pkt);
    int delay_ms = compute_per_flow_delay(flow_id, latency, jitter);

    struct timespec send_time = now;
    send_time.tv_sec += delay_ms / 1000;
    send_time.tv_nsec += (delay_ms % 1000) * 1000000L;
    if (send_time.tv_nsec >= 1000000000L) {
        send_time.tv_sec++;
        send_time.tv_nsec -= 1000000000L;
    }

    delay_queue[delay_queue_tail].pkt = pkt;
    delay_queue[delay_queue_tail].send_time = send_time;
    delay_queue_tail = (delay_queue_tail + 1) % MAX_DELAYED_PACKETS;
}

void flush_ready_packets(uint16_t egress_port) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    struct rte_mbuf *to_forward[PACKET_BURST];
    int forward_count = 0;

    while (delay_queue_head != delay_queue_tail) {
        struct delayed_packet *dp = &delay_queue[delay_queue_head];
        if ((dp->send_time.tv_sec < now.tv_sec) ||
            (dp->send_time.tv_sec == now.tv_sec && dp->send_time.tv_nsec <= now.tv_nsec)) {
            // Ready to send
            to_forward[forward_count++] = dp->pkt;
            delay_queue_head = (delay_queue_head + 1) % MAX_DELAYED_PACKETS;

            if (forward_count == PACKET_BURST)
                break;
        } else {
            break; // queue is ordered by arrival, stop
        }
    }

    if (forward_count > 0) {
        rte_eth_tx_burst(egress_port, 0, to_forward, forward_count);
    }
}


/*                 PACKET LOSS                       */

static int packet_loss_initialized = 0;
float packet_loss;  // Change from int to float

void init_packet_loss(float packet_loss_percent) {
	if (!packet_loss_initialized) {
		srand(time(NULL)); // Seed with current time
		packet_loss_initialized = 1;
	}
	packet_loss = packet_loss_percent;
}

int should_drop_packet() {
	if (packet_loss <= 0.0){
		return 0;
	}
	if (packet_loss >= 100.0){
		return 1;
	}
	// Generate random number from 0-99
	float random_val = (float)rand() / RAND_MAX * 100.0;

	return (random_val < packet_loss);
}

void update_loss(float new_packet_loss) {
    packet_loss = new_packet_loss;
}

static void process_packets(int ingress_port)
{
    struct rte_mbuf *packets[PACKET_BURST];
    struct rte_mbuf *to_forward[PACKET_BURST];
    uint16_t egress_port = (ingress_port == 0) ? 1 : 0; // assuming 2 ports: 0 and 1
    int queue_index = 0;
    int nb_packets;
    int forward_count = 0;


    nb_packets = rte_eth_rx_burst(ingress_port, queue_index, packets, PACKET_BURST);
    
    for (int i = 0; i < nb_packets; i++) {
		struct rte_mbuf *pkt = packets[i];
        uint16_t pkt_len = rte_pktmbuf_pkt_len(pkt);

        if (should_drop_packet()) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        if (!process_bandwidth_limit(pkt_len)) {
            rte_pktmbuf_free(pkt);
            continue;
        }

        // Enqueue with latency + jitter
        enqueue_with_delay(pkt);
    }

    // Try sending any packets whose time has expired
    flush_ready_packets(egress_port);
}

int get_link_params(const char *src, const char *dst) {
    char topology_path[PATH_MAX];
    
    // Possible locations of topology.txt
    const char *possible_paths[] = {
        "rss/build/topology.txt",
        "/home/ubuntu/digital-twin/rss/buildtopology.txt"
    };
    
    int fd = -1;
    FILE *fp = NULL;
    for (int i = 0; i < sizeof(possible_paths) / sizeof(possible_paths[0]); i++) {
        snprintf(topology_path, sizeof(topology_path), "%s", possible_paths[i]);
        
        fd = open(topology_path, O_RDONLY);
        if (fd < 0)
            continue;  // try next path
        
        // Acquire shared lock (read lock)
        if (flock(fd, LOCK_SH) == -1) {
            DOCA_LOG_ERR("Failed to acquire shared lock on %s: %s", topology_path, strerror(errno));
            close(fd);
            continue;
        }
        
        // Open FILE* from fd for fgets usage
        fp = fdopen(fd, "r");
        if (!fp) {
            DOCA_LOG_ERR("fdopen failed on %s: %s", topology_path, strerror(errno));
            flock(fd, LOCK_UN);
            close(fd);
            continue;
        }
        
        DOCA_LOG_INFO("Found and locked topology file at: %s", topology_path);
        break;
    }
    
    if (!fp) {
        DOCA_LOG_ERR("Failed to open and lock topology.txt in any location");
        return -1;
    }

    char line[256];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        char src_line[32], dst_line[32];
        uint64_t bw;
        int lat, jit;
        float pl;

        int fields = sscanf(line, "%31s %31s %lu %d %d %f", src_line, dst_line, &bw, &lat, &jit, &pl);
        if (fields == 6) {
            if (strcmp(src_line, src) == 0 && strcmp(dst_line, dst) == 0) {
                pthread_mutex_lock(&topology_mutex);
                update_bandwidth_bytes_per_sec(bw);
                update_latency_and_jitter(lat, jit);
                update_loss(pl);
                pthread_mutex_unlock(&topology_mutex);
                
                DOCA_LOG_INFO("Updated parameters for connection %s->%s: bw: %lu Mbps, lat: %d ms, jit: %d ms, loss: %f%%",
                       src, dst, bw, lat, jit, pl);
                found = 1;
                break;
            }
        }
    }

    // Close file and release lock
    fclose(fp);  // this also closes fd and releases lock automatically
    // Alternatively, if using close(fd) explicitly, unlock with flock(fd, LOCK_UN);

    return found ? 0 : -2;
}

void *topology_updater(void *args) {
    const char **params = (const char **)args;
    const char *src = params[0];
    const char *dst = params[1];

    while (topology_thread_running) {
        int ret = get_link_params(src, dst);
        if (ret != 0) {
            DOCA_LOG_WARN("Failed to get link parameters (ret=%d), using defaults", ret);
            pthread_mutex_lock(&topology_mutex);
            bandwidth = 0;
            latency = 0;
            jitter = 0;
            packet_loss = 0;
            pthread_mutex_unlock(&topology_mutex);
        }
        sleep(1);  // Check once per second
    }
    return NULL;
}

// Signal handler for clean shutdown
static void signal_handler(int signum) {
    DOCA_LOG_INFO("Caught signal %d, shutting down...", signum);
    topology_thread_running = 0;
}

/*
 * Create DOCA Flow pipe with 5 tuple match, changeable set meta action, and forward RSS
 *
 * @port [in]: port of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t create_rss_meta_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
    struct doca_flow_match match;
    struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
    struct doca_flow_fwd fwd;
    struct doca_flow_fwd fwd_miss;
    struct doca_flow_pipe_cfg *pipe_cfg;
    uint16_t rss_queues[1];
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));
    memset(&fwd, 0, sizeof(fwd));
    memset(&fwd_miss, 0, sizeof(fwd_miss));

    /* set mask value */
    actions.meta.pkt_meta = UINT32_MAX;
    actions_arr[0] = &actions;

    result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
        return result;
    }

    result = set_flow_pipe_cfg(pipe_cfg, "RSS_META_PIPE", DOCA_FLOW_PIPE_BASIC, true);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }
    result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s", doca_error_get_descr(result));
        goto destroy_pipe_cfg;
    }

    /* RSS queue - send matched traffic to queue 0  */
    rss_queues[0] = 0;
    fwd.type = DOCA_FLOW_FWD_RSS;
    fwd.rss_queues = rss_queues;
    fwd.rss_inner_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_UDP;
    fwd.num_of_queues = 1;

    fwd_miss.type = DOCA_FLOW_FWD_DROP;

    result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
    destroy_pipe_cfg:
    doca_flow_pipe_cfg_destroy(pipe_cfg);
    return result;
}

/*
 * Add DOCA Flow pipe entry with example 5 tuple to match and set meta data value
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t add_rss_meta_pipe_entry(struct doca_flow_pipe *pipe, struct entries_status *status)
{
    struct doca_flow_match match;
    struct doca_flow_actions actions;
    struct doca_flow_pipe_entry *entry;
    doca_error_t result;

    memset(&match, 0, sizeof(match));
    memset(&actions, 0, sizeof(actions));

    /* set meta value */
    actions.meta.pkt_meta = 10;
    actions.action_idx = 0;

    result = doca_flow_pipe_add_entry(0, pipe, &match, &actions, NULL, NULL, 0, status, &entry);
    if (result != DOCA_SUCCESS)
        return result;

    return DOCA_SUCCESS;
}

/*
 * Run flow_rss_meta sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t flow_rss_meta(int nb_queues, const char *src, const char *dst)
{
    const int nb_ports = 2;
    struct flow_resources resource = {0};
    uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
    struct doca_flow_port *ports[nb_ports];
    struct doca_dev *dev_arr[nb_ports];
    struct doca_flow_pipe *pipe;
    struct entries_status status;
    int num_of_entries = 1;
    doca_error_t result;
    int port_id;
    
    // Set up signal handlers for graceful termination
    signal(SIGINT, signal_handler);  
    signal(SIGTERM, signal_handler);

    /* Set the Configuration of the Switch*/
	init_working_bandwidth_limiter(0);
	latency = 0;
	jitter = 0;
	init_packet_loss(0);

	init_flow_table(); //used for per-packet jitter
    
    // Initialize mutex
    pthread_mutex_init(&topology_mutex, NULL);

    // Get initial link parameters
    int ret = get_link_params(src, dst);
    if (ret != 0) {
        DOCA_LOG_WARN("Initial link parameters not found, using defaults");
        bandwidth = 0;
        latency = 0;
        jitter = 0;
        packet_loss = 0;
    }

    result = init_doca_flow(nb_queues, "vnf,hws", &resource, nr_shared_resources);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
        pthread_mutex_destroy(&topology_mutex);
        return -1;
    }

    memset(dev_arr, 0, sizeof(struct doca_dev *) * nb_ports);
    result = init_doca_flow_ports(nb_ports, ports, true, dev_arr);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
        doca_flow_destroy();
        pthread_mutex_destroy(&topology_mutex);
        return result;
    }

    for (port_id = 0; port_id < nb_ports; port_id++) {
        memset(&status, 0, sizeof(status));

        result = create_rss_meta_pipe(ports[port_id], &pipe);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to create pipe: %s", doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            pthread_mutex_destroy(&topology_mutex);
            return result;
        }

        result = add_rss_meta_pipe_entry(pipe, &status);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to add entry: %s", doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            pthread_mutex_destroy(&topology_mutex);
            return result;
        }

        result = doca_flow_entries_process(ports[port_id], 0, DEFAULT_TIMEOUT_US, num_of_entries);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Failed to process entries: %s", doca_error_get_descr(result));
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            pthread_mutex_destroy(&topology_mutex);
            return result;
        }

        if (status.nb_processed != num_of_entries || status.failure) {
            DOCA_LOG_ERR("Failed to process entries");
            stop_doca_flow_ports(nb_ports, ports);
            doca_flow_destroy();
            pthread_mutex_destroy(&topology_mutex);
            return DOCA_ERROR_BAD_STATE;
        }
    }
    
    DOCA_LOG_INFO("Wait few seconds for packets to arrive");
    
    // Start topology updater thread
    const char *params[2] = {src, dst};
    if (pthread_create(&topology_thread, NULL, topology_updater, (void *)params) != 0) {
        DOCA_LOG_ERR("Failed to create topology updater thread");
        stop_doca_flow_ports(nb_ports, ports);
        doca_flow_destroy();
        pthread_mutex_destroy(&topology_mutex);
        return -1;
    }

    sleep(5);
    
    pthread_mutex_lock(&topology_mutex);
    DOCA_LOG_INFO("NUMBER OF PORTS: %d", nb_ports);
    DOCA_LOG_INFO("CONFIGURATION...");
    DOCA_LOG_INFO("BANDWIDTH: %lu bytes/sec", bandwidth);
    DOCA_LOG_INFO("LATENCY: %d ms", latency);
    DOCA_LOG_INFO("JITTER: %d ms", jitter);
    DOCA_LOG_INFO("PACKET_LOSS: %.2f%%", packet_loss);
    pthread_mutex_unlock(&topology_mutex);

    // Main processing loop
    while (topology_thread_running) {
        for (port_id = 0; port_id < nb_ports; port_id++) {
            process_packets(port_id);
        }
        
        // Periodically print the current values
        static time_t last_print = 0;
        time_t now = time(NULL);
        if (now - last_print >= 10) {  // Print every 10 seconds
            pthread_mutex_lock(&topology_mutex);
            DOCA_LOG_INFO("CURRENT SETTINGS - BW: %lu bytes/sec, LAT: %d ms, JIT: %d ms, LOSS: %.2f%%", 
                         bandwidth, latency, jitter, packet_loss);
            pthread_mutex_unlock(&topology_mutex);
            last_print = now;
        }
    }
    
    // Clean shutdown
    pthread_join(topology_thread, NULL);
    pthread_mutex_destroy(&topology_mutex);
    result = stop_doca_flow_ports(nb_ports, ports);
    doca_flow_destroy();
    return result;
}

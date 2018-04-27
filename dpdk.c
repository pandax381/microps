#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dpdk.h"
#include "microps.h"

struct device {
    uint16_t port;
};

struct rte_mempool *mbuf_pool;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = { .max_rx_pkt_len = ETHER_MAX_LEN }
};


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static int
port_init(uint16_t port)
{ 
    struct rte_eth_conf port_conf = port_conf_default;
    const uint16_t rx_rings = 32, tx_rings = 32;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct ether_addr addr;
    
    if (port >= rte_eth_dev_count()) {
        return -1;
    }
    
    /* Configure the Ethernet device. */ 
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        return retval;
    }
    
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) {
        return retval;
    }
    
    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) {
            return retval;
        }
    }
    
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), NULL);
        if (retval < 0) {
            return retval;
        }
    }
    
    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0) {
        return retval;
    }
  
    /* Display the port MAC address. */
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
        port,
        addr.addr_bytes[0], addr.addr_bytes[1],
        addr.addr_bytes[2], addr.addr_bytes[3],
        addr.addr_bytes[4], addr.addr_bytes[5]);
    
    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);
  
    return 0;
}

int
dpdk_init(void){
    int ret;
    unsigned nb_ports;
    uint16_t portid;  
    char *argv[] = {"microps"};

    ret = rte_eal_init(1, argv);
    if (ret < 0) {
        return -1;
    }

    nb_ports = rte_eth_dev_count();
    if (nb_ports != 1) {
        return -1;
    }
    
    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  
    if (mbuf_pool == NULL) {
        return -1;
    }
  
    return 0;
}


/* Wrapped a function to control device but not practically meaningful. It is expected that name will be assigned port number. */
device_t 
*device_open (const char *name) {
    device_t *device;
    if ((device = malloc(sizeof(*device))) == NULL) {
        perror("malloc");
        return NULL;
    }
    device->port = (uint16_t)atoi(name);
    
    if (port_init(device->port) < 0){
        free(device);
        return NULL;
    }
  
    return device;
}

void 
device_close (device_t *device) {
    printf("close port %u\n", device->port);
    rte_eth_dev_stop(device->port);
    rte_eth_dev_close(device->port);
    free(device);
}

void
device_input (device_t *device, void (*callback)(uint8_t *, size_t), int timeout) {
    uint16_t nb_ports;
    uint16_t port = device->port;
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_rx;
    nb_ports = rte_eth_dev_count();
    int i;

    /* Recv burst of RX packets */
    nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
    for (i = 0; i < nb_rx ; i++) {
        uint8_t *p = rte_pktmbuf_mtod(bufs[i], uint8_t*);
        size_t size = rte_pktmbuf_pkt_len(bufs[i]);
  
        callback(p, size);
    }
}

ssize_t
device_output (device_t *device, const uint8_t *buffer, size_t length) {
    struct rte_mbuf *bufs[BURST_SIZE];
    uint16_t nb_ports;
    uint16_t port = device->port;
    uint8_t *p;
    nb_ports = rte_eth_dev_count();
  
    /* Send burst of TX packets */
    bufs[0] = rte_pktmbuf_alloc(mbuf_pool);
    bufs[0]->pkt_len = length;
    bufs[0]->data_len = length;
    bufs[0]->port = port;
    bufs[0]->packet_type = 1;
  
    p = rte_pktmbuf_mtod(bufs[0], uint8_t*);
    memcpy(p, buffer, length);
  
    if (rte_eth_tx_burst(port, 0, bufs, 1) > 0) {
        return length;
    }
    return -1;
}


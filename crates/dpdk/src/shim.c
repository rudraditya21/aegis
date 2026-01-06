#include <rte_config.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct aegis_dpdk_stats {
    uint64_t rx;
    uint64_t tx;
    uint64_t rx_dropped;
    uint64_t imissed;
};

#define AEGIS_RSS_FIELD_IPV4 (1u << 0)
#define AEGIS_RSS_FIELD_IPV6 (1u << 1)
#define AEGIS_RSS_FIELD_TCP  (1u << 2)
#define AEGIS_RSS_FIELD_UDP  (1u << 3)

struct aegis_dpdk_rss_info {
    uint32_t hash_key_size;
    uint16_t reta_size;
    uint16_t _pad;
    uint64_t rss_offload;
};

int aegis_dpdk_port_configure(uint16_t port_id, uint16_t rxq, uint16_t txq) {
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof(conf));
    return rte_eth_dev_configure(port_id, rxq, txq, &conf);
}

int aegis_dpdk_rx_queue_setup(uint16_t port_id, uint16_t qid, uint16_t desc, int socket_id, struct rte_mempool *pool) {
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(port_id, &info);
    struct rte_eth_rxconf rx_conf = info.default_rxconf;
    return rte_eth_rx_queue_setup(port_id, qid, desc, socket_id, &rx_conf, pool);
}

int aegis_dpdk_tx_queue_setup(uint16_t port_id, uint16_t qid, uint16_t desc, int socket_id) {
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(port_id, &info);
    struct rte_eth_txconf tx_conf = info.default_txconf;
    return rte_eth_tx_queue_setup(port_id, qid, desc, socket_id, &tx_conf);
}

const void *aegis_dpdk_mbuf_data(const struct rte_mbuf *m) {
    return rte_pktmbuf_mtod(m, const void *);
}

uint16_t aegis_dpdk_mbuf_data_len(const struct rte_mbuf *m) {
    return rte_pktmbuf_data_len(m);
}

int aegis_dpdk_mbuf_write(struct rte_mbuf *m, const void *data, uint16_t len) {
    void *dst = rte_pktmbuf_append(m, len);
    if (!dst) {
        return -1;
    }
    rte_memcpy(dst, data, len);
    return 0;
}

int aegis_dpdk_stats_get(uint16_t port_id, struct aegis_dpdk_stats *out) {
    struct rte_eth_stats stats;
    if (rte_eth_stats_get(port_id, &stats) != 0) {
        return -1;
    }
    out->rx = stats.ipackets;
    out->tx = stats.opackets;
    out->rx_dropped = stats.ierrors;
    out->imissed = stats.imissed;
    return 0;
}

int aegis_dpdk_port_by_name(const char *name, uint16_t *out_port) {
    return rte_eth_dev_get_port_by_name(name, out_port);
}

int aegis_dpdk_rss_info(uint16_t port_id, struct aegis_dpdk_rss_info *out) {
    if (!out) {
        rte_errno = EINVAL;
        return -1;
    }
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(port_id, &info);
    out->hash_key_size = info.hash_key_size;
    out->reta_size = info.reta_size;
    out->rss_offload = info.flow_type_rss_offloads;
    return 0;
}

int aegis_dpdk_rss_configure(uint16_t port_id,
                             uint32_t fields_mask,
                             int symmetric,
                             const uint8_t *key,
                             uint32_t key_len,
                             const uint16_t *queues,
                             uint16_t queue_len) {
    struct rte_eth_dev_info info;
    rte_eth_dev_info_get(port_id, &info);

    uint64_t rss_hf = 0;
    if (fields_mask & AEGIS_RSS_FIELD_IPV4) {
        rss_hf |= RTE_ETH_RSS_IPV4;
    }
    if (fields_mask & AEGIS_RSS_FIELD_IPV6) {
        rss_hf |= RTE_ETH_RSS_IPV6;
    }
    if (fields_mask & AEGIS_RSS_FIELD_TCP) {
        rss_hf |= RTE_ETH_RSS_TCP;
    }
    if (fields_mask & AEGIS_RSS_FIELD_UDP) {
        rss_hf |= RTE_ETH_RSS_UDP;
    }
#ifdef RTE_ETH_RSS_SYMMETRIC_TOEPLITZ
    if (symmetric) {
        rss_hf |= RTE_ETH_RSS_SYMMETRIC_TOEPLITZ;
    }
#else
    (void)symmetric;
#endif

    if (rss_hf == 0) {
        rte_errno = EINVAL;
        return -1;
    }
    if (info.flow_type_rss_offloads != 0) {
        rss_hf &= info.flow_type_rss_offloads;
        if (rss_hf == 0) {
            rte_errno = ENOTSUP;
            return -1;
        }
    }

    struct rte_eth_rss_conf rss_conf;
    memset(&rss_conf, 0, sizeof(rss_conf));
    rss_conf.rss_key = (uint8_t *)(uintptr_t)key;
    rss_conf.rss_key_len = key_len;
    rss_conf.rss_hf = rss_hf;

    if (rte_eth_dev_rss_hash_update(port_id, &rss_conf) != 0) {
        return -1;
    }

    if (queue_len == 0) {
        return 0;
    }
    if (info.reta_size == 0) {
        rte_errno = ENOTSUP;
        return -1;
    }

    uint16_t reta_size = info.reta_size;
    uint16_t reta_conf_size =
        (uint16_t)((reta_size + RTE_ETH_RETA_GROUP_SIZE - 1) / RTE_ETH_RETA_GROUP_SIZE);
    struct rte_eth_rss_reta_entry64 *reta_conf =
        calloc(reta_conf_size, sizeof(*reta_conf));
    if (!reta_conf) {
        rte_errno = ENOMEM;
        return -1;
    }

    for (uint16_t i = 0; i < reta_size; i++) {
        uint16_t idx = (uint16_t)(i / RTE_ETH_RETA_GROUP_SIZE);
        uint16_t shift = (uint16_t)(i % RTE_ETH_RETA_GROUP_SIZE);
        reta_conf[idx].mask |= (uint64_t)(1ULL << shift);
        reta_conf[idx].reta[shift] = queues[i % queue_len];
    }

    int rc = rte_eth_dev_rss_reta_update(port_id, reta_conf, reta_size);
    free(reta_conf);
    if (rc != 0) {
        return -1;
    }
    return 0;
}

int aegis_dpdk_errno(void) {
    return rte_errno;
}

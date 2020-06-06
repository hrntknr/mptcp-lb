#include <stdio.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <arpa/inet.h>

#include "bpf_helpers.h"
#include "bpf_endian.h"

#define MAX_SERVICE_COUNT 64

#define assert_len(target, end)     \
    if ((void *)(target + 1) > end) \
        return XDP_DROP;

struct services_key
{
    __u8 addr[16];
    __u16 port;
};

struct services_value
{
    __u8 addr[16];
    __u16 port;
};

struct bpf_map_def SEC("maps") services = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(struct services_key),
    .value_size = sizeof(struct services_value),
    .max_entries = MAX_SERVICE_COUNT,
};

static inline int process_tcphdr(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcp = (struct tcphdr *)(ipv6 + 1);

    struct services_key key = {};
    struct services_value *service;

    assert_len(tcp, data_end);

    for (int i = 0; i < 16; i++)
        key.addr[i] = ipv6->ip6_dst.in6_u.u6_addr8[i];
    key.port = tcp->dest;

    service = bpf_map_lookup_elem(&services, &key);

    if (service == NULL)
        return XDP_PASS;

    return XDP_DROP;
}

static inline int process_ipv6hdr(struct xdp_md *ctx, struct ethhdr *eth)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ip6_hdr *ipv6 = (struct ip6_hdr *)(eth + 1);

    assert_len(ipv6, data_end);

    if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
        return XDP_PASS;

    return process_tcphdr(ctx, eth, ipv6);
}

static inline int process_ethhdr(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    assert_len(eth, data_end);

    if (eth->h_proto != bpf_htons(ETH_P_IPV6))
        return XDP_PASS;

    return process_ipv6hdr(ctx, eth);
}

SEC("xdp")
int mptcp_lb(struct xdp_md *ctx)
{
    return process_ethhdr(ctx);
}

char _license[] SEC("license") = "GPL";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

struct service_dst
{
    __u8 addr[16];
    __u16 port;
};

struct upstream
{
    __u8 addr[16];
};

struct bpf_map_def SEC("maps") services = {
    .type = BPF_MAP_TYPE_ARRAY_OF_MAPS,
    .key_size = sizeof(struct service_dst),
    .value_size = sizeof(struct upstream),
    .max_entries = MAX_SERVICE_COUNT,
};

static inline int process_vip(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6, struct tcphdr *tcp, struct upstream *service)
{
    struct upstream *upstream;
    __u64 index = 0;
    __u8 tmp[ETH_ALEN];
    __u64 sum = tcp->check ^ 0xffff;

    upstream = bpf_map_lookup_elem(service, &index);
    if (upstream == NULL)
        return XDP_DROP;

    memcpy(tmp, eth->h_source, sizeof(__u8) * ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, sizeof(__u8) * ETH_ALEN);
    memcpy(eth->h_dest, tmp, sizeof(__u8) * ETH_ALEN);
    ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow =
        (ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow & 0xf00fffff) |
        (htonl(1) << 20 & 0x0ff00000);

    for (int i = 0; i < 8; i++)
    {
        sum += *(__u16 *)&upstream->addr[i * 2];
        sum -= *(__u16 *)&ipv6->ip6_dst.in6_u.u6_addr8[i * 2];
    }

    memcpy(ipv6->ip6_dst.in6_u.u6_addr8, upstream->addr, sizeof(__u8) * 16);

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    tcp->check = sum ^ 0xffff;

    return XDP_TX;
}

static inline int process_tcphdr(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcp = (struct tcphdr *)(ipv6 + 1);

    struct service_dst key = {};
    struct upstream *service;

    assert_len(tcp, data_end);

    memcpy(key.addr, ipv6->ip6_dst.in6_u.u6_addr8, sizeof(__u8) * 16);
    key.port = __bpf_ntohs(tcp->dest);

    service = bpf_map_lookup_elem(&services, &key);

    if (service == NULL)
        return XDP_PASS;

    return process_vip(ctx, eth, ipv6, tcp, service);
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

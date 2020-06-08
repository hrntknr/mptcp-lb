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

#define assert_len(target, end)     \
    if ((void *)(target + 1) > end) \
        return XDP_DROP;

const __u8 vip[16] = {
    0xfc,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x01,
};

static inline int dnat(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6, struct tcphdr *tcp)
{
    unsigned long sum = tcp->check ^ 0xffff;

    if (sizeof(vip) / sizeof(vip[0]) < 16)
        return XDP_DROP;

    for (int i = 0; i < 8; i++)
    {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        sum += vip[i * 2 + 1] << 8 | vip[i * 2];
        sum -= ipv6->ip6_dst.in6_u.u6_addr8[i * 2 + 1] << 8 | ipv6->ip6_dst.in6_u.u6_addr8[i * 2];
#else
        sum += vip[i * 2] << 8 | vip[i * 2 + 1];
        sum -= ipv6->ip6_dst.in6_u.u6_addr8[i * 2] << 8 | ipv6->ip6_dst.in6_u.u6_addr8[i * 2 + 1];
#endif
    }

    memcpy(ipv6->ip6_dst.in6_u.u6_addr8, vip, sizeof(__u8) * 16);

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    tcp->check = sum ^ 0xffff;

    return XDP_PASS;
}

static inline int process_tcphdr(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct tcphdr *tcp = (struct tcphdr *)(ipv6 + 1);

    assert_len(tcp, data_end);

    return dnat(ctx, eth, ipv6, tcp);
}

static inline int process_ipv6hdr(struct xdp_md *ctx, struct ethhdr *eth)
{
    void *data_end = (void *)(long)ctx->data_end;
    struct ip6_hdr *ipv6 = (struct ip6_hdr *)(eth + 1);

    assert_len(ipv6, data_end);

    if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
        return XDP_PASS;

    // if (ipv6->ip6_ctlun.ip6_un1.ip6_un1_flow != bpf_htons(1))
    //     return XDP_PASS;

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

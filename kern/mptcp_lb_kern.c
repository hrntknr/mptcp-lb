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
#define cROUNDS 2
#define dROUNDS 4

#define assert_len(target, end)     \
    if ((void *)(target + 1) > end) \
        return XDP_DROP;

#define ROTATE(x, b) (__u64)(((x) << (b)) | ((x) >> (64 - (b))))

#define HALF_ROUND(a, b, c, d, s, t) \
    a += b;                          \
    c += d;                          \
    b = ROTATE(b, s) ^ a;            \
    d = ROTATE(d, t) ^ c;            \
    a = ROTATE(a, 32);

#define DOUBLE_ROUND(v0, v1, v2, v3)    \
    HALF_ROUND(v0, v1, v2, v3, 13, 16); \
    HALF_ROUND(v2, v1, v0, v3, 17, 21); \
    HALF_ROUND(v0, v1, v2, v3, 13, 16); \
    HALF_ROUND(v2, v1, v0, v3, 17, 21);

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _le64toh(x) ((__u64)(x))
#else
#define _le64toh(x) le64toh(x)
#endif

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

inline static __u64 siphash(const void *src, size_t inlen, __u8 *key)
{
    const __u64 *_key = (__u64 *)key;
    __u64 k0 = _le64toh(_key[0]);
    __u64 k1 = _le64toh(_key[1]);
    __u64 b = (__u64)inlen << 56;
    const __u64 *in = (__u64 *)src;

    __u64 v0 = k0 ^ 0x736f6d6570736575ULL;
    __u64 v1 = k1 ^ 0x646f72616e646f6dULL;
    __u64 v2 = k0 ^ 0x6c7967656e657261ULL;
    __u64 v3 = k1 ^ 0x7465646279746573ULL;

    while (inlen >= 8)
    {
        __u64 mi = _le64toh(*in);
        in += 1;
        inlen -= 8;
        v3 ^= mi;
        DOUBLE_ROUND(v0, v1, v2, v3);
        v0 ^= mi;
    }

    __u64 t = 0;
    __u8 *pt = (__u8 *)&t;
    __u8 *m = (__u8 *)in;
    switch (inlen)
    {
    case 7:
        pt[6] = m[6];
    case 6:
        pt[5] = m[5];
    case 5:
        pt[4] = m[4];
    case 4:
        *((__u32 *)&pt[0]) = *((__u32 *)&m[0]);
        break;
    case 3:
        pt[2] = m[2];
    case 2:
        pt[1] = m[1];
    case 1:
        pt[0] = m[0];
    }
    b |= _le64toh(t);

    v3 ^= b;
    DOUBLE_ROUND(v0, v1, v2, v3);
    v0 ^= b;
    v2 ^= 0xff;
    DOUBLE_ROUND(v0, v1, v2, v3);
    DOUBLE_ROUND(v0, v1, v2, v3);
    return (v0 ^ v1) ^ (v2 ^ v3);
}

static inline __u64 select_server(__u8 *addr, __u64 count)
{
    __u8 key[16] = {0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    __u64 hash = siphash(addr, sizeof(__u8) * 16, key);
    return hash % count;
}

static inline int process_vip(struct xdp_md *ctx, struct ethhdr *eth, struct ip6_hdr *ipv6, struct tcphdr *tcp, struct upstream *service)
{
    struct upstream *upstream;
    __u64 index = 0;
    __u64 count = 2;
    __u8 tmp[ETH_ALEN];
    __u64 sum = tcp->check ^ 0xffff;

    index = select_server(ipv6->ip6_src.in6_u.u6_addr8, count);

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

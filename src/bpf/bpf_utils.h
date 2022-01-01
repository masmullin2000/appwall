
//#include <linux/if_ether.h>
#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD

//#include <linux/pkt_cls.h>
#define TC_ACT_UNSPEC	(-1)
#define TC_ACT_OK		0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		2
#define TC_ACT_PIPE		3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		8

enum ip_type {
    TCP_V4,
    TCP_V6,
    UDP_V4,
    UDP_V6,
    OTHER 
};

/*
 * Determine an ip4 header
 *
 * @param eth, ethernet header
 * @param data_end, end of the entire packet
 *
 * @return a struct iphdr if this is an ipv4 packet
 *         NULL otherwise
 */
static struct iphdr* is_ipv4(struct ethhdr *eth, void *data_end) 
{
    struct iphdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

/*
 * Determine an ip6 header
 *
 * @param eth, ethernet header
 * @param data_end, end of the entire packet
 *
 * @return a struct ipv6hdr if this is an ipv6 packet
 *         NULL otherwise
 */
struct ipv6hdr* is_ipv6(struct ethhdr *eth, void *data_end) 
{
    struct ipv6hdr *iph = NULL;
    if (!eth || !data_end) {
        return NULL;
    }

    if ((void*)eth + sizeof(*eth) + sizeof(*iph) > data_end) {
        return NULL;
    }
    
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        iph = (struct ipv6hdr*)((void*)eth + sizeof(*eth));
    }
    return iph;
}

/*
 * Determine udp header 
 *
 * @param iph, iphdr or ipv6hdr depending on hdr_size
 * @param hdr_sz, size of the iph.
 *        valid values are either sizeof(struct iphdr) or sizeof(ipv6hdr)
 * @param data_end, end of the entire packet
 *
 * @return a struct udphdr if this is an udp packet
 *         NULL otherwise
 */
struct udphdr* is_udp(void *iph, u8 hdr_sz, void *data_end)
{
    struct udphdr *udph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*udph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_UDP) {
        udph = (struct udphdr*)((void*)iph + hdr_sz);
    }
    return udph; 
}

/*
 * Determine tcp header 
 *
 * @param iph, iphdr or ipv6hdr depending on hdr_size
 * @param hdr_sz, size of the iph.
 *        valid values are either sizeof(struct iphdr) or sizeof(ipv6hdr)
 * @param data_end, end of the entire packet
 *
 * @return a struct tcphdr if this is a tcp packet
 *         NULL otherwise
 */
struct tcphdr* is_tcp(void *iph, u8 hdr_sz, void *data_end)
{
    struct tcphdr *tcph = NULL;
    if (!iph || !data_end) {
        return NULL;
    }

    if ((void*)(iph + hdr_sz + sizeof(*tcph)) > data_end) {
        return NULL;
    }

    int proto = -1;
    if (hdr_sz == sizeof(struct iphdr)) {
        struct iphdr *v4 = (struct iphdr*)iph;
        proto = v4->protocol;
    } else if (hdr_sz == sizeof(struct ipv6hdr)) {
        struct ipv6hdr *v6 = (struct ipv6hdr*)iph;
        proto = v6->nexthdr;
    }

    if (proto == IPPROTO_TCP) {
        tcph = (struct tcphdr*)((void*)iph + hdr_sz);
    }
    return tcph;
}

static inline void* get_bpf_sock_tuple(struct __sk_buff *skb, struct bpf_sock_tuple *tup, enum ip_type *iptype)
{
    void *rc = ERR_PTR(-EINVAL);
    if (iptype) *iptype = OTHER;

    if (!skb || !tup)
       goto err; 

    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;
    struct iphdr *iph = is_ipv4(eth, data_end);
    struct ipv6hdr *iph6 = is_ipv6(eth, data_end);
    struct udphdr *udph = NULL;
    struct tcphdr *tcph = NULL;
    __be16 dst = 0;
    __be16 src = 0;
    __be16 port = 0;
    // IPv4 packet
    if (iph) {
        u8 hdr_sz = sizeof(*iph);
        udph = is_udp(iph, hdr_sz, data_end);
        tcph = is_tcp(iph, hdr_sz, data_end);

        tup->ipv4.daddr = BPF_CORE_READ(iph, daddr);
        tup->ipv4.saddr = BPF_CORE_READ(iph, saddr);
    } else if (iph6) { // IPv6 packet
        u8 hdr_sz = sizeof(*iph6);
        udph = is_udp(iph6, hdr_sz, data_end);
        tcph = is_tcp(iph6, hdr_sz, data_end);

        __builtin_memcpy(&tup->ipv6.daddr, &iph6->daddr, sizeof(tup->ipv6.daddr));
        __builtin_memcpy(&tup->ipv6.saddr, &iph6->saddr, sizeof(tup->ipv6.saddr));
    }

    // if both NULL then this was not IPvX/TCP or UDP -- allow
    if (!udph && !tcph)
        goto err;

    if (tcph) {
        dst = tcph->dest;
        src = tcph->source;

        if (iph) {
            tup->ipv4.dport = tcph->dest;
            tup->ipv4.sport = tcph->source;
            if (iptype) *iptype = TCP_V4;
        } else {
            tup->ipv6.dport = tcph->dest;
            tup->ipv6.sport = tcph->source;
            if (iptype) *iptype = TCP_V6;
        }

        rc = tcph + sizeof(*tcph);
    } else if (udph) {
        dst = udph->dest;
        src = udph->source;

        if (iph) {
            tup->ipv4.dport = udph->dest;
            tup->ipv4.sport = udph->source;
            if (iptype) *iptype = UDP_V4;
        } else {
            tup->ipv6.dport = udph->dest;
            tup->ipv6.sport = udph->source;
            if (iptype) *iptype = UDP_V6;
        }

        rc = udph + sizeof(*udph);
    }

err:
    return rc;
}

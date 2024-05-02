
//go:build ignore

#include <linux/if_ether.h>
//#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>

#define PORT_MAP_SIZE 1
#define STATS_MAP_SIZE 16
#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, STATS_MAP_SIZE);
	__type(key, __u32); // source IPv4 address
	__type(value, __u32); // packet count
} xdp_stats_map SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, PORT_MAP_SIZE);
} bpf_port_map SEC(".maps");

SEC("xdp")
int block_port(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("Received packet\n: ");
    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    __u32 *ip_src_addr = (__u32)(ip->saddr);
    __u32 *pkt_count = bpf_map_lookup_elem(&xdp_stats_map, &ip_src_addr);

    int *port = bpf_map_lookup_elem(&bpf_port_map, &(int){0});
    if (!port) {
        bpf_printk("Port map lookup failed\n");
        return XDP_PASS;
    }

    if (ip->protocol == IPPROTO_TCP && tcph->dest == htons(*port)) {
        if (!pkt_count) {
            __u32 init_pkt_count = 1;
            bpf_map_update_elem(&xdp_stats_map, &ip_src_addr, &init_pkt_count, BPF_ANY);
        } else {
            __sync_fetch_and_add(pkt_count, 1);
        }
	bpf_printk("Dropped packet\n: ");
    	return XDP_DROP;
    }

    bpf_printk("Accepted packet\n: ");
    return XDP_PASS;
}

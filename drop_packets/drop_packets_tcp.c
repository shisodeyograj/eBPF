
//go:build ignore

#include <linux/if_ether.h>
//#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>
#define PORT_MAP_SIZE 1
// Sizeof all headers till TCP
#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

// Define an eBPF map to store the port number
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, PORT_MAP_SIZE);
} bpf_port_map SEC(".maps");

SEC("xdp")
int drop_packets(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("Received packet\n: ");
    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    int *port = bpf_map_lookup_elem(&bpf_port_map, &(int){0});
    if (!port) {
        bpf_printk("Port map lookup failed\n");
        return XDP_PASS;
    }

    //if (ip->protocol == IPPROTO_TCP && tcph->dest == htons(8080)) {
    //if (ntohs(tcp->dest) == *port) {
    if (ip->protocol == IPPROTO_TCP && tcph->dest == htons(*port)) {
        bpf_printk("Dropped packet 2222\n: ");
    	return XDP_DROP;
    }
    bpf_printk("Received packet 2222\n: ");
    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

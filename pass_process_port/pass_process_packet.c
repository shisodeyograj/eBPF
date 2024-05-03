// +build ignore

#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/bpf.h>
#include <netinet/in.h>
#include <bpf/bpf_helpers.h>
#include <netinet/ip.h>


char __license[] SEC("license") = "Dual MIT/GPL";

#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))
#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
        _val;                                                                                  \
    })

struct info {
    __u32 pid;
    __u8 comm[32];
}x;

struct bpf_map_def SEC("maps") eventmap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
    .value_size = sizeof(x),
    .max_entries = 3,
};

const struct info *unused __attribute__((unused));

SEC("kprobe/security_socket_bind")
int bind_intercept(struct pt_regs *ctx,  const struct sockaddr *addr) {

    struct info infostruct;
    //struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    //struct sockaddr_in *in_addr = (struct sockaddr_in *) address;
    //u16 in_port = READ_KERN(in_addr->sin_port);
    //infostruct.lport= bpf_ntohs(in_port);

    // Hradcoded port to be remove once issue for above commented code gets resolved
    __u32 in_port = 5000;
    __u64 p= bpf_get_current_pid_tgid();
    p = p >>32;

    bpf_printk("Socket binding\n: ");   
    infostruct.pid=p;
    bpf_get_current_comm(&infostruct.comm,sizeof(infostruct.comm));
    
    bpf_map_update_elem(&eventmap,&in_port,&infostruct,BPF_ANY);
    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    
    struct info *s;
    __u32 pass_port = 5000;

    // Get current port
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("Received packet\n: ");
    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    // 
    __u32 port = ntohs(tcph->dest);
    bpf_printk("Port=====: %u: ", port);
   
    s = bpf_map_lookup_elem(&eventmap, &port);
    if (!s) {
	    bpf_printk("Accept packet\n: ");
	    return XDP_PASS;
    }

    // match process
    __u8 check_process[] = {'m', 'y', 'p', 'r', 'o', 'c', 'e', 's', 's'};
    __u16 len = 9;

    __u16 i = 0;
    __u16 match = 1;
    for (__u16 i=0; i<9; i++) {
        if (s->comm[i] == check_process[i]) {
            match = 1;
        }
        if (match != 1) break;
    }
    if (match == 1) {
	bpf_printk("Process matched");
	// Check for port	
    	if (port == pass_port) {
		bpf_printk("Accepting packets for pass ports");
		return XDP_PASS;
	} else {
		bpf_printk("Dropping packets for process ports");
	        return XDP_DROP;
	}
    }
    return XDP_PASS;
}

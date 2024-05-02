// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TOTSZ (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))

char __license[] SEC("license") = "Dual MIT/GPL";

#define READ_KERN(ptr)                                                                         \
    ({                                                                                         \
        typeof(ptr) _val;                                                                      \
        __builtin_memset((void *) &_val, 0, sizeof(_val));                                     \
        bpf_core_read((void *) &_val, sizeof(_val), &ptr);                                     \
        _val;                                                                                  \
    })

struct info {
    u32 pid;
    u8 comm[32];
    u16 lport;
    u16 rport;
}x;

struct bpf_map_def SEC("maps") eventmap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
    .value_size = sizeof(x),
    .max_entries = 3,
};

const struct info *unused __attribute__((unused));
u32 key = 0;

SEC("kprobe/security_socket_bind")
int bind_intercept(struct pt_regs *ctx,  const struct sockaddr *addr) {

    struct info infostruct;
    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct sock_common conn = READ_KERN(sk->__sk_common);

    u64 p= bpf_get_current_pid_tgid();
    p = p >>32;
    
    infostruct.pid=p;
    bpf_get_current_comm(&infostruct.comm,sizeof(infostruct.comm));
    
    struct sockaddr *address = (struct sockaddr *) PT_REGS_PARM2(ctx);
    struct sockaddr_in *in_addr = (struct sockaddr_in *) address;
    
    // checking bind port address
    u16 x = READ_KERN(in_addr->sin_port);
    infostruct.lport= bpf_ntohs(x);
    infostruct.rport  = READ_KERN(sk->__sk_common.skc_num);

    struct info *s;
    s = bpf_map_lookup_elem(&eventmap,&key);
    bool commcheck =  s->comm[0]=='m' && s->comm[1]=='y' && s->comm[2]=='p' && s->comm[3]=='r' && s->comm[4]=='o' && s->comm[5]=='c' && s->comm[6]=='e' && s->comm[7]=='s' && s->comm[8]=='s';
    if (commcheck) {
        key = key + 1;
    	bpf_map_update_elem(&eventmap,&key,&infostruct,BPF_ANY);
    }
    return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    
    u16 passport= 5000;
    struct info *s;
    s = bpf_map_lookup_elem(&eventmap,&key);
    if (!s) return XDP_PASS;

    // Get current port
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    bpf_printk("Received packet\n: ");
    if (data + TOTSZ > data_end) {
        return XDP_PASS;
    }

    __be16 port = tcph->dest;
     
    // Check this port is associated with process
    u32 i;
    for(i=0; i < 3; i++) {
        key = i;
        s = bpf_map_lookup_elem(&eventmap,&key);
        if (!s) return XDP_PASS;
        if (s->lport == port) {
            if (htons(passport) != port) {
	        return XDP_DROP; 
            }
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}

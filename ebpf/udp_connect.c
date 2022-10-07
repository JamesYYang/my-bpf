#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct net_udp_event
{
  u32 pid;
  char comm[16];
  u32 daddr;
  u16 dport;
};

/* BPF perfbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} udp_connect_events SEC(".maps");

SEC("kprobe/ip4_datagram_connect")
int kp_udp_connect(struct pt_regs *ctx)
{
  struct net_udp_event t = {};
  struct net_udp_event *data = &t;

  struct sockaddr *ska = (struct sockaddr *)PT_REGS_PARM2(ctx);
  u16 family = READ_KERN(ska->sa_family);

  if (family == AF_INET)
  {
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(data->comm, sizeof(data->comm));
    struct sockaddr_in *ska_in = (struct sockaddr_in *)ska;
    data->dport = bpf_ntohs(READ_KERN(ska_in->sin_port));
    data->daddr = READ_KERN(ska_in->sin_addr.s_addr);
    bpf_perf_event_output(ctx, &udp_connect_events, BPF_F_CURRENT_CPU, data, sizeof(*data));
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
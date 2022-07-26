#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

/* BPF ringbuf map */
// struct
// {
//   __uint(type, BPF_MAP_TYPE_RINGBUF);
//   __uint(max_entries, 256 * 1024 /* 256 KB */);
// } tcp_reset_events SEC(".maps");

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_reset_events SEC(".maps");

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
  return READ_KERN(skb->head) + READ_KERN(skb->transport_header);
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
  return READ_KERN(skb->head) + READ_KERN(skb->network_header);
}

SEC("kprobe/tcp_v4_send_reset")
int kp_tcp_v4_send_reset(struct pt_regs *ctx)
{
  struct net_sock_event t = {};
  struct net_sock_event *data = &t;

  data->pid = bpf_get_current_pid_tgid() >> 32;
  bpf_get_current_comm(data->comm, sizeof(data->comm));
  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
  struct tcphdr *tcp = (struct tcphdr *)skb_transport_header(skb);
  struct iphdr *ip = (struct iphdr *)skb_network_header(skb);
  data->dip = READ_KERN(ip->daddr);
  data->sip = READ_KERN(ip->saddr);
  data->dport = bpf_ntohs(READ_KERN(tcp->dest));
  data->sport = bpf_ntohs(READ_KERN(tcp->source));

  bpf_perf_event_output(ctx, &tcp_reset_events, BPF_F_CURRENT_CPU, data, sizeof(*data));

  return 0;
}

char _license[] SEC("license") = "GPL";
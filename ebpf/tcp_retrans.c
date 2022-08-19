#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct retrans_sock_data
{
  u32 sip;   //源IP
  u32 dip;   //目的IP
  u16 sport; //源端口
  u16 dport; //目的端口
  u8 state;
};

/* BPF ringbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} tcp_retrans_events SEC(".maps");


SEC("kprobe/tcp_retransmit_skb")
int kp_tcp_retransmit_skb(struct pt_regs *ctx)
{
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct sock_common sk_common = READ_KERN(sk->__sk_common);
  u16 family = sk_common.skc_family;

  if (family == AF_INET)
  {
    struct retrans_sock_data *data;
    data = bpf_ringbuf_reserve(&tcp_retrans_events, sizeof(*data), 0);
    if (!data)
    {
      return 0;
    }

    data->dip = sk_common.skc_daddr;
    data->sip = sk_common.skc_rcv_saddr;
    data->dport = bpf_ntohs(sk_common.skc_dport);
    data->sport = sk_common.skc_num;
    data->state = sk_common.skc_state;

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct sock_data
{
  __u32 sip;    //源IP
  __u32 dip;    //目的IP
  __u32 sport;  //源端口
  __u32 dport;  //目的端口
  __u32 family; //协议
};

/* BPF ringbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} tcp_connect_events SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct sock *sk, int old_state, int new_state)
{
  // struct sock *sk = (struct sock *)ctx->args[0];
  // int old_state = ctx->args[1];
  // int new_state = ctx->args[2];
  struct sock_common sk_common = READ_KERN(sk->__sk_common);
  u16 family = sk_common.skc_family;

  if (family == AF_INET) // && new_state == TCP_SYN_SENT)
  {
    struct sock_data *data;
    data = bpf_ringbuf_reserve(&tcp_connect_events, sizeof(*data), 0);
    if (!data)
    {
      return 0;
    }

    // data->sip = READ_KERN(sk_common.skc_rcv_saddr);
    // data->dip = READ_KERN(sk_common.skc_daddr);
    // data->sport = READ_KERN(sk_common.skc_num);
    // data->dport = bpf_ntohs(READ_KERN(sk_common.skc_dport));
    data->sip = sk_common.skc_rcv_saddr;
    data->dip = sk_common.skc_daddr;
    data->sport = sk_common.skc_num;
    data->dport = bpf_ntohs(sk_common.skc_dport);
    data->family = family;

    bpf_ringbuf_submit(data, 0);
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
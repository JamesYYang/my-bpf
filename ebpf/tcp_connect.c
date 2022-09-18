#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct net_tcp_event
{
  u32 pid;
  char comm[16];
  char saddr[16];
  char daddr[16];
  u16 sport;
  u16 dport;
  u16 family;
  u16 oldstate;
  u16 newstate;
};

/* BPF ringbuf map */
// struct
// {
//   __uint(type, BPF_MAP_TYPE_RINGBUF);
//   __uint(max_entries, 256 * 1024 /* 256 KB */);
// } tcp_connect_events SEC(".maps");

/* BPF perfbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_connect_events SEC(".maps");

/*
 * inet_sock_set_state tracepoint format.
 *
 * Format: cat /sys/kernel/debug/tracing/events/sock/inet_sock_set_state/format
 * Code: https://github.com/torvalds/linux/blob/v4.16/include/trace/events/sock.h#L123-L135
 */

SEC("tracepoint/sock/inet_sock_set_state")
int tracepoint_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
  u16 family = ctx->family;
  if (family == AF_INET)
  {
    struct net_tcp_event t = {};
    struct net_tcp_event *data = &t;
    
    data->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    data->family = family;
    data->newstate = ctx->newstate;
    data->oldstate = ctx->oldstate;
    bpf_probe_read(data->saddr, 4, ctx->saddr);
    bpf_probe_read(data->daddr, 4, ctx->daddr);
    data->sport = ctx->sport;
    data->dport = ctx->dport;
    bpf_perf_event_output(ctx, &tcp_connect_events, BPF_F_CURRENT_CPU, data, sizeof(*data));
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
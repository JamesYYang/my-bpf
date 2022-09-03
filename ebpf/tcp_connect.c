#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct net_tcp_event
{
  u64 ts;
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  char saddr[16];
  char daddr[16];
  u16 sport;
  u16 dport;
  u16 family;
  u16 oldstate;
  u16 newstate;
  char uts_name[65];
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

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_kconnect_events SEC(".maps");

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
  struct nsproxy *np = READ_KERN(task->nsproxy);
  struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
  return READ_KERN(uts_ns->name.nodename);
}

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
    // data = bpf_ringbuf_reserve(&tcp_connect_events, sizeof(*data), 0);
    // if (!data)
    // {
    //   return 0;
    // }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data->ts = bpf_ktime_get_ns();
    data->pid = READ_KERN(task->pid);
    data->tgid = READ_KERN(task->tgid);
    data->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    char *uts_name = get_task_uts_name(task);
    if (uts_name)
      bpf_probe_read_str(data->uts_name, sizeof(data->uts_name), uts_name);

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
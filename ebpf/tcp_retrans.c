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
// } tcp_retrans_events SEC(".maps");

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tcp_retrans_events SEC(".maps");

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	return READ_KERN(uts_ns->name.nodename);
}

SEC("kprobe/tcp_retransmit_skb")
int kp_tcp_retransmit_skb(struct pt_regs *ctx)
{
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  struct sock_common sk_common = READ_KERN(sk->__sk_common);
  u16 family = sk_common.skc_family;

  if (family == AF_INET)
  {
    struct exception_sock_data t = {};
    struct exception_sock_data *data = &t;
    // data = bpf_ringbuf_reserve(&tcp_retrans_events, sizeof(*data), 0);
    // if (!data)
    // {
    //   return 0;
    // }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    data->pid = READ_KERN(task->pid);
    data->tgid = READ_KERN(task->tgid);
    data->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
    bpf_get_current_comm(data->comm, sizeof(data->comm));

    char *uts_name = get_task_uts_name(task);
    if (uts_name)
      bpf_probe_read_str(data->uts_name, sizeof(data->uts_name), uts_name);

    data->dip = sk_common.skc_daddr;
    data->sip = sk_common.skc_rcv_saddr;
    data->dport = bpf_ntohs(sk_common.skc_dport);
    data->sport = sk_common.skc_num;
    // data->state = sk_common.skc_state;

    bpf_perf_event_output(ctx, &tcp_retrans_events, BPF_F_CURRENT_CPU, data, sizeof(*data));
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
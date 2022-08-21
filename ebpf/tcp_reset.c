#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

/* BPF ringbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} tcp_reset_events SEC(".maps");

static inline unsigned char *skb_transport_header(const struct sk_buff *skb)
{
  return READ_KERN(skb->head) + READ_KERN(skb->transport_header);
}

static inline unsigned char *skb_network_header(const struct sk_buff *skb)
{
  return READ_KERN(skb->head) + READ_KERN(skb->network_header);
}

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	return READ_KERN(uts_ns->name.nodename);
}

SEC("kprobe/tcp_v4_send_reset")
int kp_tcp_v4_send_reset(struct pt_regs *ctx)
{
  struct exception_sock_data *data;
  data = bpf_ringbuf_reserve(&tcp_reset_events, sizeof(*data), 0);
  if (!data)
  {
    return 0;
  }

  struct task_struct *task = (struct task_struct *)bpf_get_current_task();

  data->pid = READ_KERN(task->pid);
  data->tgid = READ_KERN(task->tgid);
  data->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
  bpf_get_current_comm(data->comm, sizeof(data->comm));

  char *uts_name = get_task_uts_name(task);
  if (uts_name)
    bpf_probe_read_str(data->uts_name, sizeof(data->uts_name), uts_name);

  struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM2(ctx);
  struct tcphdr *tcp = (struct tcphdr *)skb_transport_header(skb);
  struct iphdr *ip = (struct iphdr *)skb_network_header(skb);
  data->dip = READ_KERN(ip->daddr);
  data->sip = READ_KERN(ip->saddr);
  data->dport = bpf_ntohs(READ_KERN(tcp->dest));
  data->sport = bpf_ntohs(READ_KERN(tcp->source));

  bpf_ringbuf_submit(data, 0);

  return 0;
}

char _license[] SEC("license") = "GPL";
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct val_t
{
  u32 pid;
  u64 starts;
  u64 ends;
  char comm[16];
  char host[256];
} __attribute__((packed));

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct val_t);
  __uint(max_entries, 1024);
} start SEC(".maps");

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} udp_dns_events SEC(".maps");

SEC("uprobe/getaddrinfo")
int getaddrinfo_entry(struct pt_regs *ctx)
{
  struct val_t t = {};
  t.pid = bpf_get_current_pid_tgid() >> 32;
  t.starts = bpf_ktime_get_ns();
  bpf_get_current_comm(&t.comm, sizeof(t.comm));
  bpf_probe_read(&t.host, sizeof(t.host), (void *)PT_REGS_PARM1(ctx));
  bpf_map_update_elem(&start, &t.pid, &t, BPF_ANY);
  return 0;
}

SEC("uretprobe/getaddrinfo")
int getaddrinfo_return(struct pt_regs *ctx)
{
  struct val_t *valp;
  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;
  valp = bpf_map_lookup_elem(&start, &pid);
  if (valp == 0)
  {
    bpf_printk("miss entry");
    return 0; // missed start
  }

  valp->ends = bpf_ktime_get_ns();
  bpf_perf_event_output(ctx, &udp_dns_events, BPF_F_CURRENT_CPU, valp, sizeof(*valp));
  bpf_map_delete_elem(&start, &pid);
  
  return 0;
}

char _license[] SEC("license") = "GPL";
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"

struct sys_capable_event
{
  u32 pid;
  u32 uid;
  char comm[16];
  u8 cap;
  u8 audit;
};

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} sys_capable_events SEC(".maps");


SEC("kprobe/cap_capable")
int kp_sys_capable(struct pt_regs *ctx)
{
	struct sys_capable_event t = {};
	struct sys_capable_event *e = &t;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->cap = PT_REGS_PARM3(ctx);
    e->audit = PT_REGS_PARM4(ctx);
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    if (e->audit & CAP_OPT_NOAUDIT)
        return 0;

	bpf_perf_event_output(ctx, &sys_capable_events, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

char _license[] SEC("license") = "GPL";
#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"

struct openat_event
{
	u32 pid;
	u32 tgid;
	u32 ppid;
	char comm[50];
	char filename[256];
	char uts_name[64];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_enter_openat_events SEC(".maps");

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	return READ_KERN(uts_ns->name.nodename);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct openat_event *e;
	e = bpf_ringbuf_reserve(&sys_enter_openat_events, sizeof(*e), 0);
	if (!e)
	{
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	e->pid = READ_KERN(task->pid);
	e->tgid = READ_KERN(task->tgid);
	e->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	char *uts_name = get_task_uts_name(task);
	if (uts_name)
		bpf_probe_read_str(e->uts_name, sizeof(e->uts_name), uts_name);

	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[1]));
	bpf_ringbuf_submit(e, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
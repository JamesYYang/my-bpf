// +build ignore
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "helper.h"

struct execve_data
{
	u32 pid;
	u32 tgid;
	u32 ppid;
	char comm[50];
	char filename[50];
	// char cmdline[256];
	char uts_name[64];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} sys_enter_execve_events SEC(".maps");

// static __always_inline void get_proc_cmdline(struct task_struct *task, char *cmdline, int size)
// {
// 	struct mm_struct *mm = READ_KERN(task->mm);
// 	long unsigned int args_start = READ_KERN(mm->arg_start);
// 	long unsigned int args_end = READ_KERN(mm->arg_end);
// 	int len = (args_end - args_start);
// 	if (len >= size)
// 		len = size - 1;
// 	bpf_probe_read(cmdline, len & (size - 1), (const void *)args_start);
// }

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	return READ_KERN(uts_ns->name.nodename);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct execve_data *e;

	e = bpf_ringbuf_reserve(&sys_enter_execve_events, sizeof(*e), 0);
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

	// get_proc_cmdline(task, e->cmdline, sizeof(e->cmdline));

	bpf_probe_read_user_str(e->filename, sizeof(e->filename), (char *)(ctx->args[0]));

	bpf_ringbuf_submit(e, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
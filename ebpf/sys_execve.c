#include "vmlinux.h"
#include "bpf_helpers.h"
#include "helper.h"
#include "bpf_tracing.h"

/* BPF ringbuf map */
// struct
// {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024 /* 256 KB */);
// } sys_enter_execve_events SEC(".maps");

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} sys_enter_execve_events SEC(".maps");

// 一个 struct event 变量的大小超过了 512 字节，无法放到 BPF 栈上，
// 因此声明一个 size=1 的 per-CPU array 来存放 event 变量
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per-cpu array
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sys_execve_event);
} heap SEC(".maps");

static __always_inline char *get_task_uts_name(struct task_struct *task)
{
	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	return READ_KERN(uts_ns->name.nodename);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
	int zero = 0;
	struct sys_execve_event *e;
	e = bpf_map_lookup_elem(&heap, &zero);
	if (!e) /* can't happen */
	{
		return 0;
	}
	// struct sys_execve_event *e;
	// e = bpf_ringbuf_reserve(&sys_enter_execve_events, sizeof(*e), 0);
	// if (!e)
	// {
	// 	return 0;
	// }
  e->ts = bpf_ktime_get_ns();
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->pid = READ_KERN(task->pid);
	e->tgid = READ_KERN(task->tgid);
	e->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
	bpf_get_current_comm(e->comm, sizeof(e->comm));

	bpf_probe_read_user_str(e->filename, sizeof(e->filename), (char *)(ctx->args[0]));

	char *uts_name = get_task_uts_name(task);
	if (uts_name)
		bpf_probe_read_str(e->uts_name, sizeof(e->uts_name), uts_name);

	char **args = (char **)(ctx->args[1]);
	e->buf_off = 0;

	for (int i = 1; i < MAX_STR_ARR_ELEM; i++)
	{
		char *argp = READ_USER(args[i]);
		if (!argp)
			break;

		if (e->buf_off > MAX_PERCPU_BUFSIZE - MAX_STRING_SIZE)
			// not enough space - return
			break;

		// Read into buffer
		int sz = bpf_probe_read_user_str(&(e->args[e->buf_off]), MAX_STRING_SIZE, argp);
		if (sz > 0)
		{
			e->buf_off += sz;
		}
		else
		{
			break;
		}
	}

	bpf_perf_event_output(ctx, &sys_enter_execve_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	// bpf_ringbuf_submit(e, 0);

	return 0;
}

char _license[] SEC("license") = "GPL";
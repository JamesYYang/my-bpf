#include "vmlinux.h"
#include "bpf_helpers.h"
#include "helper.h"
#include "bpf_tracing.h"

struct sys_execve_event
{
	u32 pid;
	u32 tgid;
	u32 ppid;
	char comm[16];
	char uts_name[64];
	char filename[256];
	u32 buf_off;
	char args[MAX_PERCPU_BUFSIZE];
};

// 一个 struct event 变量的大小超过了 512 字节，无法放到 BPF 栈上，
// 因此声明一个 size=1 的 per-CPU array 来存放 event 变量
struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); // per-cpu array
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct sys_execve_event);
} heap SEC(".maps");

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

	get_task_info(e);
	memset(&e->filename[0], 0, sizeof(e->filename));
	bpf_probe_read_user_str(e->filename, sizeof(e->filename), (char *)(ctx->args[0]));

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

	bpf_printk("args: %s", e->args);

	bpf_perf_event_output(ctx, &sys_enter_execve_events, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

char _license[] SEC("license") = "GPL";
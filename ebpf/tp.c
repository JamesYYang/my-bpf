#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

struct event
{
	int pid;
	char filename[256];
};

/* BPF ringbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} tp_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&tp_events, sizeof(*e), 0);
	if (!e)
	{
		return 0;
	}
	e->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[1]));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char _license[] SEC("license") = "GPL";
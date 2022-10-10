#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"

struct sys_openat_event
{
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
	char uts_name[64];
  char filename[256];
};

/* BPF ringbuf map */
// struct
// {
// 	__uint(type, BPF_MAP_TYPE_RINGBUF);
// 	__uint(max_entries, 256 * 1024 /* 256 KB */);
// } sys_enter_openat_events SEC(".maps");

/* BPF perfbuf map */
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} sys_enter_openat_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct sys_openat_event t = {};
	struct sys_openat_event *e = &t;
	// e = bpf_ringbuf_reserve(&sys_enter_openat_events, sizeof(*e), 0);
	// if (!e)
	// {
	// 	return 0;
	// }

	get_task_info(e);

	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (char *)(ctx->args[1]));
	bpf_perf_event_output(ctx, &sys_enter_openat_events, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

char _license[] SEC("license") = "GPL";
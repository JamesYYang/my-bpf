#define READ_KERN(ptr)                                 \
  ({                                                   \
    typeof(ptr) _val;                                  \
    __builtin_memset((void *)&_val, 0, sizeof(_val));  \
    bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
    _val;                                              \
  })

#define READ_USER(ptr)                                      \
  ({                                                        \
    typeof(ptr) _val;                                       \
    __builtin_memset((void *)&_val, 0, sizeof(_val));       \
    bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
    _val;                                                   \
  })

#define memset(dest, chr, n) __builtin_memset((dest), (chr), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define ctx_ptr(field)		(void *)(long)(field)

#define AF_INET 2
#define AF_INET6 10

#define MAX_PERCPU_BUFSIZE 10240
#define MAX_STR_ARR_ELEM 40
#define MAX_STRING_SIZE 4096

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

struct task_base_info
{
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  char uts_name[64];
};

struct net_sock_event
{
  u32 pid;
  char comm[16];
  u32 sip;   //源IP
  u32 dip;   //目的IP
  u16 sport; //源端口
  u16 dport; //目的端口
};

struct net_packet_event
{
  u64 ts;
  u32 len;
  u32 ifindex;
  u32 sip;   //源IP
  u32 dip;   //目的IP
  u16 sport; //源端口
  u16 dport; //目的端口
  bool ingress;
};

static inline void get_task_info(void *t)
{
  struct task_base_info *base_info = (struct task_base_info *)t;
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  base_info->pid = READ_KERN(task->pid);
	base_info->tgid = READ_KERN(task->tgid);
	base_info->ppid = READ_KERN(READ_KERN(task->real_parent)->pid);
	bpf_get_current_comm(base_info->comm, sizeof(base_info->comm));

	struct nsproxy *np = READ_KERN(task->nsproxy);
	struct uts_namespace *uts_ns = READ_KERN(np->uts_ns);
	char *uts_name = READ_KERN(uts_ns->name.nodename);
  if (uts_name)
  {
    memset(&base_info->uts_name[0], 0, sizeof(base_info->uts_name));
    bpf_probe_read_str(base_info->uts_name, sizeof(base_info->uts_name), uts_name);
  }
}
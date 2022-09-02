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

#define AF_INET 2
#define AF_INET6 10

struct sys_probe_event
{
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  char filename[256];
  char uts_name[65];
};

#define MAX_PERCPU_BUFSIZE  10240
#define MAX_STR_ARR_ELEM      40
#define MAX_STRING_SIZE     4096 

#define TC_ACT_UNSPEC         (-1)
#define TC_ACT_OK               0
#define TC_ACT_SHOT             2
#define TC_ACT_STOLEN           4
#define TC_ACT_REDIRECT         7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

struct sys_execve_event
{
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  u32 buf_off;
  char filename[256];
  char uts_name[65];
  char args[MAX_PERCPU_BUFSIZE];
};

struct exception_sock_data
{
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  u32 sip;   //源IP
  u32 dip;   //目的IP
  u16 sport; //源端口
  u16 dport; //目的端口
  char uts_name[65];
};

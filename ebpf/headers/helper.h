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

#define memset(dest, chr, n)  __builtin_memset((dest), (chr), (n))

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))

#define AF_INET 2
#define AF_INET6 10

struct sys_probe_event
{
  u64 ts;
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
#define MAX_DNS_NAME_LENGTH 256

struct sys_execve_event
{
  u64 ts;
  u32 pid;
  u32 tgid;
  u32 ppid;
  char comm[16];
  u32 buf_off;
  char filename[256];
  char uts_name[65];
  char args[MAX_PERCPU_BUFSIZE];
};

struct net_sock_event
{
  u64 ts;
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

struct dns_hdr
{
    uint16_t transaction_id;
    uint8_t rd : 1;      //Recursion desired
    uint8_t tc : 1;      //Truncated
    uint8_t aa : 1;      //Authoritive answer
    uint8_t opcode : 4;  //Opcode
    uint8_t qr : 1;      //Query/response flag
    uint8_t rcode : 4;   //Response code
    uint8_t cd : 1;      //Checking disabled
    uint8_t ad : 1;      //Authenticated data
    uint8_t z : 1;       //Z reserved bit
    uint8_t ra : 1;      //Recursion available
    uint16_t q_count;    //Number of questions
    uint16_t ans_count;  //Number of answer RRs
    uint16_t auth_count; //Number of authority RRs
    uint16_t add_count;  //Number of resource RRs
};

struct dns_query {
    uint16_t record_type;
    uint16_t class;
    char name[MAX_DNS_NAME_LENGTH];
};
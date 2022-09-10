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

struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};

struct dns_response {
   uint16_t query_pointer;
   uint16_t record_type;
   uint16_t class;
   uint32_t ttl;
   uint16_t data_length;
};

static inline void swap_mac_addresses(struct __sk_buff *skb) {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, 6);
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, 6);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, 6, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, 6, 0);
}

#define ETH_HLEN sizeof(struct ethhdr)

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

static inline void swap_ip_addresses(struct __sk_buff *skb) {
  unsigned char src_ip[4];
  unsigned char dst_ip[4];
  bpf_skb_load_bytes(skb, IP_SRC_OFF, src_ip, 4);
  bpf_skb_load_bytes(skb, IP_DST_OFF, dst_ip, 4);
  bpf_skb_store_bytes(skb, IP_SRC_OFF, dst_ip, 4, 0);
  bpf_skb_store_bytes(skb, IP_DST_OFF, src_ip, 4, 0);
}


// Update IP checksum for IP header, as specified in RFC 1071
// The checksum_location is passed as a pointer. At this location 16 bits need to be set to 0.
static inline void update_ip_checksum(void *data, int len, uint16_t *checksum_location)
{
  uint32_t accumulator = 0;
  int i;
  for (i = 0; i < len; i += 2)
  {
    uint16_t val;
    // If we are currently at the checksum_location, set to zero
    if (data + i == checksum_location)
    {
      val = 0;
    }
    else
    {
      // Else we load two bytes of data into val
      val = *(uint16_t *)(data + i);
    }
    accumulator += val;
  }

  // Add 16 bits overflow back to accumulator (if necessary)
  uint16_t overflow = accumulator >> 16;
  accumulator &= 0x00FFFF;
  accumulator += overflow;

  // If this resulted in an overflow again, do the same (if necessary)
  accumulator += (accumulator >> 16);
  accumulator &= 0x00FFFF;

  // Invert bits and set the checksum at checksum_location
  uint16_t chk = accumulator ^ 0xFFFF;
  *checksum_location = chk;
}
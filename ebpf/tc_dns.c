#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

/* BPF perfbuf map */
struct
{
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} tc_dns_events SEC(".maps");


// Parse query and return query length
static inline int parse_query(struct __sk_buff *ctx, void *query_start, struct dns_query *q)
{
  void *data_end = (void *)(long)ctx->data_end;

  uint16_t i;
  void *cursor = query_start;
  int namepos = 0;

  // Fill dns_query.name with zero bytes
  // Not doing so will make the verifier complain when dns_query is used as a key in bpf_map_lookup
  memset(&q->name[0], 0, sizeof(q->name));
  // Fill record_type and class with default values to satisfy verifier
  q->record_type = 0;
  q->class = 0;

  // We create a bounded loop of MAX_DNS_NAME_LENGTH (maximum allowed dns name size).
  // We'll loop through the packet byte by byte until we reach '0' in order to get the dns query name
  for (i = 0; i < MAX_DNS_NAME_LENGTH; i++)
  {

    // Boundary check of cursor. Verifier requires a +1 here.
    // Probably because we are advancing the pointer at the end of the loop
    if (cursor + 1 > data_end)
    {
      break;
    }
    
    // If separator is zero we've reached the end of the domain query
    if (*(char *)(cursor) == 0)
    {

      // We've reached the end of the query name.
      // This will be followed by 2x 2 bytes: the dns type and dns class.
      if (cursor + 5 > data_end)
      {
        break;
      }
      else
      {
        q->record_type = bpf_htons(*(uint16_t *)(cursor + 1));
        q->class = bpf_htons(*(uint16_t *)(cursor + 3));
      }

      // Return the bytecount of (namepos + current '0' byte + dns type + dns class) as the query length.
      return namepos + 1 + 2 + 2;
    }

    // Read and fill data into struct
    q->name[namepos] = *(char *)(cursor);
    namepos++;
    cursor++;
  }

  return -1;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int tc_dns_func(struct __sk_buff *ctx)
{
  void *data_end = (void *)(unsigned long)ctx->data_end;
  void *data = (void *)(unsigned long)ctx->data;

  // Boundary check: check if packet is larger than a full ethernet + ip header
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
  {
    return TC_ACT_OK;
  }

  struct ethhdr *eth = data;

  // Ignore packet if ethernet protocol is not IP-based
  if (eth->h_proto != bpf_htons(ETH_P_IP))
  {
    return TC_ACT_OK;
  }

  struct iphdr *ip = data + sizeof(*eth);

  if (ip->protocol == IPPROTO_UDP)
  {
    struct udphdr *udp;
    // Boundary check for UDP
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) > data_end)
    {
      return TC_ACT_OK;
    }

    udp = data + sizeof(*eth) + sizeof(*ip);

    // Check if dest port equals 53
    if (udp->dest == bpf_htons(53))
    {
      struct dns_hdr *dns_hdr;

      // Boundary check for minimal DNS header
      if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*dns_hdr) > data_end)
      {
        return TC_ACT_OK;
      }

      dns_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);

      // Check if header contains a standard query
      if (dns_hdr->qr == 0 && dns_hdr->opcode == 0)
      {
        bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));

        // Get a pointer to the start of the DNS query
        void *query_start = (void *)dns_hdr + sizeof(struct dns_hdr);
        // We will only be parsing a single query for now
        struct dns_query q;
        int query_length = 0;
        query_length = parse_query(ctx, query_start, &q);
        if (query_length < 1)
        {
          return TC_ACT_OK;
        }

        bpf_printk("DNS record type: %i", q.record_type);
        bpf_printk("DNS class: %i", q.class);
        bpf_printk("DNS name: %s", q.name);
      }
    }
  }

  return TC_ACT_OK;
};


char _license[] SEC("license") = "GPL";
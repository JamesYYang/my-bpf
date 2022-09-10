#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

char dns_buffer[512];

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

static inline void modify_dns_header_response(struct dns_hdr *dns_hdr)
{
  // Set query response
  dns_hdr->qr = 1;
  // Set truncated to 0
  // dns_hdr->tc = 0;
  // Set authorative to zero
  // dns_hdr->aa = 0;
  // Recursion available
  dns_hdr->ra = 1;
  // One answer
  dns_hdr->ans_count = bpf_htons(1);
}

static inline void create_query_response(struct a_record *a, char *dns_buffer, size_t *buf_size)
{
  // Formulate a DNS response. Currently defaults to hardcoded query pointer + type a + class in + ttl + 4 bytes as reply.
  struct dns_response *response = (struct dns_response *)&dns_buffer[0];
  response->query_pointer = bpf_htons(0xc00c);
  response->record_type = bpf_htons(0x0001);
  response->class = bpf_htons(0x0001);
  response->ttl = bpf_htonl(a->ttl);
  response->data_length = bpf_htons((uint16_t)sizeof(a->ip_addr));
  *buf_size += sizeof(struct dns_response);
  // Copy IP address
  memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(struct in_addr));
  *buf_size += sizeof(struct in_addr);
}

//__builtin_memcpy only supports static size_t
// The following function is a memcpy wrapper that uses __builtin_memcpy when size_t n is known.
// Otherwise it uses our own naive & slow memcpy routine
static inline void copy_to_pkt_buf(struct __sk_buff *ctx, void *dst, void *src, size_t n)
{
  // Boundary check
  if ((void *)(long)ctx->data_end >= dst + n)
  {
    int i;
    char *cdst = dst;
    char *csrc = src;

    // For A records, src is either 16 or 27 bytes, depending if OPT record is requested.
    // Use __builtin_memcpy for this. Otherwise, use our own slow, naive memcpy implementation.
    switch (n)
    {
    case 16:
      __builtin_memcpy(cdst, csrc, 16);
      break;

    case 27:
      __builtin_memcpy(cdst, csrc, 27);
      break;

    default:
      for (i = 0; i < n; i += 1)
      {
        cdst[i] = csrc[i];
      }
    }
  }
}

// static inline void swap_mac(uint8_t *src_mac, uint8_t *dst_mac)
// {
//   int i;
//   for (i = 0; i < 6; i++)
//   {
//     uint8_t tmp_src;
//     tmp_src = *(src_mac + i);
//     *(src_mac + i) = *(dst_mac + i);
//     *(dst_mac + i) = tmp_src;
//   }
// }

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int tc_dns_func(struct __sk_buff *ctx)
{
  uint64_t start = bpf_ktime_get_ns();

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
        // bpf_printk("DNS query transaction id %u", bpf_ntohs(dns_hdr->transaction_id));

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

        // bpf_printk("DNS record type: %i", q.record_type);
        // bpf_printk("DNS class: %i", q.class);
        // bpf_printk("DNS name: %s", q.name);

        size_t buf_size = 0;
        // Check if query matches a record in our hash table
        struct a_record a_record;

        a_record.ip_addr.s_addr = 0x846F070A;
        a_record.ttl = 120;

        // Change DNS header to a valid response header
        modify_dns_header_response(dns_hdr);

        // Create DNS response and add to temporary buffer.
        create_query_response(&a_record, &dns_buffer[buf_size], &buf_size);

        // // Start our response [query_length] bytes beyond the header
        void *answer_start = (void *)dns_hdr + sizeof(struct dns_hdr) + query_length;
        // // Determine increment of packet buffer
        int tailadjust = answer_start + buf_size - data_end;

        // // Adjust packet length accordingly 
        if (bpf_skb_change_tail(ctx, tailadjust, 0))
        {
          bpf_printk("Adjust tail fail");
        }
        else
        {
          // Because we adjusted packet length, mem addresses might be changed.
          // Reinit pointers, as verifier will complain otherwise.
          data = (void *)(unsigned long)ctx->data;
          data_end = (void *)(unsigned long)ctx->data_end;

          // Copy bytes from our temporary buffer to packet buffer
          copy_to_pkt_buf(ctx, data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dns_hdr) + query_length,
                          &dns_buffer[0], buf_size);

          eth = data;
          ip = data + sizeof(struct ethhdr);
          udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

          // Do a new boundary check
          if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
          {
            return TC_ACT_OK;
          }

          // Adjust UDP length and IP length
          uint16_t iplen = (data_end - data) - sizeof(struct ethhdr);
          uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct iphdr);
          ip->tot_len = bpf_htons(iplen);
          udp->len = bpf_htons(udplen);

          // Swap eth macs
          // swap_mac((uint8_t *)eth->h_source, (uint8_t *)eth->h_dest);
          swap_mac_addresses(ctx);

          // Swap src/dst IP
          // uint32_t src_ip = ip->saddr;
          // ip->saddr = ip->daddr;
          // ip->daddr = src_ip;
          swap_ip_addresses(ctx);

          // Set UDP checksum to zero
          udp->check = 0;

          // Swap udp src/dst ports
          uint16_t tmp_src = udp->source;
          udp->source = udp->dest;
          udp->dest = tmp_src;

          // Recalculate IP checksum
          update_ip_checksum(ip, sizeof(struct iphdr), &ip->check);

          uint64_t end = bpf_ktime_get_ns();
          uint64_t elapsed = end - start;
          bpf_printk("Time elapsed: %d", elapsed);

          // Redirecting the modified skb on the same interface to be transmitted
          // again
          bpf_clone_redirect(ctx, ctx->ifindex, BPF_F_INGRESS);

          // We modified the packet and redirected a clone of it, so drop this one
          return TC_ACT_SHOT;
        }
      }
    }
  }

  return TC_ACT_OK;
};

char _license[] SEC("license") = "GPL";
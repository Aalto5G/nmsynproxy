#include "synproxy.h"
#include "ipcksum.h"
#include "branchpredict.h"
#include <sys/time.h>
#include <arpa/inet.h>
#include "time64.h"

#define MAX_FRAG 65535
#define IPV6_FRAG_CUTOFF 512


static inline uint32_t gen_flowlabel(const void *local_ip, uint16_t local_port,
                                     const void *remote_ip, uint16_t remote_port)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_buf(&ctx, local_ip, 16);
  siphash_feed_buf(&ctx, remote_ip, 16);
  siphash_feed_u64(&ctx, ((uint32_t)local_port)<<16 | remote_port);
  return siphash_get(&ctx) & ((1U<<20) - 1);
}

static inline uint32_t gen_flowlabel_entry(struct synproxy_hash_entry *e)
{
  if (e->version != 6)
  {
    abort();
  }
  return gen_flowlabel(&e->local_ip, e->local_port, &e->remote_ip, e->remote_port);
}

static void add_off(size_t *off, ssize_t val)
{
  if (val > 0)
  {
    (*off) += (size_t)val;
  }
}

static size_t synproxy_state_to_str(
  char *str, size_t bufsiz, struct synproxy_hash_entry *e)
{
  size_t off = 0;
  int already = 0;
  add_off(&off, snprintf(str + off, bufsiz - off, "<"));
  if (e->flag_state & FLAG_STATE_UPLINK_SYN_SENT)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "UPLINK_SYN_SENT"));
  }
  if (e->flag_state & FLAG_STATE_UPLINK_SYN_RCVD)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "UPLINK_SYN_RCVD"));
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "DOWNLINK_SYN_SENT"));
  }
  if (e->flag_state & FLAG_STATE_ESTABLISHED)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "ESTABLISHED"));
  }
  if (e->flag_state & FLAG_STATE_UPLINK_FIN)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "UPLINK_FIN"));
  }
  if (e->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "UPLINK_FIN_ACK"));
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_FIN)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "DOWNLINK_FIN"));
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_FIN_ACK)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "DOWNLINK_FIN_ACK"));
  }
  if (e->flag_state & FLAG_STATE_TIME_WAIT)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "TIME_WAIT"));
  }
  if (e->flag_state & FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "DOWNLINK_HALF_OPEN"));
  }
  if (e->flag_state & FLAG_STATE_RESETED)
  {
    if (already)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, ","));
    }
    already = 1;
    add_off(&off, snprintf(str + off, bufsiz - off, "RESETED"));
  }
  add_off(&off, snprintf(str + off, bufsiz - off, ">"));
  return off;
}

static size_t synproxy_entry_to_str(
  char *str, size_t bufsiz, struct synproxy_hash_entry *e)
{
  size_t off = 0;
  off += synproxy_state_to_str(str + off, bufsiz - off, e);
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  if (e->version == 4)
  {
    add_off(&off, snprintf(str + off, bufsiz - off, "local_end=%d.%d.%d.%d:%d",
                    (ntohl(e->local_ip.ipv4)>>24)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>16)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>8)&0xFF,
                    (ntohl(e->local_ip.ipv4)>>0)&0xFF,
                    e->local_port));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "remote_end=%d.%d.%d.%d:%d",
                    (ntohl(e->remote_ip.ipv4)>>24)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>16)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>8)&0xFF,
                    (ntohl(e->remote_ip.ipv4)>>0)&0xFF,
                    e->remote_port));
  }
  else
  {
    struct in6_addr in6loc, in6rem;
    char str6loc[INET6_ADDRSTRLEN] = {0};
    char str6rem[INET6_ADDRSTRLEN] = {0};
    memcpy(in6loc.s6_addr, &e->local_ip, 16);
    memcpy(in6rem.s6_addr, &e->remote_ip, 16);
    if (inet_ntop(AF_INET6, &in6loc, str6loc, sizeof(str6loc)) == NULL)
    {
      strncpy(str6loc, "UNKNOWN", sizeof(str6loc));
    }
    if (inet_ntop(AF_INET6, &in6rem, str6rem, sizeof(str6rem)) == NULL)
    {
      strncpy(str6rem, "UNKNOWN", sizeof(str6rem));
    }
    add_off(&off, snprintf(str + off, bufsiz - off, "local_end=[%s]:%d",
                    str6loc, e->local_port));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "remote_end=[%s]:%d",
                    str6rem, e->remote_port));
  }
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wscalediff=%d", e->wscalediff));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_wscale=%d", e->statetrack.lan.wscale));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wan_wscale=%d", e->statetrack.wan.wscale));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "was_synproxied=%d", e->was_synproxied));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_sack_was_supported=%d", e->lan_sack_was_supported));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "seqoffset=%u", e->seqoffset));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "tsoffset=%u", e->tsoffset));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_sent=%u", e->statetrack.lan.sent));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wan_sent=%u", e->statetrack.wan.sent));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_acked=%u", e->statetrack.lan.acked));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wan_acked=%u", e->statetrack.wan.acked));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_max=%u", e->statetrack.lan.max));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wan_max=%u", e->statetrack.wan.max));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "lan_max_window_unscaled=%u", e->statetrack.lan.max_window_unscaled));
  add_off(&off, snprintf(str + off, bufsiz - off, ", "));
  add_off(&off, snprintf(str + off, bufsiz - off, "wan_max_window_unscaled=%u", e->statetrack.wan.max_window_unscaled));
  return off;
}

static size_t synproxy_packet_to_str(
  char *str, size_t bufsiz, const void *ether)
{
  size_t off = 0;
  const void *ip = ether_const_payload(ether);
  const void *ippay;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;

  if (ip_version(ip) == 4)
  {
    ippay = ip_const_payload(ip);
    src_ip = ip_src(ip);
    dst_ip = ip_dst(ip);
    src_port = tcp_src_port(ippay);
    dst_port = tcp_dst_port(ippay);
    add_off(&off, snprintf(str + off, bufsiz - off, "src_end=%d.%d.%d.%d:%d",
                    (src_ip>>24)&0xFF,
                    (src_ip>>16)&0xFF,
                    (src_ip>>8)&0xFF,
                    (src_ip>>0)&0xFF,
                    src_port));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "dst_end=%d.%d.%d.%d:%d",
                    (dst_ip>>24)&0xFF,
                    (dst_ip>>16)&0xFF,
                    (dst_ip>>8)&0xFF,
                    (dst_ip>>0)&0xFF,
                    dst_port));
    add_off(&off, snprintf(str + off, bufsiz - off, ", flags="));
    if (tcp_syn(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "S"));
    }
    if (tcp_ack(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "A"));
    }
    if (tcp_fin(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "F"));
    }
    if (tcp_rst(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "R"));
    }
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "seq=%u", tcp_seq_number(ippay)));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "ack=%u", tcp_ack_number(ippay)));
    return off;
  }
  else if (ip_version(ip) == 6)
  {
    uint8_t proto;
    struct in6_addr in6src, in6dst;
    char str6src[INET6_ADDRSTRLEN] = {0};
    char str6dst[INET6_ADDRSTRLEN] = {0};
    ippay = ipv6_const_proto_hdr(ip, &proto);
    if (ippay == NULL || proto != 6)
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "unknown protocol"));
      return off;
    }
    memcpy(in6src.s6_addr, ipv6_const_src(ip), 16);
    memcpy(in6dst.s6_addr, ipv6_const_dst(ip), 16);
    if (inet_ntop(AF_INET6, &in6src, str6src, sizeof(str6src)) == NULL)
    {
      strncpy(str6src, "UNKNOWN", sizeof(str6src));
    }
    if (inet_ntop(AF_INET6, &in6dst, str6dst, sizeof(str6dst)) == NULL)
    {
      strncpy(str6dst, "UNKNOWN", sizeof(str6dst));
    }
    src_port = tcp_src_port(ippay);
    dst_port = tcp_dst_port(ippay);
    add_off(&off, snprintf(str + off, bufsiz - off, "src_end=[%s]", str6src));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "dst_end=[%s]", str6dst));
    add_off(&off, snprintf(str + off, bufsiz - off, ", flags="));
    if (tcp_syn(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "S"));
    }
    if (tcp_ack(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "A"));
    }
    if (tcp_fin(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "F"));
    }
    if (tcp_rst(ippay))
    {
      add_off(&off, snprintf(str + off, bufsiz - off, "R"));
    }
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "seq=%u", tcp_seq_number(ippay)));
    add_off(&off, snprintf(str + off, bufsiz - off, ", "));
    add_off(&off, snprintf(str + off, bufsiz - off, "ack=%u", tcp_ack_number(ippay)));
    return off;
  }
  else
  {
    add_off(&off, snprintf(str + off, bufsiz - off, "unknown protocol"));
    return off;
  }
}

static inline int rst_is_valid(uint32_t rst_seq, uint32_t ref_seq)
{
  int32_t diff = (int32_t)(rst_seq - ref_seq);
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", rst_seq, ref_seq);
  }
  return diff >= -3;
}

static inline int resend_request_is_valid(uint32_t seq, uint32_t ref_seq)
{
  int32_t diff = (int32_t)(seq - ref_seq);
  if (diff >= 0)
  {
    if (diff > 512*1024*1024)
    {
      log_log(LOG_LEVEL_EMERG, "WORKER",
        "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
    }
    return diff <= 3;
  }
  if (diff < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", seq, ref_seq);
  }
  return diff >= -3;
}

// caller must not have worker_local lock
// caller must not have bucket lock
static void synproxy_expiry_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *td)
{
  struct worker_local *local = ud;
  struct synproxy_hash_entry *e;
  e = CONTAINER_OF(timer, struct synproxy_hash_entry, timer);
  hash_table_delete(&local->hash, &e->node, synproxy_hash(e));
  worker_local_wrlock(local);
  if (e->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  if (e->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    linked_list_delete(&e->state_data.downlink_half_open.listnode);
    local->half_open_connections--;
  }
  if (e->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    timer_linkheap_remove(&local->timers, &e->syn_timer);
  }
  worker_local_wrunlock(local);
  free(e);
}

static inline int seq_cmp(uint32_t x, uint32_t y)
{
  int32_t result = (int32_t)(x-y);
  if (result > 512*1024*1024 || result < -512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u", x, y);
  }
  if (result > 0)
  {
    return 1;
  }
  if (result < 0)
  {
    return -1;
  }
  return result;
}

static inline uint32_t between(uint32_t a, uint32_t x, uint32_t b)
{
  if (b - a > 512*1024*1024)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "TOO GREAT SEQUENCE NUMBER DIFFERENCE %u %u %u", a, x, b);
  }
  if (b >= a)
  {
    return x >= a && x < b;
  }
  else
  {
    return x >= a || x < b;
  }
}

static inline int
rst_is_valid_downlink(uint32_t seq, struct tcp_statetrack_entry *statetrack)
{
  return rst_is_valid(seq, statetrack->wan.sent) ||
         rst_is_valid(seq, statetrack->lan.acked);
}

static inline int
rst_is_valid_uplink(uint32_t seq, struct tcp_statetrack_entry *statetrack)
{
  return rst_is_valid(seq, statetrack->lan.sent) ||
         rst_is_valid(seq, statetrack->wan.acked);
}

struct seqs {
  uint32_t first_seq;
  uint32_t last_seq;
};

static inline int
seqs_valid_downlink(struct synproxy_hash_entry *entry,
                    struct seqs *seqs,
                    const char *ether, const char *ip, const char *ippay,
                    int log,
                    char *statebuf, size_t statebufsiz,
                    char *packetbuf, size_t packetbufsiz)
{
  uint32_t wan_min;

  if (!between(
    entry->statetrack.wan.acked -
      (((uint32_t)entry->statetrack.wan.max_window_unscaled)<<entry->statetrack.wan.wscale),
    tcp_ack_number(ippay),
    entry->statetrack.lan.sent + 1 + MAX_FRAG))
  {
    if (log)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
    }
    return 0;
  }
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      if (log)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      }
      return 0;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      if (log)
      {
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      }
      return 0;
    }
  }
  wan_min =
    entry->statetrack.wan.sent -
      (((uint32_t)entry->statetrack.lan.max_window_unscaled)<<entry->statetrack.lan.wscale);
  if (
    !between(
      wan_min, seqs->first_seq, entry->statetrack.lan.max+1)
    &&
    !between(
      wan_min, seqs->last_seq, entry->statetrack.lan.max+1)
    )
  {
    if (log)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "packet has invalid SEQ number, state: %s, packet: %s", statebuf, packetbuf);
    }
    return 0;
  }
  return 1;
}

static inline int
seqs_valid_uplink(struct synproxy_hash_entry *entry,
                  struct seqs *seqs,
                  const char *ether, const char *ip, const char *ippay,
                  int log,
                  char *statebuf, size_t statebufsiz,
                  char *packetbuf, size_t packetbufsiz)
{
  uint32_t lan_min;

  if (!between(
    entry->statetrack.lan.acked -
      (((uint32_t)entry->statetrack.lan.max_window_unscaled)<<entry->statetrack.lan.wscale),
    tcp_ack_number(ippay),
    entry->statetrack.wan.sent + 1 + MAX_FRAG))
  {
    if (log)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
    }
    return 0;
  }
  if (unlikely(tcp_fin(ippay)))
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      if (log)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      }
      return 0;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      if (log)
      {
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      }
      return 0;
    }
  }
  lan_min =
    entry->statetrack.lan.sent -
      (((uint32_t)entry->statetrack.wan.max_window_unscaled)<<entry->statetrack.wan.wscale);
  if (
    !between(
      lan_min, seqs->first_seq, entry->statetrack.wan.max+1)
    &&
    !between(
      lan_min, seqs->last_seq, entry->statetrack.wan.max+1)
    )
  {
    if (log)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "packet has invalid SEQ number, state: %s, packet: %s", statebuf, packetbuf);
    }
    return 0;
  }
  return 1;
}

static inline void
calc_seqs(struct seqs *seqs, const char *ip, const char *ippay, uint32_t offset)
{
  int32_t data_len;
  uint32_t ip_len = ip_total_len(ip);
  uint32_t ihl = ip_hdr_len(ip);

  seqs->first_seq = tcp_seq_number(ippay);
  data_len =
    ((int32_t)ip_len) - ((int32_t)ihl) - ((int32_t)tcp_data_offset(ippay));
  if (data_len < 0)
  {
    // This can occur in fragmented packets. We don't then know the true
    // data length, and can therefore drop packets that would otherwise be
    // valid.
    data_len = 0;
  }
  seqs->last_seq = seqs->first_seq + ((uint32_t)data_len) - 1U;

  seqs->first_seq += offset;
  seqs->last_seq += offset;

  if (unlikely(tcp_fin(ippay)))
  {
    seqs->last_seq += 1;
  }
}


static inline void
update_side(struct tcp_statetrackside_entry *side,
            struct seqs *seqs, const char *ippay)
{
  if (tcp_window(ippay) > side->max_window_unscaled)
  {
    side->max_window_unscaled = tcp_window(ippay);
    if (side->max_window_unscaled == 0)
    {
      side->max_window_unscaled = 1;
    }
  }

  if (seq_cmp(seqs->last_seq, side->sent) >= 0)
  {
    side->sent = seqs->last_seq + 1;
  }
  if (likely(tcp_ack(ippay)))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (seq_cmp(ack, side->acked) >= 0)
    {
      side->acked = ack;
    }
    if (seq_cmp(ack + (((uint32_t)window) << side->wscale), side->max) >= 0)
    {
      side->max = ack + (((uint32_t)window) << side->wscale);
    }
  }
}

struct synproxy_hash_entry *synproxy_hash_put(
  struct worker_local *local,
  int version,
  const void *local_ip,
  uint16_t local_port,
  const void *remote_ip,
  uint16_t remote_port,
  uint8_t was_synproxied,
  uint64_t time64)
{
  struct synproxy_hash_entry *e;
  struct synproxy_hash_ctx ctx;
  ctx.locked = 1;
  if (synproxy_hash_get(local, version, local_ip, local_port, remote_ip, remote_port, &ctx))
  {
    return NULL;
  }
  e = malloc(sizeof(*e));
  if (e == NULL)
  {
    return NULL;
  }
  memset(e, 0, sizeof(*e));
  e->version = version;
  memcpy(&e->local_ip, local_ip, (version == 4) ? 4 : 16);
  memcpy(&e->remote_ip, remote_ip, (version == 4) ? 4 : 16);
  e->local_port = local_port;
  e->remote_port = remote_port;
  e->was_synproxied = was_synproxied;
  e->timer.time64 = time64 +
    local->synproxy->conf->timeouts.connected*1000ULL*1000ULL;
  e->timer.fn = synproxy_expiry_fn;
  e->timer.userdata = local;
  worker_local_wrlock(local);
  timer_linkheap_add(&local->timers, &e->timer);
  hash_table_add_nogrow_already_bucket_locked(
    &local->hash, &e->node, synproxy_hash(e));
  if (was_synproxied)
  {
    local->synproxied_connections++;
  }
  else
  {
    local->direct_connections++;
  }
  worker_local_wrunlock(local);
  return e;
}


uint32_t synproxy_hash_fn(struct hash_list_node *node, void *userdata)
{
  return synproxy_hash(CONTAINER_OF(node, struct synproxy_hash_entry, node));
}

static void delete_closing_already_bucket_locked(
  struct synproxy *synproxy, struct worker_local *local,
  struct synproxy_hash_entry *entry)
{
  int ok = 0;
  if (entry->flag_state == FLAG_STATE_RESETED ||
      entry->flag_state == FLAG_STATE_TIME_WAIT ||
      ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
       (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
  {
    ok = 1;
  }
  if (!ok)
  {
    abort();
  }
  log_log(LOG_LEVEL_NOTICE, "SYNPROXY",
          "deleting closing connection to make room for new");
  timer_linkheap_remove(&local->timers, &entry->timer);
  hash_table_delete_already_bucket_locked(&local->hash, &entry->node);
  worker_local_wrlock(local);
  if (entry->was_synproxied)
  {
    local->synproxied_connections--;
  }
  else
  {
    local->direct_connections--;
  }
  if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    // Ok, this should never happen but let's use belts and suspenders!
    timer_linkheap_remove(&local->timers, &entry->syn_timer);
  }
  worker_local_wrunlock(local);
  free(entry);
  entry = NULL;
}


// Caller must hold worker_local mutex lock
static void send_synack(
  void *orig, struct worker_local *local, struct synproxy *synproxy,
  struct port *port, struct ll_alloc_st *st, uint64_t time64)
{
  char synack[14+40+20+12+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  uint32_t syn_cookie;
  struct tcp_information tcpinfo;
  struct sack_hash_data ipentry, ipportentry;
  uint16_t own_mss;
  uint8_t own_sack;
  uint32_t ts;
  const void *local_ip, *remote_ip;
  uint16_t local_port, remote_port;
  uint8_t own_wscale;
  struct threetuplepayload threetuplepayload;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = ((version == 4) ? (sizeof(synack) - 20) : sizeof(synack));
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);
  if (!tcpinfo.options_valid)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "options in TCP SYN invalid");
    return;
  }
  if (version == 4)
  {
    syn_cookie = form_cookie(
      &local->info, synproxy, ip_dst(origip), ip_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale, tcpinfo.sack_permitted,
      tcp_seq_number(origtcp));
    ts = form_timestamp(
      &local->info, synproxy, ip_dst(origip), ip_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale);
  }
  else
  {
    syn_cookie = form_cookie6(
      &local->info, synproxy, ipv6_dst(origip), ipv6_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale, tcpinfo.sack_permitted,
      tcp_seq_number(origtcp));
    ts = form_timestamp6(
      &local->info, synproxy, ipv6_dst(origip), ipv6_src(origip),
      tcp_dst_port(origtcp), tcp_src_port(origtcp),
      tcpinfo.mss, tcpinfo.wscale);
  }

  if (   synproxy->conf->mssmode == HASHMODE_COMMANDED
      || synproxy->conf->sackmode == HASHMODE_COMMANDED
      || synproxy->conf->wscalemode == HASHMODE_COMMANDED)
  {
    if (version == 4)
    {
      if (threetuplectx_find(&synproxy->threetuplectx, ip_dst(origip), tcp_dst_port(origtcp), 6, &threetuplepayload) != 0)
      {
        threetuplepayload.sack_supported = synproxy->conf->own_sack;
        threetuplepayload.mss = synproxy->conf->own_mss;
        threetuplepayload.wscaleshift = synproxy->conf->own_wscale;
      }
    }
    else
    {
      if (threetuplectx_find6(&synproxy->threetuplectx, ipv6_dst(origip), tcp_dst_port(origtcp), 6, &threetuplepayload) != 0)
      {
        threetuplepayload.sack_supported = synproxy->conf->own_sack;
        threetuplepayload.mss = synproxy->conf->own_mss;
        threetuplepayload.wscaleshift = synproxy->conf->own_wscale;
      }
    }
  }
  if (   synproxy->conf->mssmode == HASHMODE_HASHIPPORT
      || synproxy->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    if (version == 4)
    {
      if (sack_ip_port_hash_get4(&synproxy->autolearn, ip_dst(origip), tcp_dst_port(origtcp), &ipportentry) == 0)
      {
        ipportentry.sack_supported = synproxy->conf->own_sack;
        ipportentry.mss = synproxy->conf->own_mss;
      }
    }
    else
    {
      if (sack_ip_port_hash_get6(&synproxy->autolearn, ipv6_dst(origip), tcp_dst_port(origtcp), &ipportentry) == 0)
      {
        ipportentry.sack_supported = synproxy->conf->own_sack;
        ipportentry.mss = synproxy->conf->own_mss;
      }
    }
  }
  if (   synproxy->conf->mssmode == HASHMODE_HASHIP
      || synproxy->conf->sackmode == HASHMODE_HASHIP)
  {
    if (version == 4)
    {
      if (sack_ip_port_hash_get4(&synproxy->autolearn, ip_dst(origip), 0, &ipentry) == 0)
      {
        ipentry.sack_supported = synproxy->conf->own_sack;
        ipentry.mss = synproxy->conf->own_mss;
      }
    }
    else
    {
      if (sack_ip_port_hash_get6(&synproxy->autolearn, ipv6_dst(origip), 0, &ipentry) == 0)
      {
        ipentry.sack_supported = synproxy->conf->own_sack;
        ipentry.mss = synproxy->conf->own_mss;
      }
    }
  }
  if (synproxy->conf->mssmode == HASHMODE_HASHIPPORT)
  {
    own_mss = ipportentry.mss;
  }
  else if (synproxy->conf->mssmode == HASHMODE_HASHIP)
  {
    own_mss = ipentry.mss;
  }
  else if (synproxy->conf->mssmode == HASHMODE_COMMANDED)
  {
    own_mss = threetuplepayload.mss;
  }
  else
  {
    own_mss = synproxy->conf->own_mss;
  }
  if (synproxy->conf->sackmode == HASHMODE_HASHIPPORT)
  {
    own_sack = ipportentry.sack_supported;
  }
  else if (synproxy->conf->sackmode == HASHMODE_HASHIP)
  {
    own_sack = ipentry.sack_supported;
  }
  else if (synproxy->conf->sackmode == HASHMODE_COMMANDED)
  {
    own_sack = threetuplepayload.sack_supported;
  }
  else
  {
    own_sack = synproxy->conf->own_sack;
  }
  if (synproxy->conf->wscalemode == HASHMODE_COMMANDED)
  {
    own_wscale = threetuplepayload.wscaleshift;
  }
  else
  {
    own_wscale = synproxy->conf->own_wscale;
  }

  local_ip = ip46_dst(origip);
  remote_ip = ip46_src(origip);
  local_port = tcp_dst_port(origtcp);
  remote_port = tcp_src_port(origtcp);

  memcpy(ether_src(synack), ether_dst(orig), 6);
  memcpy(ether_dst(synack), ether_src(orig), 6);
  ether_set_type(synack, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(synack);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, gen_flowlabel(ip46_dst(origip), tcp_dst_port(origtcp), ip46_src(origip), tcp_src_port(origtcp)));
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(synack) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_syn_on(tcp);
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(synack) - 14 - 40);
  tcp_set_seq_number(tcp, syn_cookie);
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp) + 1);
  tcp_set_window(tcp, 0);
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = own_wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], own_mss);
  if (own_sack)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (tcpinfo.options_valid && tcpinfo.ts_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16], ts); // ts
    hdr_set32n(&tcpopts[20], tcpinfo.ts); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp46_set_cksum_calc(ip);
  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, synack, sz);
  port->portfunc(pktstruct, port->userdata);

  if (synproxy->conf->halfopen_cache_max)
  {
    struct synproxy_hash_entry *e;
    struct synproxy_hash_entry *e2;
    struct synproxy_hash_ctx ctx;
    ctx.locked = 0;
    e2 = synproxy_hash_get(local, version,
                           local_ip, local_port, remote_ip, remote_port,
                           &ctx);
    if (e2)
    {
      if (e2->flag_state == FLAG_STATE_RESETED ||
          e2->flag_state == FLAG_STATE_TIME_WAIT ||
          ((e2->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (e2->flag_state & FLAG_STATE_DOWNLINK_FIN)))
      {
        delete_closing_already_bucket_locked(synproxy, local, e2);
        e2 = NULL;
      }
      else
      {
        synproxy_hash_unlock(local, &ctx);
        return; // duplicate SYN
      }
    }
    worker_local_wrlock(local);
    if (local->half_open_connections >= synproxy->conf->halfopen_cache_max)
    {
      struct linked_list_node *node = local->half_open_list.node.next;
      uint32_t hashval;
      e = CONTAINER_OF(
            node, struct synproxy_hash_entry,
            state_data.downlink_half_open.listnode);
      hashval = synproxy_hash(e);
      linked_list_delete(&e->state_data.downlink_half_open.listnode);
      timer_linkheap_remove(&local->timers, &e->timer);
      if (e->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
      {
        timer_linkheap_remove(&local->timers, &e->syn_timer);
      }
      if (ctx.hashval == hashval)
      {
        hash_table_delete_already_bucket_locked(&local->hash, &e->node);
      }
      else
      {
        // Prevent lock order reversal
        worker_local_wrunlock(local);
        hash_table_delete(&local->hash, &e->node, synproxy_hash(e));
        worker_local_wrlock(local);
      }
    }
    else
    {
      local->half_open_connections++;
      local->synproxied_connections++;
      e = malloc(sizeof(*e));
      if (e == NULL)
      {
        worker_local_wrunlock(local);
        synproxy_hash_unlock(local, &ctx);
        log_log(LOG_LEVEL_ERR, "WORKER", "out of memory");
        return;
      }
    }
    memset(e, 0, sizeof(*e));
    e->version = version;
    memcpy(&e->local_ip, local_ip, (version == 6) ? 16 : 4);
    memcpy(&e->remote_ip, remote_ip, (version == 6) ? 16 : 4);
    e->local_port = local_port;
    e->remote_port = remote_port;
    e->was_synproxied = 1;
    e->timer.time64 = time64 +
      synproxy->conf->timeouts.dl_half_open*1000ULL*1000ULL;
    e->timer.fn = synproxy_expiry_fn;
    e->timer.userdata = local;
    timer_linkheap_add(&local->timers, &e->timer);
    hash_table_add_nogrow(&local->hash, &e->node, synproxy_hash(e));
    linked_list_add_tail(
      &e->state_data.downlink_half_open.listnode, &local->half_open_list);
    e->flag_state = FLAG_STATE_DOWNLINK_HALF_OPEN;
    e->state_data.downlink_half_open.wscale = tcpinfo.wscale;
    e->state_data.downlink_half_open.mss = tcpinfo.mss;
    e->state_data.downlink_half_open.sack_permitted = tcpinfo.sack_permitted;
    e->state_data.downlink_half_open.remote_isn = tcp_seq_number(origtcp);
    e->state_data.downlink_half_open.local_isn = syn_cookie;
    if (e->version == 6)
    {
      e->ulflowlabel = gen_flowlabel_entry(e);
    }

    worker_local_wrunlock(local);
    synproxy_hash_unlock(local, &ctx);
  }
}

static void send_or_resend_syn(
  struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct synproxy_hash_entry *entry)
{
  char syn[14+20+40+12+12] = {0};
  void *ip;
  void *tcp;
  unsigned char *tcpopts;
  struct packet *pktstruct;
  int version;
  size_t sz;

  version = entry->version;
  sz = ((version == 4) ? (sizeof(syn) - 20) : sizeof(syn));

  memcpy(ether_src(syn), entry->state_data.downlink_syn_sent.syn_src_ether, 6);
  memcpy(ether_dst(syn), entry->state_data.downlink_syn_sent.syn_dst_ether, 6);
  ether_set_type(syn, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(syn);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->dlflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(syn) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, &entry->state_data.downlink_syn_sent.syn_src_ip);
  ip46_set_dst(ip, &entry->state_data.downlink_syn_sent.syn_dst_ip);
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, entry->state_data.downlink_syn_sent.syn_src_port);
  tcp_set_dst_port(tcp, entry->state_data.downlink_syn_sent.syn_dst_port);
  tcp_set_syn_on(tcp);
  tcp_set_data_offset(tcp, sizeof(syn) - 14 - 40);
  tcp_set_seq_number(tcp, entry->state_data.downlink_syn_sent.remote_isn);
  tcp_set_ack_number(tcp, 0);
  tcp_set_window(tcp, entry->state_data.downlink_syn_sent.window);
  tcpopts = &((unsigned char*)tcp)[20];
  // WS, kind 3 len 3
  // NOP, kind 1 len 1
  // MSS, kind 2 len 4
  // SACK permitted, kind 4 len 2
  // endlist, kind 0 len 1
  // pad, kind 0 len 1
  tcpopts[0] = 3;
  tcpopts[1] = 3;
  tcpopts[2] = entry->statetrack.wan.wscale;
  tcpopts[3] = 1;
  tcpopts[4] = 2;
  tcpopts[5] = 4;
  hdr_set16n(&tcpopts[6], entry->state_data.downlink_syn_sent.mss);
  if (entry->state_data.downlink_syn_sent.sack_permitted)
  {
    tcpopts[8] = 4;
    tcpopts[9] = 2;
    if (entry->state_data.downlink_syn_sent.timestamp_present)
    {
      tcpopts[10] = 1;
      tcpopts[11] = 1;
    }
    else
    {
      tcpopts[10] = 0;
      tcpopts[11] = 0;
    }
  }
  else if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[8] = 1;
    tcpopts[9] = 1;
    tcpopts[10] = 1;
    tcpopts[11] = 1;
  }
  else
  {
    tcpopts[8] = 0;
    tcpopts[9] = 0;
    tcpopts[10] = 0;
    tcpopts[11] = 0;
  }
  if (entry->state_data.downlink_syn_sent.timestamp_present)
  {
    tcpopts[12] = 1;
    tcpopts[13] = 1;
    tcpopts[14] = 8;
    tcpopts[15] = 10;
    hdr_set32n(&tcpopts[16],
      entry->state_data.downlink_syn_sent.remote_timestamp);
    hdr_set32n(&tcpopts[20], 0); // tsecho
  }
  else
  {
    memset(&tcpopts[12], 0, 12);
  }
  tcp46_set_cksum_calc(ip);
  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, syn, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void resend_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct synproxy_hash_entry *entry,
  uint64_t time64)
{
  void *origip;
  void *origtcp;
  struct seqs seqs;

  if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    abort();
  }

  origip = ether_payload(orig);
  origtcp = ip46_payload(origip);

  calc_seqs(&seqs, origip, origtcp, 0);
  update_side(&entry->statetrack.wan, &seqs, origtcp);

  entry->timer.time64 = time64 +
    local->synproxy->conf->timeouts.dl_syn_sent*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);

  // Update state_date packet info cache
  memcpy(entry->state_data.downlink_syn_sent.syn_src_ether, ether_src(orig), 6);
  memcpy(entry->state_data.downlink_syn_sent.syn_dst_ether, ether_dst(orig), 6);
  memcpy(&entry->state_data.downlink_syn_sent.syn_src_ip, ip46_src(origip), (entry->version == 4) ? 4 : 16);
  memcpy(&entry->state_data.downlink_syn_sent.syn_dst_ip, ip46_dst(origip), (entry->version == 4) ? 4 : 16);
  entry->state_data.downlink_syn_sent.syn_src_port = tcp_src_port(origtcp);
  entry->state_data.downlink_syn_sent.syn_dst_port = tcp_dst_port(origtcp);
  entry->state_data.downlink_syn_sent.window = tcp_window(origtcp);

  send_or_resend_syn(local, port, st, entry);
}

static void timed_resend_syn(
  struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  struct synproxy_hash_entry *entry,
  uint64_t time64)
{
  if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    abort();
  }
  send_or_resend_syn(local, port, st, entry);
}

// caller must not have worker_local lock
// caller must not have bucket lock
static void synproxy_resend_syn_fn(
  struct timer_link *timer, struct timer_linkheap *heap, void *ud, void *vtd)
{
  struct worker_local *local = ud;
  struct timer_thread_data *td = vtd;
  struct synproxy_hash_entry *e;

  e = CONTAINER_OF(timer, struct synproxy_hash_entry, syn_timer);

  if (e->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    log_log(LOG_LEVEL_EMERG, "WORKER",
      "DETECTED TIMER synproxy_resend_syn_fn IN STATE %d", (int)e->flag_state);
    return;
  }

  log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "resending SYN in a timed manner");

  // FIXME take bucket lock for timed_resend_syn??? take wrker lock too?
  timed_resend_syn(local, td->port, td->st, e, gettime64());

  e->syn_timer.time64 += local->synproxy->conf->timeouts.syn_retx*1000ULL*1000ULL;
  worker_local_wrlock(local);
  timer_linkheap_add(&local->timers, &e->syn_timer);
  worker_local_wrunlock(local);
}

static void send_syn(
  void *orig, struct worker_local *local, struct port *port,
  struct ll_alloc_st *st,
  uint16_t mss, uint8_t wscale, uint8_t sack_permitted,
  struct synproxy_hash_entry *entry,
  uint64_t time64, int was_keepalive)
{
  void *origip;
  void *origtcp;
  struct tcp_information info;
  int version;

  origip = ether_payload(orig);
  version = ip_version(origip);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &info);

  if (entry == NULL)
  {
    entry = synproxy_hash_put(
      local, version, ip46_dst(origip), tcp_dst_port(origtcp),
      ip46_src(origip), tcp_src_port(origtcp),
      1, time64);
    if (entry->version == 6)
    {
      entry->ulflowlabel = gen_flowlabel_entry(entry);
    }
    if (entry == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKER", "not enough memory or already existing");
      return;
    }
  }
  if (version == 6)
  {
    entry->dlflowlabel = ipv6_flow_label(origip);
  }

  entry->state_data.downlink_syn_sent.mss = mss;
  entry->state_data.downlink_syn_sent.sack_permitted = sack_permitted;
  entry->state_data.downlink_syn_sent.timestamp_present = info.ts_present;
  if (info.ts_present)
  {
    entry->state_data.downlink_syn_sent.local_timestamp = info.tsecho;
    entry->state_data.downlink_syn_sent.remote_timestamp = info.ts;
  }

  entry->statetrack.wan.wscale = wscale;
  entry->statetrack.wan.sent = tcp_seq_number(origtcp) + (!!was_keepalive);
  entry->statetrack.wan.acked = tcp_ack_number(origtcp);
  entry->statetrack.wan.max =
    tcp_ack_number(origtcp) + (((uint32_t)tcp_window(origtcp)) << entry->statetrack.wan.wscale);

  entry->statetrack.wan.max_window_unscaled = tcp_window(origtcp);
  if (entry->statetrack.wan.max_window_unscaled == 0)
  {
    entry->statetrack.wan.max_window_unscaled = 1;
  }
  entry->state_data.downlink_syn_sent.local_isn = tcp_ack_number(origtcp) - 1;
  entry->state_data.downlink_syn_sent.remote_isn = tcp_seq_number(origtcp) - 1 + (!!was_keepalive);
  entry->flag_state = FLAG_STATE_DOWNLINK_SYN_SENT;
  entry->timer.time64 = time64 +
    local->synproxy->conf->timeouts.dl_syn_sent*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);

  worker_local_wrlock(local); // FIXME ?????? is this already taken?
  entry->syn_timer.time64 = time64 + 
    local->synproxy->conf->timeouts.syn_retx*1000ULL*1000ULL;
  entry->syn_timer.fn = synproxy_resend_syn_fn;
  entry->syn_timer.userdata = local;
  timer_linkheap_add(&local->timers, &entry->syn_timer); // FIXME needs worker local lock???
  worker_local_wrunlock(local);

  // Update state_date packet info cache
  memcpy(entry->state_data.downlink_syn_sent.syn_src_ether, ether_src(orig), 6);
  memcpy(entry->state_data.downlink_syn_sent.syn_dst_ether, ether_dst(orig), 6);
  memcpy(&entry->state_data.downlink_syn_sent.syn_src_ip, ip46_src(origip), (entry->version == 4) ? 4 : 16);
  memcpy(&entry->state_data.downlink_syn_sent.syn_dst_ip, ip46_dst(origip), (entry->version == 4) ? 4 : 16);
  entry->state_data.downlink_syn_sent.syn_src_port = tcp_src_port(origtcp);
  entry->state_data.downlink_syn_sent.syn_dst_port = tcp_dst_port(origtcp);
  entry->state_data.downlink_syn_sent.window = tcp_window(origtcp);

  send_or_resend_syn(local, port, st, entry);
}

static void send_ack_only(
  void *orig, struct synproxy_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char ack[14+40+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = ((version == 4) ? (sizeof(ack) - 20) : sizeof(ack));
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  memcpy(ether_src(ack), ether_dst(orig), 6);
  memcpy(ether_dst(ack), ether_src(orig), 6);
  ether_set_type(ack, version == 4 ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(ack);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->dlflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(ack) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_dst(origip));
  ip46_set_dst(ip, ip46_src(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_dst_port(origtcp));
  tcp_set_dst_port(tcp, tcp_src_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(ack) - 14 - 40);
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp));
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1);
  tcp_set_window(tcp, entry->statetrack.wan.max_window_unscaled);

  tcpopts = &((unsigned char*)tcp)[20];

  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.tsecho);
    hdr_set32n(&tcpopts[8], tcpinfo.ts);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }

  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_DOWNLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, ack, sz);
  port->portfunc(pktstruct, port->userdata);
}

static void send_ack_and_window_update(
  void *orig, struct synproxy_hash_entry *entry, struct port *port,
  struct ll_alloc_st *st)
{
  char windowupdate[14+40+20+12] = {0};
  void *ip, *origip;
  void *tcp, *origtcp;
  struct packet *pktstruct;
  struct tcp_information tcpinfo;
  unsigned char *tcpopts;
  int version;
  size_t sz;

  origip = ether_payload(orig);
  version = ip_version(origip);
  sz = (version == 4) ? (sizeof(windowupdate) - 20) : sizeof(windowupdate);
  origtcp = ip46_payload(origip);
  tcp_parse_options(origtcp, &tcpinfo);

  send_ack_only(orig, entry, port, st); // XXX send_ack_only reparses opts

  memcpy(ether_src(windowupdate), ether_src(orig), 6);
  memcpy(ether_dst(windowupdate), ether_dst(orig), 6);
  ether_set_type(windowupdate, (version == 4) ? ETHER_TYPE_IP : ETHER_TYPE_IPV6);
  ip = ether_payload(windowupdate);
  ip_set_version(ip, version);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
  ip46_set_min_hdr_len(ip);
  ip46_set_payload_len(ip, sizeof(windowupdate) - 14 - 40);
  ip46_set_dont_frag(ip, 1);
  ip46_set_id(ip, 0); // XXX
  ip46_set_ttl(ip, 64);
  ip46_set_proto(ip, 6);
  ip46_set_src(ip, ip46_src(origip));
  ip46_set_dst(ip, ip46_dst(origip));
  ip46_set_hdr_cksum_calc(ip);
  tcp = ip46_payload(ip);
  tcp_set_src_port(tcp, tcp_src_port(origtcp));
  tcp_set_dst_port(tcp, tcp_dst_port(origtcp));
  tcp_set_ack_on(tcp);
  tcp_set_data_offset(tcp, sizeof(windowupdate) - 14 - 40);
#if 0
  tcp_set_seq_number(tcp, tcp_ack_number(origtcp)); // FIXME looks suspicious
  tcp_set_ack_number(tcp, tcp_seq_number(origtcp)+1); // FIXME the same
#endif
  tcp_set_seq_number(tcp, tcp_seq_number(origtcp)+1+entry->seqoffset);
  tcp_set_ack_number(tcp, tcp_ack_number(origtcp));
  if (entry->wscalediff >= 0)
  {
    uint16_t win16 = tcp_window(origtcp) >> entry->wscalediff;
    if (win16 == 0 && tcp_window(origtcp) != 0)
    {
      win16 = 1;
    }
    tcp_set_window(tcp, win16);
  }
  else
  {
    uint64_t win64 = (uint64_t)(tcp_window(origtcp)<<(-entry->wscalediff));
    if (win64 > 0xFFFF)
    {
      win64 = 0xFFFF;
    }
    tcp_set_window(tcp, win64);
  }
  tcpopts = &((unsigned char*)tcp)[20];
  if (tcpinfo.options_valid && tcpinfo.ts_present)
  {
    tcpopts[0] = 1;
    tcpopts[1] = 1;
    tcpopts[2] = 8;
    tcpopts[3] = 10;
    hdr_set32n(&tcpopts[4], tcpinfo.ts+entry->tsoffset);
    hdr_set32n(&tcpopts[8], tcpinfo.tsecho);
  }
  else
  {
    memset(&tcpopts[0], 0, 12);
  }
  tcp46_set_cksum_calc(ip);

  pktstruct = ll_alloc_st(st, packet_size(sz));
  pktstruct->data = packet_calc_data(pktstruct);
  pktstruct->direction = PACKET_DIRECTION_UPLINK;
  pktstruct->sz = sz;
  memcpy(pktstruct->data, windowupdate, sz);
  port->portfunc(pktstruct, port->userdata);
}

static int
check_downlink_finack(struct synproxy_hash_entry *entry, void *ip, void *ippay)
{
  int todelete = 0;
  uint32_t fin = entry->state_data.established.upfin;
  if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      return -1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      return -1;
    }
    entry->flag_state |= FLAG_STATE_UPLINK_FIN_ACK;
    if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN_ACK)
    {
      todelete = 1;
    }
  }
  return todelete;
}

static int
handle_downlink_fin(struct synproxy_hash_entry *entry, void *ip,
                    struct seqs *seqs, int version)
{
  if (version == 4 && ip_more_frags(ip)) // FIXME for IPv6 also
  {
    log_log(LOG_LEVEL_WARNING, "WORKERDOWNLINK", "FIN with more frags");
  }
  if (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)
  {
    if (entry->state_data.established.downfin != seqs->last_seq)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "FIN seq changed");
      return 1;
    }
  }
  entry->state_data.established.downfin = seqs->last_seq;
  entry->flag_state |= FLAG_STATE_DOWNLINK_FIN;
  return 0;
}

static inline void update_tcp_timeout(struct synproxy_hash_entry *entry,
                                      struct worker_local *local,
                                      uint64_t time64)
{
  uint64_t next64;
  if (entry->flag_state == FLAG_STATE_RESETED)
  {
    next64 = time64 + local->synproxy->conf->timeouts.reseted*1000ULL*1000ULL;
  }
  else if ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + local->synproxy->conf->timeouts.both_fin*1000ULL*1000ULL;
  }
  else if (entry->flag_state & (FLAG_STATE_UPLINK_FIN|FLAG_STATE_DOWNLINK_FIN))
  {
    next64 = time64 + local->synproxy->conf->timeouts.one_fin*1000ULL*1000ULL;
  }
  else
  {
    next64 = time64 + local->synproxy->conf->timeouts.connected*1000ULL*1000ULL;
  }
  if (llabs(((int64_t)next64) - ((int64_t)entry->timer.time64)) >= 1000*1000)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = next64;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
}

static int
handle_downlink_rst(void *ip, void *ippay,
                    struct synproxy_hash_entry *entry,
                    struct worker_local *local,
                    struct synproxy *synproxy,
                    struct port *port,
                    struct ll_alloc_st *st,
                    int version,
                    struct packet *pkt,
                    uint64_t time64)
{
  uint32_t tcp_len;
  tcp_len = (uint32_t)(ip46_total_len(ip) - ip46_hdr_len(ip));
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
    return 1;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
    return 1;
  }
  if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
  {
    if (!tcp_ack(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "R/RA in UPLINK_SYN_SENT");
      return 1;
    }
    if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "RA/RA in UL_SYN_SENT, bad seq");
      return 1;
    }
  }
  else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "dropping RST in DOWNLINK_SYN_SENT");
    return 1;
  }
  else
  {
    uint32_t seq = tcp_seq_number(ippay);
    if (tcp_ack(ippay) && entry->flag_state == FLAG_STATE_RESETED)
    {
      // Don't spam the log in this common case
      return 1;
    }
    if (!rst_is_valid_downlink(seq, &entry->statetrack))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK",
              "RST has invalid SEQ number, %u/%u/%u",
              seq, entry->statetrack.wan.sent, entry->statetrack.lan.acked);
      return 1;
    }
  }
  if (tcp_ack(ippay))
  {
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
  }
  entry->flag_state = FLAG_STATE_RESETED;
  worker_local_wrlock(local);
  entry->timer.time64 = time64 +
    synproxy->conf->timeouts.reseted*1000ULL*1000ULL;
  if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    timer_linkheap_remove(&local->timers, &entry->syn_timer);
  }
  timer_linkheap_modify(&local->timers, &entry->timer);
  worker_local_wrunlock(local);
  //port->portfunc(pkt, port->userdata);
  return 0;
}

static void
handle_downlink_half_open(struct synproxy_hash_entry *entry,
                          struct worker_local *local, struct synproxy *synproxy,
                          struct port *port, struct ll_alloc_st *st,
                          void *ether, void *ip, void *ippay, int version,
                          uint64_t time64)
{
  if (tcp_rst(ippay))
  {
    /*
     * Ok, here we could verify that the RST is valid and drop the half-open
     * state. But it's extremely unlikely that someone opens a connection
     * with SYN and then to the SYN+ACK responds with RST. Also, the timeout
     * for downlink half-open connections is 64 seconds, and the timeout for
     * connections in the RST state is 45 seconds. So, the additional benefit
     * for moving the connection to RST state is minimal. Also, by maintaining
     * the connection in DOWNLINK_HALF_OPEN state, we can use the linked list
     * to remove old expired connections. In reseted connections, there is no
     * such list. So, the short summary is that moving the connection to the
     * RST state is not worth it.
     */
  }
  if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay))
  {
    uint32_t ack_num = tcp_ack_number(ippay);
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
      return;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
      return;
    }
    if (((uint32_t)(entry->state_data.downlink_half_open.local_isn + 1)) != ack_num)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP ACK number");
      return;
    }
    if (((uint32_t)(entry->state_data.downlink_half_open.remote_isn + 1)) != tcp_seq_number(ippay))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP SEQ number");
      return;
    }
    worker_local_wrlock(local);
    if (version == 4)
    {
      ip_increment_one(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit);
    }
    else
    {
      ipv6_increment_one(
        ipv6_src(ip), synproxy->conf->ratehash.network_prefix6, &local->ratelimit);
    }
    log_log(
      LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN, found");
    linked_list_delete(&entry->state_data.downlink_half_open.listnode);
    if (local->half_open_connections <= 0)
    {
      abort();
    }
    local->half_open_connections--;
    worker_local_wrunlock(local);
    // FIXME does send_syn require worker local lock?
    send_syn(
      ether, local, port, st,
      entry->state_data.downlink_half_open.mss,
      entry->state_data.downlink_half_open.wscale,
      entry->state_data.downlink_half_open.sack_permitted, entry, time64, 0);
    return;
  }
  log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry is HALF_OPEN");
  return;
}

static void
handle_ack_cookie(void *ether, void *ip, void *ippay, // RFE const
                  int version,
                  struct synproxy_hash_entry *entry,
                  struct worker_local *local,
                  struct synproxy *synproxy,
                  uint64_t time64,
                  char *packetbuf, size_t packetbufsiz,
                  char *statebuf, size_t statebufsiz,
                  struct port *port,
                  struct ll_alloc_st *st)
{
  uint32_t ack_num = tcp_ack_number(ippay);
  uint32_t other_seq = tcp_seq_number(ippay);
  uint16_t mss;
  uint16_t tsmss;
  uint8_t tswscale;
  uint8_t wscale, sack_permitted;
  int ok;
  int was_keepalive = 0;
  struct tcp_information tcpinfo;
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
    return;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
    return;
  }
  if (version == 4)
  {
    ok = verify_cookie(
      &local->info, synproxy, ip_dst(ip), ip_src(ip),
      tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
      &mss, &wscale, &sack_permitted, other_seq - 1);
    if (!ok)
    {
      other_seq++;
      ok = verify_cookie(
        &local->info, synproxy, ip_dst(ip), ip_src(ip),
        tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
        &mss, &wscale, &sack_permitted, other_seq - 1);
      if (ok)
      {
        synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
        log_log(
          LOG_LEVEL_NOTICE, "WORKERDOWNLINK",
          "SYN proxy detected keepalive packet opening connection: %s",
          packetbuf);
        was_keepalive = 1;
      }
    }
  }
  else
  {
    ok = verify_cookie6(
      &local->info, synproxy, ipv6_dst(ip), ipv6_src(ip),
      tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
      &mss, &wscale, &sack_permitted, other_seq - 1);
    if (!ok)
    {
      other_seq++;
      ok = verify_cookie6(
        &local->info, synproxy, ipv6_dst(ip), ipv6_src(ip),
        tcp_dst_port(ippay), tcp_src_port(ippay), ack_num - 1,
        &mss, &wscale, &sack_permitted, other_seq - 1);
      if (ok)
      {
        synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
        log_log(
          LOG_LEVEL_NOTICE, "WORKERDOWNLINK",
          "SYN proxy detected keepalive packet opening connection6: %s",
          packetbuf);
        was_keepalive = 1;
      }
    }
  }
  if (ok)
  {
    tcp_parse_options(ippay, &tcpinfo); // XXX send_syn reparses
    if (tcpinfo.options_valid && tcpinfo.ts_present)
    {
      if (version == 4)
      {
        if (verify_timestamp(
          &local->info, synproxy, ip_dst(ip), ip_src(ip),
          tcp_dst_port(ippay), tcp_src_port(ippay), tcpinfo.tsecho,
          &tsmss, &tswscale))
        {
          if (tsmss > mss)
          {
            mss = tsmss;
          }
          if (tswscale > wscale)
          {
            wscale = tswscale;
          }
        }
      }
      else
      {
        if (verify_timestamp6(
          &local->info, synproxy, ipv6_dst(ip), ipv6_src(ip),
          tcp_dst_port(ippay), tcp_src_port(ippay), tcpinfo.tsecho,
          &tsmss, &tswscale))
        {
          if (tsmss > mss)
          {
            mss = tsmss;
          }
          if (tswscale > wscale)
          {
            wscale = tswscale;
          }
        }
      }
    }
  }
  if (!ok)
  {
    if (entry != NULL)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(
        LOG_LEVEL_ERR, "WORKERDOWNLINK",
        "entry found, A/SAFR set, SYN cookie invalid, state: %s, packet: %s", statebuf, packetbuf);
    }
    else
    {
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(
        LOG_LEVEL_ERR, "WORKERDOWNLINK",
        "entry not found but A/SAFR set, SYN cookie invalid, packet: %s", packetbuf);
    }
    return;
  }
  worker_local_wrlock(local);
  if (version == 4)
  {
    ip_increment_one(
      ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit);
  }
  else
  {
    ipv6_increment_one(
      ipv6_src(ip), synproxy->conf->ratehash.network_prefix6, &local->ratelimit);
  }
  worker_local_wrunlock(local);
  synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
  log_log(
    LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "SYN proxy sending SYN, packet: %s",
    packetbuf);
  if (entry != NULL)
  {
    delete_closing_already_bucket_locked(synproxy, local, entry);
    entry = NULL;
  }
  // FIXME does send_syn require worker local lock?
  send_syn(ether, local, port, st, mss, wscale, sack_permitted, NULL, time64, was_keepalive);
  return;
}

static int
handle_downlink_syn(struct packet *pkt, void *ether, void *ip, void *ippay,
                    struct worker_local *local, struct synproxy *synproxy,
                    struct port *port, struct ll_alloc_st *st,
                    int version, uint64_t time64)
{
  struct synproxy_hash_entry *entry;
  //uint32_t ip_len = ip46_total_len(ip);
  //uint32_t tcp_len = ip_len - ip46_hdr_len(ip);
  uint16_t lan_port = tcp_dst_port(ippay);
  uint16_t remote_port = tcp_src_port(ippay);
  const void *lan_ip = ip46_dst(ip);
  const void *remote_ip = ip46_src(ip);
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid IP hdr cksum");
    return 1;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "invalid TCP hdr cksum");
    return 1;
  }
  if (tcp_fin(ippay) || tcp_rst(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SYN packet contains FIN or RST");
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    worker_local_wrlock(local);
    if (version == 4)
    {
      if (!ip_permitted(
        ip_src(ip), synproxy->conf->ratehash.network_prefix, &local->ratelimit))
      {
        worker_local_wrunlock(local);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP ratelimited");
        return 1;
      }
    }
    else
    {
      if (!ipv6_permitted(
        ipv6_src(ip), synproxy->conf->ratehash.network_prefix6, &local->ratelimit))
      {
        worker_local_wrunlock(local);
        log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 ratelimited");
        return 1;
      }
    }
    send_synack(ether, local, synproxy, port, st, time64);
    worker_local_wrunlock(local);
    return 1;
  }
  else
  {
    struct tcp_information tcpinfo;
    struct synproxy_hash_ctx ctx;
    ctx.locked = 0;
    entry = synproxy_hash_get(
      local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (entry == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA but entry nonexistent");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD &&
        entry->state_data.uplink_syn_rcvd.isn == tcp_seq_number(ippay))
    {
      // retransmit of SYN+ACK
      if (synproxy->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        tcp_parse_options(ippay, &tcpinfo);
        if (tcpinfo.options_valid)
        {
          mss = tcpinfo.mss;
          if (mss > synproxy->conf->mss_clamp)
          {
            mss = synproxy->conf->mss_clamp;
          }
          if (tcpinfo.mssoff)
          {
            tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
          }
        }
      }
      synproxy_hash_unlock(local, &ctx);
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (entry->flag_state == FLAG_STATE_ESTABLISHED &&
        entry->statetrack.wan.sent-1 == tcp_seq_number(ippay))
    {
      // retransmit of SYN+ACK
      // FIXME should store the ISN for a longer duration of time...
      if (synproxy->conf->mss_clamp_enabled)
      {
        uint16_t mss;
        tcp_parse_options(ippay, &tcpinfo);
        if (tcpinfo.options_valid)
        {
          mss = tcpinfo.mss;
          if (mss > synproxy->conf->mss_clamp)
          {
            mss = synproxy->conf->mss_clamp;
          }
          if (tcpinfo.mssoff)
          {
            tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
          }
        }
      }
      synproxy_hash_unlock(local, &ctx);
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (entry->flag_state != FLAG_STATE_UPLINK_SYN_SENT)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, entry != UL_SYN_SENT");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_sent.isn + 1)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "SA/SA, invalid ACK num");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    tcp_parse_options(ippay, &tcpinfo);
    if (!tcpinfo.options_valid)
    {
      tcpinfo.wscale = 0;
      tcpinfo.mssoff = 0;
      tcpinfo.mss = 1460;
    }
    entry->statetrack.wan.wscale = tcpinfo.wscale;
    entry->statetrack.wan.max_window_unscaled = tcp_window(ippay);
    if (entry->statetrack.wan.max_window_unscaled == 0)
    {
      entry->statetrack.wan.max_window_unscaled = 1;
    }
    entry->state_data.uplink_syn_rcvd.isn = tcp_seq_number(ippay);
    entry->statetrack.wan.sent = tcp_seq_number(ippay) + 1;
    entry->statetrack.wan.acked = tcp_ack_number(ippay);
    entry->statetrack.wan.max =
      entry->statetrack.wan.acked + (((uint32_t)tcp_window(ippay)) << entry->statetrack.wan.wscale);
    entry->flag_state = FLAG_STATE_UPLINK_SYN_RCVD;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.ul_syn_rcvd*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    if (synproxy->conf->mss_clamp_enabled)
    {
      uint16_t mss;
      mss = tcpinfo.mss;
      if (mss > synproxy->conf->mss_clamp)
      {
        mss = synproxy->conf->mss_clamp;
      }
      if (tcpinfo.mssoff)
      {
        tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
      }
    }
    synproxy_hash_unlock(local, &ctx);
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
}

int downlink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  const void *remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  const void *lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct synproxy_hash_entry *entry;
  struct synproxy_hash_ctx ctx;
  int todelete = 0;
  struct sack_ts_headers hdrs;
  char statebuf[8192];
  char packetbuf[8192];
  int version;
  struct seqs seqs;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) != ETHER_TYPE_IP && ether_type(ether) != ETHER_TYPE_IPV6)
  {
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  version = ip_version(ip);
  if (version != 4 && version != 6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IP version mismatch");
    return 1;
  }
  if (version == 4)
  {
    ihl = ip_hdr_len(ip);
    if (ip_len < ihl)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP hdr 2");
      return 1;
    }
    if (ip_proto(ip) != 6)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (ip_frag_off(ip) >= 60)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    else if (ip_frag_off(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "fragment has partial header");
      return 1;
    }
    if (ip_len < ip_total_len(ip))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IP data");
      return 1;
    }
    lan_ip = ip_dst_ptr(ip);
    remote_ip = ip_src_ptr(ip);
    protocol = ip_proto(ip);
    ippay = ip_payload(ip);
  }
  else if (version == 6)
  {
    int is_frag = 0;
    uint16_t proto_off_from_frag = 0;
    if (ip_len < 40)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IPv6 hdr 1");
      return 1;
    }
    if (ip_len < (size_t)(ipv6_payload_len(ip) + 40))
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full IPv6 data");
      return 1;
    }
    protocol = 0;
    ippay = ipv6_proto_hdr_2(ip, &protocol, &is_frag, NULL, &proto_off_from_frag);
    if (ippay == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt without ext hdr chain");
      return 1;
    }
    if (is_frag && proto_off_from_frag + 60 > IPV6_FRAG_CUTOFF)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 proto hdr too deep in hdr chain");
      return 1;
    }
    if (protocol == 44 && ipv6_frag_off(ippay) < IPV6_FRAG_CUTOFF)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "IPv6 subsequent frag too low frag off");
      return 1;
    }
    if (protocol != 6)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    ihl = ((char*)ippay) - ((char*)ip);
    lan_ip = ipv6_dst(ip);
    remote_ip = ipv6_src(ip);
  }
  else
  {
    abort();
  }
  
  if (protocol == 6)
  {
    tcp_len = ip46_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_dst_port(ippay);
    remote_port = tcp_src_port(ippay);
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    int ret;
    ret = handle_downlink_syn(pkt, ether, ip, ippay,
                              local, synproxy,
                              port, st,
                              version, time64);
    return ret;
  }
  ctx.locked = 0;
  entry = synproxy_hash_get(
    local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry != NULL && entry->flag_state == FLAG_STATE_DOWNLINK_HALF_OPEN)
  {
    handle_downlink_half_open(entry, local, synproxy, port, st,
                              ether, ip, ippay, version, time64);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (entry == NULL || entry->flag_state == FLAG_STATE_RESETED ||
      entry->flag_state == FLAG_STATE_TIME_WAIT ||
      ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
       (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
  {
    /*
     * If entry is NULL, it can only be ACK of a SYN+ACK so we verify cookie
     * If entry is non-NULL, it can be ACK of FIN or ACK of SYN+ACK
     * In the latter case, we verify whether the SEQ/ACK numbers look fine.
     * If either SEQ or ACK number is invalid, it has to be ACK of SYN+ACK
     */
    calc_seqs(&seqs, ip, ippay, 0);
    if (tcp_ack(ippay) && !tcp_fin(ippay) && !tcp_rst(ippay) && !tcp_syn(ippay)
        && (entry == NULL ||
            (!seqs_valid_downlink(entry, &seqs, ether, ip, ippay, 0,
                                  NULL, 0, NULL, 0))))
    {
      handle_ack_cookie(ether, ip, ippay, version,
                        entry, local, synproxy, time64,
                        packetbuf, sizeof(packetbuf),
                        statebuf, sizeof(statebuf),
                        port, st);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry == NULL)
    {
      synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
      log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "entry not found, packet: %s", packetbuf);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }
  if (unlikely(tcp_rst(ippay)))
  {
    int ret;
    ret = handle_downlink_rst(ip, ippay, entry,
                              local, synproxy, port, st,
                              version, pkt, time64);
    synproxy_hash_unlock(local, &ctx);
    return ret;
  }
  if (   tcp_ack(ippay)
      && entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT
      && resend_request_is_valid(tcp_seq_number(ippay), entry->statetrack.wan.sent)
      && resend_request_is_valid(tcp_ack_number(ippay), entry->statetrack.wan.acked))
  {
    log_log(LOG_LEVEL_NOTICE, "WORKERDOWNLINK", "resending SYN");
    worker_local_wrlock(local);
    resend_syn(ether, local, port, st, entry, time64);
    worker_local_wrunlock(local);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!synproxy_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED)
  {
    synproxy_entry_to_str(statebuf, sizeof(statebuf), entry);
    synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "not CONNECTED/RESETED, dropping, state: %s, packet: %s", statebuf, packetbuf);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    synproxy_entry_to_str(statebuf, sizeof(statebuf), entry);
    synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERDOWNLINK", "no TCP ACK, dropping pkt, state: %s, packet: %s", statebuf, packetbuf);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }

  calc_seqs(&seqs, ip, ippay, 0);
  if (!seqs_valid_downlink(entry, &seqs, ether, ip, ippay, 1,
                           statebuf, sizeof(statebuf),
                           packetbuf, sizeof(packetbuf)))
  {
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }

  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (handle_downlink_fin(entry, ip, &seqs, version))
    {
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }
  if (unlikely(entry->flag_state & FLAG_STATE_UPLINK_FIN))
  {
    todelete = check_downlink_finack(entry, ip, ippay);
    if (todelete < 0)
    {
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }

  update_side(&entry->statetrack.wan, &seqs, ippay);

  update_tcp_timeout(entry, local, time64);

  tcp_find_sack_ts_headers(ippay, &hdrs);
  if (tcp_ack(ippay))
  {
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, tcp_ack_number(ippay)-entry->seqoffset);
    if (hdrs.sackoff)
    {
      if (   !entry->lan_sack_was_supported
          && synproxy->conf->sackconflict == SACKCONFLICT_REMOVE)
      {
        char *cippay = ippay;
        tcp_disable_sack_cksum_update(
          ippay, &cippay[hdrs.sackoff], hdrs.sacklen, !(hdrs.sackoff%2));
      }
      else
      {
        tcp_adjust_sack_cksum_update_2(
          ippay, &hdrs, -entry->seqoffset);
      }
    }
  }
  tcp_adjust_tsecho_cksum_update(ippay, &hdrs, -entry->tsoffset);
  //port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.time_wait*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  synproxy_hash_unlock(local, &ctx);
  return 0;
}

static int
check_uplink_finack(struct synproxy_hash_entry *entry, void *ip, void *ippay)
{
  int todelete = 0;
  uint32_t fin = entry->state_data.established.downfin;
  if (tcp_ack(ippay) && tcp_ack_number(ippay) == fin + 1)
  {
    if (ip46_hdr_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
      return -1;
    }
    if (tcp46_cksum_calc(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
      return -1;
    }
    entry->flag_state |= FLAG_STATE_DOWNLINK_FIN_ACK;
    if (entry->flag_state & FLAG_STATE_UPLINK_FIN_ACK)
    {
      todelete = 1;
    }
  }
  return todelete;
}

static int
handle_uplink_fin(struct synproxy_hash_entry *entry, void *ip,
                    struct seqs *seqs, int version)
{
  if (version == 4 && ip_more_frags(ip)) // FIXME for IPv6 also
  {
    log_log(LOG_LEVEL_WARNING, "WORKERUPLINK", "FIN with more frags");
  }
  if (entry->flag_state & FLAG_STATE_UPLINK_FIN)
  {
    if (entry->state_data.established.upfin != seqs->last_seq)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "FIN seq changed");
      return 1;
    }
  }
  entry->state_data.established.upfin = seqs->last_seq;
  entry->flag_state |= FLAG_STATE_UPLINK_FIN;
  return 0;
}

static int
handle_uplink_syn(struct packet *pkt, void *ether, void *ip, void *ippay,
                  struct worker_local *local, struct synproxy *synproxy,
                  struct port *port, struct ll_alloc_st *st,
                  int version, uint64_t time64,
                  char *packetbuf, size_t packetbufsiz,
                  char *statebuf, size_t statebufsiz)
{
  struct synproxy_hash_entry *entry;
  uint16_t lan_port = tcp_src_port(ippay);
  uint16_t remote_port = tcp_dst_port(ippay);
  const void *lan_ip = ip46_src(ip);
  const void *remote_ip = ip46_dst(ip);
  struct synproxy_hash_ctx ctx;
  //uint32_t ip_len = ip46_total_len(ip);
  //uint32_t tcp_len = ip46_total_len(ip) - ip46_hdr_len(ip);
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
    return 1;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
    return 1;
  }
  if (tcp_fin(ippay) || tcp_rst(ippay))
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SYN packet contains FIN or RST");
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    struct tcp_information tcpinfo;
    ctx.locked = 0;
    entry = synproxy_hash_get(
      local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (entry != NULL && entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT &&
        entry->state_data.uplink_syn_sent.isn == tcp_seq_number(ippay))
    {
      // retransmit of SYN
      synproxy_hash_unlock(local, &ctx);
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (entry != NULL)
    {
      if (entry->flag_state == FLAG_STATE_RESETED ||
          entry->flag_state == FLAG_STATE_TIME_WAIT ||
          ((entry->flag_state & FLAG_STATE_UPLINK_FIN) &&
           (entry->flag_state & FLAG_STATE_DOWNLINK_FIN)))
      {
        delete_closing_already_bucket_locked(synproxy, local, entry);
        entry = NULL;
      }
      else
      {
        synproxy_entry_to_str(statebuf, statebufsiz, entry);
        synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
        log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "S/SA but entry exists, state: %s, packet: %s", statebuf, packetbuf);
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    entry = synproxy_hash_put(
      local, version, lan_ip, lan_port, remote_ip, remote_port, 0, time64);
    if (version == 6)
    {
      entry->ulflowlabel = ipv6_flow_label(ip);
    }
    if (entry == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "out of memory or already exists");
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    tcp_parse_options(ippay, &tcpinfo);
    if (!tcpinfo.options_valid)
    {
      tcpinfo.wscale = 0;
      tcpinfo.mssoff = 0;
      tcpinfo.mss = 1460;
      tcpinfo.sack_permitted = 0;
    }
    entry->flag_state = FLAG_STATE_UPLINK_SYN_SENT;
    entry->state_data.uplink_syn_sent.isn = tcp_seq_number(ippay);
    entry->statetrack.lan.wscale = tcpinfo.wscale;
    entry->statetrack.lan.max_window_unscaled = tcp_window(ippay);
    entry->lan_sack_was_supported = tcpinfo.sack_permitted;
    if (entry->statetrack.lan.max_window_unscaled == 0)
    {
      entry->statetrack.lan.max_window_unscaled = 1;
    }
    entry->statetrack.lan.sent = tcp_seq_number(ippay) + 1;
    if (synproxy->conf->mss_clamp_enabled)
    {
      uint16_t mss;
      mss = tcpinfo.mss;
      if (mss > synproxy->conf->mss_clamp)
      {
        mss = synproxy->conf->mss_clamp;
      }
      if (tcpinfo.mssoff)
      {
        tcp_set_mss_cksum_update(ippay, &tcpinfo, mss);
      }
    }
    //port->portfunc(pkt, port->userdata);
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.ul_syn_sent*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    synproxy_hash_unlock(local, &ctx);
    return 0;
  }
  else
  {
    struct tcp_information tcpinfo;
    struct sack_hash_data sackdata;
    struct threetuplepayload threetuplepayload;
    uint8_t own_wscale;
    ctx.locked = 0;
    entry = synproxy_hash_get(
      local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
    if (entry == NULL)
    {
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA but entry nonexistent, packet: %s", packetbuf);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (entry->flag_state == FLAG_STATE_ESTABLISHED)
    {
      // FIXME we should store the ISN permanently...
      if (tcp_ack_number(ippay) == entry->statetrack.lan.acked &&
          tcp_seq_number(ippay) + 1 + entry->seqoffset == entry->statetrack.lan.sent)
      {
        synproxy_entry_to_str(statebuf, statebufsiz, entry);
        synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
        log_log(LOG_LEVEL_NOTICE, "WORKERUPLINK", "resending ACK, state: %s, packet: %s", statebuf, packetbuf);
        send_ack_only(ether, entry, port, st);
        synproxy_hash_unlock(local, &ctx);
        return 1;
      }
    }
    if (entry->flag_state != FLAG_STATE_DOWNLINK_SYN_SENT)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, entry != DL_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.remote_isn + 1)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "SA/SA, invalid ACK num, state: %s, packet: %s", statebuf, packetbuf);
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
    tcp_parse_options(ippay, &tcpinfo);
    if (!tcpinfo.options_valid)
    {
      tcpinfo.mss = synproxy->conf->own_mss;
      tcpinfo.wscale = 0;
      tcpinfo.sack_permitted = 0;
    }
    sackdata.sack_supported = tcpinfo.sack_permitted;
    sackdata.mss = tcpinfo.mss;
    if (sackdata.mss == 0)
    {
      sackdata.mss = synproxy->conf->own_mss;
    }
    if (   synproxy->conf->sackmode == HASHMODE_HASHIPPORT
        || synproxy->conf->mssmode == HASHMODE_HASHIPPORT)
    {
      if (version == 4)
      {
        sack_ip_port_hash_add4(
          &synproxy->autolearn, ip_src(ip), tcp_src_port(ippay), &sackdata);
      }
      else
      {
        sack_ip_port_hash_add6(
          &synproxy->autolearn, ipv6_src(ip), tcp_src_port(ippay), &sackdata);
      }
    }
    if (   synproxy->conf->sackmode == HASHMODE_HASHIP
        || synproxy->conf->mssmode == HASHMODE_HASHIP)
    {
      if (version == 4)
      {
        sack_ip_port_hash_add4(
          &synproxy->autolearn, ip_src(ip), 0, &sackdata);
      }
      else
      {
        sack_ip_port_hash_add6(
          &synproxy->autolearn, ipv6_src(ip), 0, &sackdata);
      }
    }
    if (synproxy->conf->wscalemode == HASHMODE_COMMANDED)
    {
      if (version == 4)
      {
        if (threetuplectx_find(&synproxy->threetuplectx, ip_src(ip), tcp_src_port(ippay), 6, &threetuplepayload) != 0)
        {
          threetuplepayload.wscaleshift = synproxy->conf->own_wscale;
        }
      }
      else
      {
        if (threetuplectx_find6(&synproxy->threetuplectx, ipv6_src(ip), tcp_src_port(ippay), 6, &threetuplepayload) != 0)
        {
          threetuplepayload.wscaleshift = synproxy->conf->own_wscale;
        }
      }
    }
    if (synproxy->conf->wscalemode == HASHMODE_COMMANDED)
    {
      own_wscale = threetuplepayload.wscaleshift;
    }
    else
    {
      own_wscale = synproxy->conf->own_wscale;
    }
    entry->wscalediff =
      ((int)own_wscale) - ((int)tcpinfo.wscale);
    entry->seqoffset =
      entry->state_data.downlink_syn_sent.local_isn - tcp_seq_number(ippay);
    if (tcpinfo.ts_present)
    {
      entry->tsoffset =
        entry->state_data.downlink_syn_sent.local_timestamp - tcpinfo.ts;
    }
    else
    {
      entry->tsoffset = 0;
    }
    entry->statetrack.lan.wscale = tcpinfo.wscale;
    entry->statetrack.lan.sent = tcp_seq_number(ippay) + 1 + entry->seqoffset;
    entry->statetrack.lan.acked = tcp_ack_number(ippay);
    entry->statetrack.lan.max = tcp_ack_number(ippay) + (((uint32_t)tcp_window(ippay)) << entry->statetrack.lan.wscale);
    entry->statetrack.lan.max_window_unscaled = tcp_window(ippay);
    entry->lan_sack_was_supported = tcpinfo.sack_permitted;
    if (entry->statetrack.lan.max_window_unscaled == 0)
    {
      entry->statetrack.lan.max_window_unscaled = 1;
    }
    entry->flag_state = FLAG_STATE_ESTABLISHED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.connected*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    timer_linkheap_remove(&local->timers, &entry->syn_timer);
    worker_local_wrunlock(local);
    send_ack_and_window_update(ether, entry, port, st);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
}


static int
handle_uplink_syn_rcvd(struct packet *pkt, void *ether, void *ip, void *ippay,
                       struct synproxy_hash_entry *entry,
                       struct synproxy *synproxy, struct worker_local *local,
                       struct port *port, struct ll_alloc_st *st,
                       char *packetbuf, size_t packetbufsiz,
                       char *statebuf, size_t statebufsiz,
                       uint64_t time64, int version)
{
  uint32_t first_seq, last_seq;
  int32_t data_len;
  uint32_t ip_len = ip46_total_len(ip);
  //uint32_t tcp_len = ip_len - ip46_hdr_len(ip);
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
    return 1;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
    return 1;
  }
  if (tcp_rst(ippay))
  {
    uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
    if (!rst_is_valid_uplink(seq, &entry->statetrack))
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
              "invalid SEQ num in RST, %u/%u/%u, state: %s, packet: %s",
              seq, entry->statetrack.lan.sent, entry->statetrack.wan.acked,
              statebuf, packetbuf);
      return 1;
    }
    entry->flag_state = FLAG_STATE_RESETED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.reseted*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
  if (tcp_ack(ippay))
  {
    uint32_t ack = tcp_ack_number(ippay);
    uint16_t window = tcp_window(ippay);
    if (tcp_ack_number(ippay) != entry->state_data.uplink_syn_rcvd.isn + 1)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid ACK number, state: %s, packet: %s", statebuf, packetbuf);
      return 1;
    }
    first_seq = tcp_seq_number(ippay);
    data_len =
      ((int32_t)ip_len) - ((int32_t)ip46_hdr_len(ip)) - ((int32_t)tcp_data_offset(ippay));
    if (data_len < 0)
    {
      // This can occur in fragmented packets. We don't then know the true
      // data length, and can therefore drop packets that would otherwise be
      // valid.
      data_len = 0;
    }
    last_seq = first_seq + ((uint32_t)data_len) - 1U;
    if (seq_cmp(last_seq, entry->statetrack.lan.sent) >= 0)
    {
      entry->statetrack.lan.sent = last_seq + 1;
    }
    entry->statetrack.lan.acked = ack;
    entry->statetrack.lan.max = ack + (((uint32_t)window) << entry->statetrack.lan.wscale);
    entry->flag_state = FLAG_STATE_ESTABLISHED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.connected*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
  synproxy_entry_to_str(statebuf, statebufsiz, entry);
  synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
  log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "UPLINK_SYN_RECEIVED w/o ACK, state: %s, packet: %s", statebuf, packetbuf);
  return 1;
}

static int
handle_uplink_rst(void *ether, void *ip, void *ippay,
                  struct synproxy_hash_entry *entry,
                  struct worker_local *local,
                  struct synproxy *synproxy,
                  struct port *port,
                  struct ll_alloc_st *st,
                  int version,
                  struct packet *pkt,
                  uint64_t time64,
                  char *packetbuf, size_t packetbufsiz,
                  char *statebuf, size_t statebufsiz)
{
  uint32_t ip_len = ip46_total_len(ip);
  uint32_t tcp_len = ip_len - ip46_hdr_len(ip);
  if (ip46_hdr_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid IP hdr cksum");
    return 1;
  }
  if (tcp46_cksum_calc(ip) != 0)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "invalid TCP hdr cksum");
    return 1;
  }
  if (entry->flag_state == FLAG_STATE_UPLINK_SYN_SENT)
  {
    synproxy_entry_to_str(statebuf, statebufsiz, entry);
    synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "dropping RST in UPLINK_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
    return 1;
  }
  else if (entry->flag_state == FLAG_STATE_DOWNLINK_SYN_SENT)
  {
    if (!tcp_ack(ippay))
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "R/RA in DOWNLINK_SYN_SENT, state: %s, packet: %s", statebuf, packetbuf);
      return 1;
    }
    if (tcp_ack_number(ippay) != entry->state_data.downlink_syn_sent.remote_isn + 1)
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "RA/RA in DL_SYN_SENT, bad seq, state: %s, packet: %s", statebuf, packetbuf);
      return 1;
    }
    tcp_set_seq_number_cksum_update(
      ippay, tcp_len, entry->state_data.downlink_syn_sent.local_isn + 1);
    tcp_set_ack_off_cksum_update(ippay);
    tcp_set_ack_number_cksum_update(
      ippay, tcp_len, 0);
    entry->flag_state = FLAG_STATE_RESETED;
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.reseted*1000ULL*1000ULL;
    timer_linkheap_modify(&local->timers, &entry->timer);
    timer_linkheap_remove(&local->timers, &entry->syn_timer);
    worker_local_wrunlock(local);
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
  else
  {
    uint32_t seq = tcp_seq_number(ippay) + entry->seqoffset;
    if (!rst_is_valid_uplink(seq, &entry->statetrack))
    {
      synproxy_entry_to_str(statebuf, statebufsiz, entry);
      synproxy_packet_to_str(packetbuf, packetbufsiz, ether);
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK",
              "invalid SEQ num in RST, %u/%u/%u, state: %s, packet: %s",
              seq, entry->statetrack.lan.sent, entry->statetrack.wan.acked, statebuf, packetbuf);
      return 1;
    }
  }
  tcp_set_seq_number_cksum_update(
    ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
  entry->flag_state = FLAG_STATE_RESETED;
  worker_local_wrlock(local);
  entry->timer.time64 = time64 +
    synproxy->conf->timeouts.reseted*1000ULL*1000ULL;
  timer_linkheap_modify(&local->timers, &entry->timer);
  worker_local_wrunlock(local);
  //port->portfunc(pkt, port->userdata);
  return 0;
}

/*
  Uplink packet arrives. It has lan_ip:lan_port remote_ip:remote_port
  - Lookup by lan_ip:lan_port, verify remote_ip:remote_port
  Downlink packet arrives. It has wan_ip:wan_port remote_ip:remote_port
  - Lookup by wan_port, verify remote_ip:remote_port
 */

// return: whether to free (1) or not (0)
int uplink(
  struct synproxy *synproxy, struct worker_local *local, struct packet *pkt,
  struct port *port, uint64_t time64, struct ll_alloc_st *st)
{
  void *ether = pkt->data;
  void *ip;
  void *ippay;
  size_t ether_len = pkt->sz;
  size_t ip_len;
  uint16_t ihl;
  const void *remote_ip;
  uint16_t remote_port;
  uint8_t protocol;
  const void *lan_ip;
  uint16_t lan_port;
  uint16_t tcp_len;
  struct synproxy_hash_entry *entry;
  struct synproxy_hash_ctx ctx;
  int8_t wscalediff;
  int todelete = 0;
  struct sack_ts_headers hdrs;
  char statebuf[8192];
  char packetbuf[8192];
  int version;
  struct seqs seqs;

  if (ether_len < ETHER_HDR_LEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full Ether hdr");
    return 1;
  }
  if (ether_type(ether) != ETHER_TYPE_IP && ether_type(ether) != ETHER_TYPE_IPV6)
  {
    //port->portfunc(pkt, port->userdata);
    return 0;
  }
  ip = ether_payload(ether);
  ip_len = ether_len - ETHER_HDR_LEN;
  if (ip_len < IP_HDR_MINLEN)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 1");
    return 1;
  }
  version = ip_version(ip);
  if (version != 4 && version != 6)
  {
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IP version mismatch");
    return 1;
  }
  if (version == 4)
  {
    ihl = ip_hdr_len(ip);
    if (ip_len < ihl)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP hdr 2");
      return 1;
    }
    if (ip_proto(ip) != 6)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    if (ip_frag_off(ip) >= 60)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    else if (ip_frag_off(ip) != 0)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "fragment has partial header");
      return 1;
    }
    if (ip_len < ip_total_len(ip))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IP data");
      return 1;
    }
    
    protocol = ip_proto(ip);
    ippay = ip_payload(ip);
    lan_ip = ip_src_ptr(ip);
    remote_ip = ip_dst_ptr(ip);
  }
  else
  {
    int is_frag = 0;
    uint16_t proto_off_from_frag = 0;
    if (ip_len < 40)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IPv6 hdr 1");
      return 1;
    }
    if (ip_len < (size_t)(ipv6_payload_len(ip) + 40))
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full IPv6 data");
      return 1;
    }
    protocol = 0;
    ippay = ipv6_proto_hdr_2(ip, &protocol, &is_frag, NULL, &proto_off_from_frag);
    if (ippay == NULL)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt without ext hdr chain");
      return 1;
    }
    if (is_frag && proto_off_from_frag + 60 > IPV6_FRAG_CUTOFF)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IPv6 proto hdr too deep in hdr chain");
      return 1;
    }
    if (protocol == 44 && ipv6_frag_off(ippay) < IPV6_FRAG_CUTOFF)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "IPv6 subsequent frag too low frag off");
      return 1;
    }
    if (protocol != 6)
    {
      //port->portfunc(pkt, port->userdata);
      return 0;
    }
    ihl = ((char*)ippay) - ((char*)ip);
    lan_ip = ipv6_src(ip);
    remote_ip = ipv6_dst(ip);
  }
  if (protocol == 6)
  {
    tcp_len = ip46_total_len(ip) - ihl;
    if (tcp_len < 20)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP hdr");
      return 1;
    }
    if (tcp_data_offset(ippay) > tcp_len)
    {
      log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "pkt does not have full TCP opts");
      return 1;
    }
    lan_port = tcp_src_port(ippay);
    remote_port = tcp_dst_port(ippay);
  }
  else
  {
    abort();
  }
  if (unlikely(tcp_syn(ippay)))
  {
    return handle_uplink_syn(pkt, ether, ip, ippay,
                             local, synproxy, port, st, version, time64,
                             packetbuf, sizeof(packetbuf),
                             statebuf, sizeof(statebuf));
  }
  ctx.locked = 0;
  entry = synproxy_hash_get(
    local, version, lan_ip, lan_port, remote_ip, remote_port, &ctx);
  if (entry == NULL)
  {
    synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "entry not found, packet: %s", packetbuf);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (unlikely(entry->flag_state == FLAG_STATE_UPLINK_SYN_RCVD))
  {
    int ret;
    ret = handle_uplink_syn_rcvd(pkt, ether, ip, ippay,
                                 entry, synproxy, local, port, st,
                                 packetbuf, sizeof(packetbuf),
                                 statebuf, sizeof(statebuf),
                                 time64, version);
    synproxy_hash_unlock(local, &ctx);
    return ret;
  }
  if (unlikely(tcp_rst(ippay)))
  {
    int ret;
    ret = handle_uplink_rst(ether, ip, ippay, entry,
                            local, synproxy, port, st, version, pkt, time64,
                            packetbuf, sizeof(packetbuf),
                            statebuf, sizeof(statebuf));
    synproxy_hash_unlock(local, &ctx);
    return ret;
  }
  if (!synproxy_is_connected(entry) && entry->flag_state != FLAG_STATE_RESETED)
  {
    synproxy_entry_to_str(statebuf, sizeof(statebuf), entry);
    synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "not CONNECTED/RESETED, dropping, state: %s, packet: %s", statebuf, packetbuf);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }
  if (!tcp_ack(ippay))
  {
    synproxy_entry_to_str(statebuf, sizeof(statebuf), entry);
    synproxy_packet_to_str(packetbuf, sizeof(packetbuf), ether);
    log_log(LOG_LEVEL_ERR, "WORKERUPLINK", "no TCP ACK, dropping pkt, state: %s, packet: %s", statebuf, packetbuf);
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }

  calc_seqs(&seqs, ip, ippay, entry->seqoffset);
  if (!seqs_valid_uplink(entry, &seqs, ether, ip, ippay, 1,
                         statebuf, sizeof(statebuf),
                         packetbuf, sizeof(packetbuf)))
  {
    synproxy_hash_unlock(local, &ctx);
    return 1;
  }

  if (unlikely(tcp_fin(ippay)) && entry->flag_state != FLAG_STATE_RESETED)
  {
    if (handle_uplink_fin(entry, ip, &seqs, version))
    {
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }
  if (unlikely(entry->flag_state & FLAG_STATE_DOWNLINK_FIN))
  {
    todelete = check_uplink_finack(entry, ip, ippay);
    if (todelete < 0)
    {
      synproxy_hash_unlock(local, &ctx);
      return 1;
    }
  }

  update_side(&entry->statetrack.lan, &seqs, ippay);

  update_tcp_timeout(entry, local, time64);

  tcp_set_seq_number_cksum_update(
    ippay, tcp_len, tcp_seq_number(ippay)+entry->seqoffset);
  if (version == 6)
  {
    ipv6_set_flow_label(ip, entry->ulflowlabel);
  }
  wscalediff = entry->wscalediff;
  if (wscalediff > 0)
  {
    uint16_t win16 = tcp_window(ippay) >> entry->wscalediff;
    if (win16 == 0 && tcp_window(ippay) != 0)
    {
      win16 = 1;
    }
    tcp_set_window_cksum_update(ippay, tcp_len, win16);
  }
  else
  {
    uint64_t win64 = ((uint64_t)tcp_window(ippay)) << (-(entry->wscalediff));
    if (win64 > 65535 || win64 < tcp_window(ippay))
    {
      win64 = 65535;
    }
    tcp_set_window_cksum_update(ippay, tcp_len, win64);
  }
  tcp_find_sack_ts_headers(ippay, &hdrs);
  tcp_adjust_tsval_cksum_update(ippay, &hdrs, entry->tsoffset);
  //port->portfunc(pkt, port->userdata);
  if (todelete)
  {
    worker_local_wrlock(local);
    entry->timer.time64 = time64 +
      synproxy->conf->timeouts.time_wait*1000ULL*1000ULL;
    entry->flag_state = FLAG_STATE_TIME_WAIT;
    timer_linkheap_modify(&local->timers, &entry->timer);
    worker_local_wrunlock(local);
  }
  synproxy_hash_unlock(local, &ctx);
  return 0;
}

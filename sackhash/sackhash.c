#include "hashtable.h"
#include "siphash.h"
#include "linkedlist.h"
#include "containerof.h"
#include <pthread.h>
#include "sackhash.h"
#include "hashseed.h"

static inline void
ipport_form4(struct ipport *ipport, uint32_t ip, uint16_t port)
{
  ipport->ipport1 = (((uint64_t)ip)<<32) | port;
  ipport->ipport2 = 1;
  ipport->ipport3 = 1; // Mutually exclusive with form6 value
}

static inline void
ipport_form6(struct ipport *ipport, const void *ip, uint16_t port)
{
  uint64_t u64;
  const char *cip = ip;
  memcpy(&u64, &cip[8], sizeof(u64));
  ipport->ipport1 = u64;
  memcpy(&u64, &cip[0], sizeof(u64));
  ipport->ipport2 = u64;
  ipport->ipport3 = ((uint64_t)port)<<32;
}

static inline int
ipport_equals(const struct ipport *ipport1, const struct ipport *ipport2)
{
  if (ipport2->ipport1 != ipport2->ipport1)
  {
    return 0;
  }
  if (ipport2->ipport2 != ipport2->ipport2)
  {
    return 0;
  }
  if (ipport2->ipport3 != ipport2->ipport3)
  {
    return 0;
  }
  return 1;
}

static inline uint32_t
ipport_hash(const struct ipport *ipport)
{
  struct siphash_ctx ctx;
  siphash_init(&ctx, hash_seed_get());
  siphash_feed_u64(&ctx, ipport->ipport1);
  siphash_feed_u64(&ctx, ipport->ipport2);
  siphash_feed_u64(&ctx, ipport->ipport3);
  return siphash_get(&ctx);
}

static inline uint64_t ip_port(uint32_t ip, uint16_t port)
{
  return ip | (((uint64_t)port)<<32);
}

static inline uint32_t sack_ipport_hash_value(uint64_t ipport)
{
  return siphash64(hash_seed_get(), ipport);
}

static inline uint32_t sack_ip_port_hash_value(uint32_t ip, uint16_t port)
{
  return sack_ipport_hash_value(ip_port(ip, port));
}

static inline uint32_t sack_ip_port_hash_fn(
  struct hash_list_node *node, void *ud)
{
  struct sack_ip_port_hash_entry *e;
  e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
  return ipport_hash(&e->ipport);
}

int sack_ip_port_hash_init(
  struct sack_ip_port_hash *hash, size_t capacity)
{
  int i;
  if (capacity < SACK_HASH_READ_MTX_CNT)
  {
    capacity = SACK_HASH_READ_MTX_CNT;
  }
  if (capacity == 0 || (capacity & (capacity-1)) != 0)
  {
    abort();
  }
  if (pthread_mutex_init(&hash->mtx, NULL) != 0)
  {
    return -ENOMEM;
  }
  for (i = 0; i < SACK_HASH_READ_MTX_CNT; i++)
  {
    if (pthread_mutex_init(&hash->read_mtx[i], NULL) != 0)
    {
      while (i >= 0)
      {
        pthread_mutex_destroy(&hash->read_mtx[i]);
        i--;
      }
      pthread_mutex_destroy(&hash->mtx);
      return -ENOMEM;
    }
  }
  if (hash_table_init(&hash->hash, capacity, sack_ip_port_hash_fn, NULL))
  {
    for (i = 0; i < SACK_HASH_READ_MTX_CNT; i++)
    {
      pthread_mutex_destroy(&hash->read_mtx[i]);
    }
    pthread_mutex_destroy(&hash->mtx);
    return -ENOMEM;
  }
  linked_list_head_init(&hash->list);
  return 0;
}

void sack_ip_port_hash_free(struct sack_ip_port_hash *hash)
{
  int i;
  while (!linked_list_is_empty(&hash->list))
  {
    struct linked_list_node *llnode = hash->list.node.next;
    struct sack_ip_port_hash_entry *old;
    uint32_t hashval2;
    old = CONTAINER_OF(llnode, struct sack_ip_port_hash_entry, llnode);
    hashval2 = ipport_hash(&old->ipport);
    linked_list_delete(llnode);
    hash_table_delete(&hash->hash, &old->node, hashval2);
    free(old);
  }
  for (i = 0; i < SACK_HASH_READ_MTX_CNT; i++)
  {
    pthread_mutex_destroy(&hash->read_mtx[i]);
  }
  pthread_mutex_destroy(&hash->mtx);
  hash_table_free(&hash->hash);
}

static inline int sack_ip_port_hash_add_common(
  struct sack_ip_port_hash *hash, struct ipport *ipport,
  const struct sack_hash_data *data)
{
  int result = 0, status = 0;
  uint32_t hashval;
  struct hash_list_node *node;
  struct sack_ip_port_hash_entry *e;
  hashval = ipport_hash(ipport);
  if (pthread_mutex_lock(&hash->mtx) != 0)
  {
    abort();
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&hash->hash, node, hashval)
  {
    e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
    if (ipport_equals(&e->ipport, ipport))
    {
      if (pthread_mutex_lock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
      {
        abort();
      }
      e->data = *data; // struct assignment
      if (pthread_mutex_unlock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
      {
        abort();
      }
      result = 1;
      break;
    }
  }
  if (!result)
  {
    e = malloc(sizeof(*e));
    if (e == NULL)
    {
      status = -ENOMEM;
      goto out;
    }
    e->ipport = *ipport;
    e->data = *data; // struct assignment
    if (hash->hash.itemcnt >= hash->hash.bucketcnt)
    {
      struct linked_list_node *llnode = hash->list.node.next;
      struct sack_ip_port_hash_entry *old;
      uint32_t hashval2;
      old = CONTAINER_OF(llnode, struct sack_ip_port_hash_entry, llnode);
      hashval2 = ipport_hash(&old->ipport);
      linked_list_delete(llnode);
      if (pthread_mutex_lock(&hash->read_mtx[hashval2%SACK_HASH_READ_MTX_CNT]) != 0)
      {
        abort();
      }
      hash_table_delete(&hash->hash, &old->node, hashval2);
      if (pthread_mutex_unlock(&hash->read_mtx[hashval2%SACK_HASH_READ_MTX_CNT]) != 0)
      {
        abort();
      }
      free(old);
    }
    linked_list_add_tail(&e->llnode, &hash->list);
    if (pthread_mutex_lock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
    {
      abort();
    }
    hash_table_add_nogrow(&hash->hash, &e->node, hashval);
    if (pthread_mutex_unlock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
    {
      abort();
    }
  }
out:
  if (pthread_mutex_unlock(&hash->mtx) != 0)
  {
    abort();
  }
  return status;
}

int sack_ip_port_hash_add4(
  struct sack_ip_port_hash *hash, uint32_t ip, uint16_t port,
  const struct sack_hash_data *data)
{
  struct ipport ipport;
  ipport_form4(&ipport, ip, port);
  return sack_ip_port_hash_add_common(hash, &ipport, data);
}

int sack_ip_port_hash_add6(
  struct sack_ip_port_hash *hash, const void *ip, uint16_t port,
  const struct sack_hash_data *data)
{
  struct ipport ipport;
  ipport_form6(&ipport, ip, port);
  return sack_ip_port_hash_add_common(hash, &ipport, data);
}

int sack_ip_port_hash_get4(
  struct sack_ip_port_hash *hash, uint32_t ip, uint16_t port,
  struct sack_hash_data *data)
{
  int result = 0;
  struct ipport ipport;
  uint32_t hashval;
  struct hash_list_node *node;
  struct sack_ip_port_hash_entry *e;
  ipport_form4(&ipport, ip, port);
  hashval = ipport_hash(&ipport);
  if (pthread_mutex_lock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
  {
    abort();
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&hash->hash, node, hashval)
  {
    e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
    if (ipport_equals(&e->ipport, &ipport))
    {
      *data = e->data; // struct assignment
      result = 1;
      break;
    }
  }
  if (pthread_mutex_unlock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
  {
    abort();
  }
  return result;
}

int sack_ip_port_hash_get6(
  struct sack_ip_port_hash *hash, const void *ip, uint16_t port,
  struct sack_hash_data *data)
{
  int result = 0;
  struct ipport ipport;
  uint32_t hashval;
  struct hash_list_node *node;
  struct sack_ip_port_hash_entry *e;
  ipport_form6(&ipport, ip, port);
  hashval = ipport_hash(&ipport);
  if (pthread_mutex_lock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
  {
    abort();
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&hash->hash, node, hashval)
  {
    e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
    if (ipport_equals(&e->ipport, &ipport))
    {
      *data = e->data; // struct assignment
      result = 1;
      break;
    }
  }
  if (pthread_mutex_unlock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
  {
    abort();
  }
  return result;
}

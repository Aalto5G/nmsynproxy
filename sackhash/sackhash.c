#include "hashtable.h"
#include "siphash.h"
#include "linkedlist.h"
#include "containerof.h"
#include <pthread.h>
#include "sackhash.h"
#include "hashseed.h"

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
  return sack_ipport_hash_value(e->ipport);
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
    old = CONTAINER_OF(llnode, struct sack_ip_port_hash_entry, llnode);
    linked_list_delete(llnode);
    hash_table_delete(&hash->hash, &old->node);
    free(old);
  }
  for (i = 0; i < SACK_HASH_READ_MTX_CNT; i++)
  {
    pthread_mutex_destroy(&hash->read_mtx[i]);
  }
  pthread_mutex_destroy(&hash->mtx);
  hash_table_free(&hash->hash);
}

int sack_ip_port_hash_add(
  struct sack_ip_port_hash *hash, uint32_t ip, uint16_t port,
  const struct sack_hash_data *data)
{
  int result = 0, status = 0;
  uint64_t ipport = ip_port(ip, port);
  uint32_t hashval = sack_ipport_hash_value(ipport);
  struct hash_list_node *node;
  struct sack_ip_port_hash_entry *e;
  if (pthread_mutex_lock(&hash->mtx) != 0)
  {
    abort();
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&hash->hash, node, hashval)
  {
    e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
    if (e->ipport == ipport)
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
    e->ipport = ipport;
    e->data = *data; // struct assignment
    if (hash->hash.itemcnt >= hash->hash.bucketcnt)
    {
      struct linked_list_node *llnode = hash->list.node.next;
      struct sack_ip_port_hash_entry *old;
      uint32_t hashval2;
      old = CONTAINER_OF(llnode, struct sack_ip_port_hash_entry, llnode);
      hashval2 = sack_ipport_hash_value(old->ipport);
      linked_list_delete(llnode);
      if (pthread_mutex_lock(&hash->read_mtx[hashval2%SACK_HASH_READ_MTX_CNT]) != 0)
      {
        abort();
      }
      hash_table_delete(&hash->hash, &old->node);
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

int sack_ip_port_hash_get(
  struct sack_ip_port_hash *hash, uint32_t ip, uint16_t port,
  struct sack_hash_data *data)
{
  int result = 0;
  uint64_t ipport = ip_port(ip, port);
  uint32_t hashval = sack_ipport_hash_value(ipport);
  struct hash_list_node *node;
  struct sack_ip_port_hash_entry *e;
  if (pthread_mutex_lock(&hash->read_mtx[hashval%SACK_HASH_READ_MTX_CNT]) != 0)
  {
    abort();
  }
  HASH_TABLE_FOR_EACH_POSSIBLE(&hash->hash, node, hashval)
  {
    e = CONTAINER_OF(node, struct sack_ip_port_hash_entry, node);
    if (e->ipport == ipport)
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

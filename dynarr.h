#ifndef _DYNARR_H_
#define _DYNARR_H_

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define DYNARR(x) \
  struct { \
    x* ar; \
    size_t capacity; \
    size_t size; \
  }

#define DYNARR_INITER \
  { \
    .ar = NULL, \
    .capacity = 0, \
    .size = 0, \
  }

#define DYNARR_GET(arptr, i) \
  ((arptr)->ar[i])

#define DYNARR_SET(arptr, i, x) \
  *(&(DYNARR_GET(arptr, i))) = (x);

void *dynarr_realloc_impl(void *old, size_t size, size_t *capacity, size_t extend, size_t item_size);

#define DYNARR_ENSURE_EXTEND(arptr, extend) \
  ({ \
    typeof(arptr) __ensure_extend_arptr = (arptr); \
    typeof(__ensure_extend_arptr->ar) __ensure_extend_newar; \
    size_t __ensure_extend_extend = (extend); \
    int __ensure_extend_result; \
    if (__ensure_extend_arptr->size + __ensure_extend_extend <= __ensure_extend_arptr->capacity) \
    { \
      __ensure_extend_result = 1; \
    } \
    else \
    { \
      __ensure_extend_newar = dynarr_realloc_impl( \
          __ensure_extend_arptr->ar, \
          __ensure_extend_arptr->size, \
          &__ensure_extend_arptr->capacity, \
          __ensure_extend_extend, \
          sizeof(*(__ensure_extend_arptr->ar))); \
      if (__ensure_extend_newar) \
      { \
        __ensure_extend_arptr->ar = __ensure_extend_newar; \
        __ensure_extend_result = 1; \
      } \
      else \
      { \
        __ensure_extend_result = 0; \
      } \
    } \
    __ensure_extend_result; \
  })

#define DYNARR_PUSH_BACK(arptr, x) \
  ({ \
    typeof(arptr) __push_back_arptr = (arptr); \
    typeof(x) __push_back_x = (x); \
    int __push_back_result; \
    __push_back_result = DYNARR_ENSURE_EXTEND(__push_back_arptr, 1); \
    if (__push_back_result) \
    { \
      __push_back_arptr->ar[__push_back_arptr->size++] = __push_back_x; \
    } \
    __push_back_result; \
  })

#define DYNARR_PUSH_BACK_RETPTR(arptr, x) \
  ({ \
    typeof(arptr) __push_back_retptr_arptr = (arptr); \
    typeof(x) __push_back_retptr_x = (x); \
    typeof(arptr->ar) __push_back_retptr_result = NULL; \
    if (DYNARR_ENSURE_EXTEND(__push_back_retptr_arptr, 1)) \
    { \
      __push_back_retptr_result = &__push_back_retptr_arptr->[__push_back_retptr_arptr->size++]; \
    } \
    else \
    { \
      __push_back_retptr_result = NULL; \
    } \
    __push_back_retptr_result; \
  })

#define DYNARR_SIZE(arptr) ((arptr)->size)

#endif

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "dynarr.h"

void *dynarr_realloc_impl(void *old, size_t size, size_t *capacity, size_t extend, size_t item_size)
{
  size_t new_capacity = size + extend;
  void *newptr;
  if (new_capacity < (*capacity)*2 + 1)
  {
    new_capacity = (*capacity)*2 + 1;
  }
  newptr = malloc(new_capacity*item_size);
  if (newptr == NULL)
  {
    return NULL;
  }
  memcpy(newptr, old, size*item_size);
  free(old);
  *capacity = new_capacity;
  return newptr;
}

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "buff.h"
static char *aligned_ptr(char *p)
{
  uintptr_t ptr = (uintptr_t)p;
  if (ptr % sizeof(void *))
  {
    p += sizeof(void *) - (ptr % sizeof(void *));
  }
  return p;
}

void buffer_init(struct buffer_t *buf, char *buffer, size_t buflen)
{
  // next always points to an aligned location.
  buf->next = aligned_ptr(buffer);
  // end is one past the buffer.
  buf->end = buffer + buflen;
}

char *buffer_strdup(struct buffer_t *buf, const char *str)
{
  char *result = buffer_alloc(buf, strlen(str) + 1);
  if (result == NULL)
  {
    return NULL;
  }
  strcpy(result, str);
  return result;
}

void *buffer_alloc(struct buffer_t *buf, size_t size)
{
  // Zero-length allocations always succeed with non-NULL.
  if (size == 0)
  {
    return buf; // Just a convenient non-NULL pointer.
  }

  char *alloc_end = buf->next + size;
  if (alloc_end > buf->end)
  {
    // No more memory in the buffer.
    return NULL;
  }

  // We have enough space. Set up the next aligned pointer and return
  // the current one, zeroed.
  char *current = buf->next;
  buf->next = aligned_ptr(alloc_end);
  memset(current, 0, size);
  return current;
}
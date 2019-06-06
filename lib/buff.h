#ifndef __BUFF_H
#define __BUFF_H
#include <stdint.h>
#include <stddef.h>
struct buffer_t
{
  char *next;
  char *end;
};
extern void buffer_init(struct buffer_t *buf, char *buffer, size_t buflen);
extern char *buffer_strdup(struct buffer_t *buf, const char *str);
extern void *buffer_alloc(struct buffer_t *buf, size_t size);
#endif
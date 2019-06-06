#ifndef __UTIL_H
#define __UTIL_H

#include <stdint.h>
#include <netdb.h>
#include "buff.h"
#include "util.h"
#define MAX_ENTRIES 16

struct ipv4_address_t
{
  uint32_t address;
};

struct ipv6_address_t
{
  uint32_t address[4];
};

struct query_address_result_t
{
  int af;
  union {
    struct ipv4_address_t ipv4;
    struct ipv6_address_t ipv6;
  } address;
  uint32_t scopeid;
};

struct userdata_t
{
  int count;
  struct query_address_result_t result[MAX_ENTRIES];
};

extern void append_address_to_userdata(
    const struct query_address_result_t *result,
    struct userdata_t *u);

extern enum nss_status convert_userdata_for_name_to_hostent(
    const struct userdata_t *u,
    const char *name,
    int af,
    struct hostent *result,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop);

extern enum nss_status convert_userdata_to_addrtuple(
    const struct userdata_t *u,
    const char *name,
    struct gaih_addrtuple **pat,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop);

extern enum nss_status convert_name_and_addr_to_hostent(
    const char *name,
    const void *addr,
    int len,
    int af,
    struct hostent *result,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop);
#endif
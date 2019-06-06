
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <netdb.h>
#include <errno.h>
#include <nss.h>
#include "buff.h"
#include "util.h"

#define RETURN_IF_FAILED_ALLOC(ptr) \
  if (ptr == NULL)                  \
  {                                 \
    *errnop = ERANGE;               \
    *h_errnop = NO_RECOVERY;        \
    return NSS_STATUS_TRYAGAIN;     \
  }

void append_address_to_userdata(
    const struct query_address_result_t *result,
    struct userdata_t *u)
{
  assert(result && u);

  if (u->count < MAX_ENTRIES)
  {
    memcpy(&(u->result[u->count]), result, sizeof(struct query_address_result_t));
    u->count++;
  }
}

enum nss_status convert_userdata_for_name_to_hostent(
    const struct userdata_t *u,
    const char *name,
    int af,
    struct hostent *result,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop)
{
  size_t address_length =
      af == AF_INET ? sizeof(struct ipv4_address_t) : sizeof(struct ipv6_address_t);

  // Set empty list of aliases.
  result->h_aliases = (char **)buffer_alloc(buf, sizeof(char **));
  RETURN_IF_FAILED_ALLOC(result->h_aliases);
  *result->h_aliases = NULL;
  // Set official name.
  result->h_name = buffer_strdup(buf, name);
  RETURN_IF_FAILED_ALLOC(result->h_name);

  // Set addrtype and length.
  result->h_addrtype = af;
  result->h_length = address_length;

  // Initialize address list, NULL terminated.
  result->h_addr_list = buffer_alloc(buf, (u->count + 1) * sizeof(char **));
  RETURN_IF_FAILED_ALLOC(result->h_addr_list);

  // Copy the addresses.
  for (int i = 0; i < u->count; i++)
  {
    char *addr = buffer_alloc(buf, address_length);
    RETURN_IF_FAILED_ALLOC(addr);
    memcpy(addr, &u->result[i].address, address_length);
    result->h_addr_list[i] = addr;
  }

  return NSS_STATUS_SUCCESS;
}

enum nss_status convert_userdata_to_addrtuple(
    const struct userdata_t *u,
    const char *name,
    struct gaih_addrtuple **pat,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop)
{

  // Copy name to buffer (referenced in every result address tuple).
  char *buffer_name = buffer_strdup(buf, name);
  RETURN_IF_FAILED_ALLOC(buffer_name);

  struct gaih_addrtuple *tuple_prev = NULL;
  for (int i = 0; i < u->count; i++)
  {
    const struct query_address_result_t *result = &u->result[i];
    struct gaih_addrtuple *tuple;
    if (tuple_prev == NULL && *pat)
    {
      // The caller has provided a valid initial location in *pat,
      // so use that as the first result. Without this, nscd will
      // segfault because it assumes that the buffer is only used as
      // an overflow.
      // See
      // https://lists.freedesktop.org/archives/systemd-devel/2013-February/008606.html
      tuple = *pat;
      memset(tuple, 0, sizeof(*tuple));
    }
    else
    {
      // Allocate a new tuple from the buffer.
      tuple = buffer_alloc(buf, sizeof(struct gaih_addrtuple));
      RETURN_IF_FAILED_ALLOC(tuple);
    }

    size_t address_length = result->af == AF_INET ? sizeof(struct ipv4_address_t)
                                                  : sizeof(struct ipv6_address_t);

    // Assign the (always same) name.
    tuple->name = buffer_name;

    // Assign actual address family of address.
    tuple->family = result->af;

    // Copy address.
    memcpy(&(tuple->addr), &(result->address), address_length);

    // Assign interface scope id
    tuple->scopeid = result->scopeid;

    if (tuple_prev == NULL)
    {
      // This is the first tuple.
      // Return the start of the list in *pat.
      *pat = tuple;
    }
    else
    {
      // Link the new tuple into the previous tuple.
      tuple_prev->next = tuple;
    }

    tuple_prev = tuple;
  }

  return NSS_STATUS_SUCCESS;
}

enum nss_status convert_name_and_addr_to_hostent(
    const char *name,
    const void *addr,
    int len,
    int af,
    struct hostent *result,
    struct buffer_t *buf,
    int *errnop,
    int *h_errnop)
{
  // Set empty list of aliases.
  result->h_aliases = (char **)buffer_alloc(buf, sizeof(char **));
  RETURN_IF_FAILED_ALLOC(result->h_aliases);
  *result->h_aliases = NULL;

  // Set official name.
  result->h_name = buffer_strdup(buf, name);
  RETURN_IF_FAILED_ALLOC(result->h_name);

  // Set addrtype and length.
  result->h_addrtype = af;
  result->h_length = len;

  // Initialize address list of length 1, NULL terminated.
  result->h_addr_list = buffer_alloc(buf, 2 * sizeof(char **));
  RETURN_IF_FAILED_ALLOC(result->h_addr_list);

  // Copy the address.
  result->h_addr_list[0] = buffer_alloc(buf, len);
  RETURN_IF_FAILED_ALLOC(result->h_addr_list[0]);
  memcpy(result->h_addr_list[0], addr, len);

  return NSS_STATUS_SUCCESS;
}
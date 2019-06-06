#include <nss.h>
#include "util.h"
#include "mdns.h"

enum nss_status mdns_resolve_name(
    int af,
    const char *name,
    struct userdata_t *userdata,
    uint32_t *ttlp)
{
  struct query_address_result_t address_result;
  // load up address_result
  append_address_to_userdata(&address_result, userdata);
  return NSS_STATUS_SUCCESS;
}
enum nss_status mdns_resolve_address(
    int af,
    const void *data,
    char *name,
    size_t name_len)
{
  return NSS_STATUS_UNAVAIL;
}
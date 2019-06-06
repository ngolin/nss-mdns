#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <nss.h>

#include "name.h"
#include "buff.h"
#include "util.h"
#include "mdns.h"
#if defined(NSS_IPV4_ONLY) && !defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns4_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns4_gethostbyaddr_r
#elif defined(NSS_IPV4_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns4_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns4_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns4_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns4_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns4_minimal_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && !defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns6_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns6_gethostbyaddr_r
#elif defined(NSS_IPV6_ONLY) && defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns6_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns6_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns6_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns6_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns6_minimal_gethostbyaddr_r
#elif defined(MDNS_MINIMAL)
#define _nss_mdns_gethostbyname4_r _nss_mdns_minimal_gethostbyname4_r
#define _nss_mdns_gethostbyname3_r _nss_mdns_minimal_gethostbyname3_r
#define _nss_mdns_gethostbyname2_r _nss_mdns_minimal_gethostbyname2_r
#define _nss_mdns_gethostbyname_r _nss_mdns_minimal_gethostbyname_r
#define _nss_mdns_gethostbyaddr_r _nss_mdns_minimal_gethostbyaddr_r
#endif

// Define prototypes for nss function we're going to export (fixes GCC warnings)
enum nss_status _nss_mdns_gethostbyname4_r(
    const char *, struct gaih_addrtuple **,
    char *, size_t, int *, int *, int32_t *);
enum nss_status _nss_mdns_gethostbyname3_r(
    const char *, int, struct hostent *,
    char *, size_t, int *, int *, int32_t *,
    char **);
enum nss_status _nss_mdns_gethostbyname2_r(
    const char *, int, struct hostent *,
    char *, size_t, int *, int *);
enum nss_status _nss_mdns_gethostbyname_r(
    const char *, struct hostent *, char *,
    size_t, int *, int *);
enum nss_status _nss_mdns_gethostbyaddr_r(
    const void *, int, int,
    struct hostent *, char *, size_t, int *,
    int *);

// static enum mdns_resolve_result_t do_mdns_resolve_name(
//     int af,
//     const char *name,
//     struct userdata_t *userdata,
//     uint32_t *ttlp)
// {
//   bool ipv4_found = false;
//   bool ipv6_found = false;

//   if (af == AF_INET || af == AF_UNSPEC)
//   {
//     struct query_address_result_t address_result;
//     switch (mdns_resolve_name(AF_INET, name, &address_result))
//     {
//     case MDNS_RESOLVE_RESULT_SUCCESS:
//       append_address_to_userdata(&address_result, userdata);
//       ipv4_found = true;
//       break;

//     case MDNS_RESOLVE_RESULT_HOST_NOT_FOUND:
//       break;

//     case MDNS_RESOLVE_RESULT_UNAVAIL:
//       // Something went wrong, just fail.
//       return MDNS_RESOLVE_RESULT_UNAVAIL;
//     }
//   }

//   if (af == AF_INET6 || af == AF_UNSPEC)
//   {
//     struct query_address_result_t address_result;
//     switch (mdns_resolve_name(AF_INET6, name, &address_result))
//     {
//     case MDNS_RESOLVE_RESULT_SUCCESS:
//       append_address_to_userdata(&address_result, userdata);
//       ipv6_found = true;
//       break;

//     case MDNS_RESOLVE_RESULT_HOST_NOT_FOUND:
//       break;

//     case MDNS_RESOLVE_RESULT_UNAVAIL:
//       // Something went wrong, just fail.
//       return MDNS_RESOLVE_RESULT_UNAVAIL;
//     }
//   }

//   if (ipv4_found || ipv6_found)
//   {
//     return MDNS_RESOLVE_RESULT_SUCCESS;
//   }
//   else
//   {
//     return MDNS_RESOLVE_RESULT_HOST_NOT_FOUND;
//   }
// }

static enum nss_status gethostbyname_impl(
    const char *name,
    int af,
    struct userdata_t *u,
    int *errnop,
    int *h_errnop,
    uint32_t *ttlp)
{

#ifdef NSS_IPV4_ONLY
  if (af == AF_UNSPEC)
  {
    af = AF_INET;
  }
#endif

#ifdef NSS_IPV6_ONLY
  if (af == AF_UNSPEC)
  {
    af = AF_INET6;
  }
#endif

#ifdef NSS_IPV4_ONLY
  if (af != AF_INET)
#elif NSS_IPV6_ONLY
  if (af != AF_INET6)
#else
  if (af != AF_INET && af != AF_INET6 && af != AF_UNSPEC)
#endif
  {
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }

  u->count = 0;
  if (!verify_name_allowed_with_soa(name))
  {
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }

  switch (mdns_resolve_name(af, name, u, ttlp))
  {
  case NSS_STATUS_SUCCESS:
    return NSS_STATUS_SUCCESS;

  case NSS_STATUS_NOTFOUND:
    *errnop = ETIMEDOUT;
    *h_errnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;

  case NSS_STATUS_UNAVAIL:
  default:
    *errnop = ETIMEDOUT;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }
}

enum nss_status _nss_mdns_gethostbyname4_r(
    const char *name,
    struct gaih_addrtuple **pat,
    char *buffer, size_t buflen,
    int *errnop, int *h_errnop,
    int32_t *ttlp)
{

  struct userdata_t u;
  struct buffer_t buf;

  enum nss_status status =
      gethostbyname_impl(name, AF_UNSPEC, &u, errnop, h_errnop, ttlp);
  if (status != NSS_STATUS_SUCCESS)
  {
    return status;
  }
  buffer_init(&buf, buffer, buflen);
  return convert_userdata_to_addrtuple(&u, name, pat, &buf, errnop, h_errnop);
}

enum nss_status _nss_mdns_gethostbyname3_r(
    const char *name, int af,
    struct hostent *result, char *buffer,
    size_t buflen, int *errnop,
    int *h_errnop, int32_t *ttlp,
    char **canonp)
{

  (void)canonp;

  struct buffer_t buf;
  struct userdata_t u;

  // The interfaces for gethostbyname3_r and below do not actually support
  // returning results for more than one address family
  if (af == AF_UNSPEC)
  {
#ifdef NSS_IPV6_ONLY
    af = AF_INET6;
#else
    af = AF_INET;
#endif
  }

  enum nss_status status = gethostbyname_impl(name, af, &u, errnop, h_errnop, ttlp);
  if (status != NSS_STATUS_SUCCESS)
  {
    return status;
  }
  buffer_init(&buf, buffer, buflen);
  return convert_userdata_for_name_to_hostent(&u, name, af, result, &buf,
                                              errnop, h_errnop);
}

enum nss_status _nss_mdns_gethostbyname2_r(
    const char *name, int af,
    struct hostent *result, char *buffer,
    size_t buflen, int *errnop,
    int *h_errnop)
{
  uint32_t ttlp;
  return _nss_mdns_gethostbyname3_r(name, af, result, buffer, buflen, errnop,
                                    h_errnop, &ttlp, NULL);
}

enum nss_status _nss_mdns_gethostbyname_r(
    const char *name,
    struct hostent *result, char *buffer,
    size_t buflen, int *errnop,
    int *h_errnop)
{

  return _nss_mdns_gethostbyname2_r(name, AF_UNSPEC, result, buffer, buflen,
                                    errnop, h_errnop);
}

enum nss_status _nss_mdns_gethostbyaddr_r(
    const void *addr, int len, int af,
    struct hostent *result, char *buffer,
    size_t buflen, int *errnop,
    int *h_errnop)
{

  size_t address_length;
  char t[256];

  /* Check for address types */
  address_length =
      af == AF_INET ? sizeof(struct ipv4_address_t) : sizeof(struct ipv6_address_t);

  if (len < (int)address_length ||
#ifdef NSS_IPV4_ONLY
      af != AF_INET
#elif NSS_IPV6_ONLY
      af != AF_INET6
#else
      (af != AF_INET && af != AF_INET6)
#endif
  )
  {
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }

#ifdef MDNS_MINIMAL
  /* Only query for 169.254.0.0/16 IPv4 in minimal mode */
  if ((af == AF_INET &&
       ((ntohl(*(const uint32_t *)addr) & 0xFFFF0000UL) != 0xA9FE0000UL)) ||
      (af == AF_INET6 && !(((const uint8_t *)addr)[0] == 0xFE &&
                           (((const uint8_t *)addr)[1] >> 6) == 2)))
  {
    *errnop = EINVAL;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }
#endif

  /* Lookup using mDNS */
  struct buffer_t buf;
  switch (mdns_resolve_address(af, addr, t, sizeof(t)))
  {
  case NSS_STATUS_SUCCESS:
    buffer_init(&buf, buffer, buflen);
    return convert_name_and_addr_to_hostent(
        t, addr, address_length, af,
        result, &buf, errnop, h_errnop);

  case NSS_STATUS_NOTFOUND:
    *errnop = ETIMEDOUT;
    *h_errnop = HOST_NOT_FOUND;
    return NSS_STATUS_NOTFOUND;

  case NSS_STATUS_UNAVAIL:
  default:
    *errnop = ETIMEDOUT;
    *h_errnop = NO_RECOVERY;
    return NSS_STATUS_UNAVAIL;
  }
}

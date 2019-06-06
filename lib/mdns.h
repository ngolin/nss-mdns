#ifndef __MDNS_H
#define __MDNS_H
#include <stddef.h>
#include <stdint.h>
#include <nss.h>
#include "util.h"

extern enum nss_status mdns_resolve_name(
    int af,
    const char *name,
    struct userdata_t *userdata,
    int32_t *ttlp);

extern enum nss_status mdns_resolve_address(
    int af,
    const void *data,
    char *name,
    size_t name_len);
#endif
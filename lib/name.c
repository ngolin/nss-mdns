#include <stdbool.h>
#include <resolv.h>
#include <stddef.h>
#include <string.h>
#include <netdb.h>
#include "name.h"

static bool endswith(const char *name, const char *suffix)
{
  size_t ln = strlen(name), ls = strlen(suffix);
  return ln > ls && strcasecmp(name + ln - ls, suffix) == 0;
}

static bool not_local_soa(void)
{
  unsigned char answer[NS_MAXMSG];
  struct __res_state state;
  int result;

  result = res_ninit(&state);
  if (result == -1)
  {
    return true;
  }
  result = res_nquery(&state, "local", ns_c_in, ns_t_soa, answer, sizeof(answer));
  res_nclose(&state);
  return result < 1;
}

static bool contains_dot(const char *name)
{
  for (size_t i = 0; i < strlen(name) - 1; i++)
  {
    if (name[i] == '.')
    {
      return true;
    }
  }
  return false;
}

bool verify_name_allowed_with_soa(const char *name)
{
  size_t len = strlen(name);
  if (0 < len && len < NI_MAXHOST && (endswith(name, ".local") || endswith(name, ".local.")))
  {
    return contains_dot(name) && not_local_soa();
  }

  return 0;
}

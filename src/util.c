#include "util.h"
#include <stdio.h>

BOOL library_name_is_api_set(const char *name) {
  return strnicmp(name, "api-", 4) == 0;
}

char *resolve_api_set_to_dll(const char *api_set_name) {
  if (strstr(api_set_name, "-crt-")) {
    return "ucrtbase.dll";
  } else {
    fprintf(stderr, "[!] Unknown API set %s.\n", api_set_name);
    exit(1);
  }
}

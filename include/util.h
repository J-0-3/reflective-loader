#pragma once
#include <windows.h>

BOOL library_name_is_api_set(const char *name);
char *resolve_api_set_to_dll(const char *api_set_name);

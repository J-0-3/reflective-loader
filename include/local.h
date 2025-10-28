#pragma once
#include <windows.h>

HANDLE reflective_load(void *dll);
FARPROC get_proc_address(HANDLE module, const char *name);

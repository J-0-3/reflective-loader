#pragma once
#include <windows.h>

ULONGLONG reflective_load_remote(HANDLE process, void *dll);
ULONGLONG get_proc_address_remote(HANDLE process, ULONGLONG remote_module,
                                  const char *name);

#include "local.h"
#include "remote.h"
#include <stdio.h>

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "[!] Usage: %s <library> <function> <pid?>", argv[0]);
    exit(1);
  }
  FILE *f = fopen(argv[1], "rb");
  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  char *buf = VirtualAlloc(0, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  fclose(f);
  f = fopen(argv[1], "rb");
  fread(buf, 1, size, f);
  if (argc == 3) {
    puts("[.] Reflectively loading into self.\n");
    HANDLE dll = reflective_load(buf);
    printf("[.] Successfully loaded dll at %p\n", dll);
    FARPROC function = get_proc_address(dll, argv[2]);
    if (function == NULL) {
      fprintf(stderr, "[!] Function %s not found in exports.\n", argv[2]);
      exit(1);
    }
    printf("[.] Calling function %s at %p\n", argv[2], function);
    function();
  } else {
    unsigned long pid = 0;
    sscanf(argv[3], "%lu", &pid);
    printf("[.] Injecting into process %lu.\n", pid);
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    ULONGLONG remote_dll = reflective_load_remote(process, buf);
    printf("[.] Successfully loaded dll remotely at %llux\n", remote_dll);
    ULONGLONG function_addr =
        get_proc_address_remote(process, remote_dll, argv[2]);
    if (function_addr == 0) {
      fprintf(stderr, "[!] Function %s not found in remote process.\n",
              argv[2]);
      exit(1);
    }
    printf("[.] Creating remote thread for function %s at %llux\n", argv[2],
           function_addr);
    DWORD thread_id;
    HANDLE thread = CreateRemoteThread(process, NULL, 0,
                                       (LPTHREAD_START_ROUTINE)function_addr,
                                       NULL, 0, &thread_id);
    printf("[.] Waiting for remote thread with ID %lu\n", thread_id);
    WaitForSingleObject(thread, INFINITE);
  }
}

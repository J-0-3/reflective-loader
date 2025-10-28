#include "remote.h"
#include "util.h"
#include <psapi.h>
#include <stdio.h>

char *strcpy_from_remote(HANDLE process, ULONGLONG address) {
  int buf_size = 128;
  while (1) {
    char *buf =
        VirtualAlloc(0, buf_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memset(buf, 0, buf_size);
    SIZE_T size_read = 0;
    ReadProcessMemory(process, (void *)address, buf, buf_size, &size_read);
    if (memchr(buf, 0, buf_size)) {
      return buf;
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    buf_size += 128;
  }
}

ULONGLONG remote_load_library(HANDLE process, char *library) {
  HMODULE remote_modules[1024] = {0};
  DWORD needed = 0;
  char dll_name[MAX_PATH];
  char *remote_library_name =
      VirtualAllocEx(process, 0, strlen(library) + 1, MEM_COMMIT | MEM_RESERVE,
                     PAGE_READWRITE);
  SIZE_T size_written = 0;
  WriteProcessMemory(process, remote_library_name, library, strlen(library) + 1,
                     &size_written);
  EnumProcessModules(process, remote_modules, sizeof(remote_modules), &needed);
  FARPROC load_library_remote;
  for (DWORD i = 0; i < 1024; i++) {
    if (remote_modules[i] == NULL) {
      continue;
    }
    GetModuleFileNameExA(process, remote_modules[i], dll_name,
                         (DWORD)sizeof(dll_name));
    for (int i = 0; i < strlen(dll_name); i++) {
      dll_name[i] = tolower((unsigned char)dll_name[i]);
    }
    if (strstr(dll_name, "kernel32.dll")) {
      HMODULE local_kernel32 = LoadLibraryA(dll_name);
      FARPROC load_library_local =
          GetProcAddress(local_kernel32, "LoadLibraryA");
      load_library_remote =
          (FARPROC)((uintptr_t)load_library_local - (uintptr_t)local_kernel32 +
                    (uintptr_t)remote_modules[i]);
      break;
    }
  }
  DWORD thread_id;
  HANDLE thread_handle = CreateRemoteThread(
      process, NULL, 1000, (LPTHREAD_START_ROUTINE)load_library_remote,
      remote_library_name, 0, &thread_id);
  WaitForSingleObject(thread_handle, INFINITE);
  needed = 0;
  EnumProcessModules(process, remote_modules, sizeof(remote_modules), &needed);
  for (DWORD i = 0; i < 1024; i++) {
    if (remote_modules[i] == NULL) {
      continue;
    }
    GetModuleFileNameExA(process, remote_modules[i], dll_name,
                         (DWORD)sizeof(dll_name));
    for (int i = 0; i < strlen(dll_name); i++) {
      dll_name[i] = tolower((unsigned char)dll_name[i]);
    }
    char library_lower[strlen(library) + 1];
    memset(library_lower, 0, strlen(library) + 1);
    strcpy(library_lower, library);
    for (int i = 0; i < strlen(library_lower); i++) {
      library_lower[i] = tolower((unsigned char)library_lower[i]);
    }

    if (strstr(dll_name, library_lower)) {
      return (ULONGLONG)remote_modules[i];
    }
  }
  return 0;
}

ULONGLONG get_proc_address_remote(HANDLE process, ULONGLONG remote_module,
                                  const char *function) {
  IMAGE_DOS_HEADER dos_header;
  SIZE_T size_read = 0;
  ReadProcessMemory(process, (void *)remote_module, &dos_header,
                    sizeof(IMAGE_DOS_HEADER), &size_read);
  IMAGE_NT_HEADERS64 nt_headers;
  size_read = 0;
  ReadProcessMemory(process, (void *)remote_module + dos_header.e_lfanew,
                    &nt_headers, sizeof(IMAGE_NT_HEADERS64), &size_read);
  IMAGE_EXPORT_DIRECTORY export_table;
  size_read = 0;
  ReadProcessMemory(
      process,
      (void *)remote_module +
          nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
              .VirtualAddress,
      &export_table, sizeof(IMAGE_EXPORT_DIRECTORY), &size_read);
  DWORD export_names[export_table.NumberOfNames];
  memset(export_names, 0, export_table.NumberOfNames * sizeof(DWORD));
  size_read = 0;
  ReadProcessMemory(
      process, (void *)remote_module + export_table.AddressOfNames,
      &export_names, export_table.NumberOfNames * sizeof(DWORD), &size_read);
  INT64 function_export_name_ordinal_index = -1;
  for (int i = 0; i < export_table.NumberOfNames; i++) {
    char *name = strcpy_from_remote(process, remote_module + export_names[i]);
    if (stricmp(name, function) == 0) {
      function_export_name_ordinal_index = i;
      VirtualFree(name, 0, MEM_RELEASE);
      break;
    }
    VirtualFree(name, 0, MEM_RELEASE);
  }
  if (function_export_name_ordinal_index == -1) {
    return 0;
  }
  WORD export_ordinals[export_table.NumberOfNames];
  memset(export_ordinals, 0, export_table.NumberOfNames * sizeof(WORD));
  size_read = 0;
  ReadProcessMemory(
      process, (void *)remote_module + export_table.AddressOfNameOrdinals,
      &export_ordinals, export_table.NumberOfNames * sizeof(WORD), &size_read);
  WORD function_export_ordinal =
      export_ordinals[function_export_name_ordinal_index];
  DWORD export_functions[export_table.NumberOfFunctions];
  memset(export_functions, 0, export_table.NumberOfFunctions * sizeof(DWORD));
  size_read = 0;
  ReadProcessMemory(process,
                    (void *)remote_module + export_table.AddressOfFunctions,
                    &export_functions,
                    export_table.NumberOfFunctions * sizeof(DWORD), &size_read);
  return remote_module + export_functions[function_export_name_ordinal_index];
}

void process_relocations_remote(HANDLE process, ULONGLONG dll_memory,
                                IMAGE_NT_HEADERS64 *pe_header) {
  ULONGLONG delta = dll_memory - pe_header->OptionalHeader.ImageBase;
  if (delta == 0) {
    printf("[.] DLL is loaded at preferred base, no relocations required\n");
    return;
  }
  IMAGE_DATA_DIRECTORY relocation_directory =
      pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  IMAGE_BASE_RELOCATION *relocation_table = VirtualAlloc(
      0, relocation_directory.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  SIZE_T size_read = 0;
  ReadProcessMemory(process,
                    (void *)dll_memory + relocation_directory.VirtualAddress,
                    relocation_table, relocation_directory.Size, &size_read);
  IMAGE_BASE_RELOCATION *current_block = relocation_table;
  while (current_block->SizeOfBlock > 0) {
    unsigned long number_of_relocations =
        (current_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(WORD);
    WORD *relocation_entry = (WORD *)(current_block + 1);
    for (int i = 0; i < number_of_relocations; i++) {
      WORD entry = *relocation_entry;
      BYTE reloc_type = (entry & 0xf000) >> 12;
      WORD offset = entry & 0xfff;
      if (reloc_type == IMAGE_REL_BASED_DIR64) {
        ULONGLONG address = 0;
        ReadProcessMemory(process,
                          (void *)dll_memory + current_block->VirtualAddress +
                              offset,
                          &address, sizeof(ULONGLONG), &size_read);
        address += delta;
        WriteProcessMemory(process,
                           (void *)dll_memory + current_block->VirtualAddress +
                               offset,
                           &address, sizeof(ULONGLONG), &size_read);
      } else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
        // skip
      } else {
        perror("[!] Unrecognised relocation type.\n");
        exit(1);
      }
      relocation_entry++;
    }
    current_block = (void *)current_block + current_block->SizeOfBlock;
  }
}

void resolve_iat_imports_remote(HANDLE process, ULONGLONG mapped_dll,
                                IMAGE_NT_HEADERS64 *pe_header) {
  IMAGE_DATA_DIRECTORY import_directory =
      pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  IMAGE_IMPORT_DESCRIPTOR import_descriptor;
  SIZE_T size_read = 0;
  ReadProcessMemory(
      process, (void *)mapped_dll + import_directory.VirtualAddress,
      &import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), &size_read);
  int i = 0;
  while (import_descriptor.Name != 0) {
    char *name =
        strcpy_from_remote(process, mapped_dll + import_descriptor.Name);
    if (library_name_is_api_set(name)) {
      printf("[.] Need to load API set: %s ", name);
      name = resolve_api_set_to_dll(name);
      printf("(actually dll: %s)\n", name);
    } else {
      printf("Need to load dll: %s\n", name);
    }
    ULONGLONG remote_module = remote_load_library(process, name);
    printf("[.] dll %s is located at %llux\n", name, remote_module);
    if (remote_module == 0) {
      fprintf(stderr, "[!] Failed to remotely load module %s.\n", name);
      exit(1);
    }
    VirtualFree(name, 0, MEM_RELEASE);
    size_read = 0;
    IMAGE_THUNK_DATA ilt_entry;
    for (int j = 0;; j++) {
      if (import_descriptor.OriginalFirstThunk != 0) {
        ReadProcessMemory(process,
                          (void *)mapped_dll +
                              import_descriptor.OriginalFirstThunk +
                              j * sizeof(IMAGE_THUNK_DATA),
                          &ilt_entry, sizeof(IMAGE_THUNK_DATA), &size_read);
      } else {
        ReadProcessMemory(process,
                          (void *)mapped_dll + import_descriptor.FirstThunk +
                              j * sizeof(IMAGE_THUNK_DATA),
                          &ilt_entry, sizeof(IMAGE_THUNK_DATA), &size_read);
      }
      if (ilt_entry.u1.AddressOfData == 0) {
        break;
      }
      ULONGLONG func_address;
      if (ilt_entry.u1.AddressOfData & IMAGE_ORDINAL_FLAG64) {
        unsigned short ordinal = ilt_entry.u1.AddressOfData & 0xFFFF;
        perror("Cannot get remote function address by ordinal...\n");
      } else {
        char *function_name = strcpy_from_remote(
            process, mapped_dll + ilt_entry.u1.AddressOfData + sizeof(WORD));
        printf("Need to resolve function: %s\n", function_name);
        func_address =
            get_proc_address_remote(process, remote_module, function_name);
        if (func_address == 0) {
          fprintf(stderr, "[!] Failed to resolve function %s.\n",
                  function_name);
          exit(1);
        }
      }
      WriteProcessMemory(process,
                         (void *)mapped_dll + import_descriptor.FirstThunk +
                             j * sizeof(void *),
                         &func_address, sizeof(ULONGLONG), &size_read);
    }
    ReadProcessMemory(process,
                      (void *)mapped_dll + import_directory.VirtualAddress +
                          sizeof(IMAGE_IMPORT_DESCRIPTOR) * ++i,
                      &import_descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR),
                      &size_read);
  }
}

void copy_image_sections_remote(HANDLE process, ULONGLONG mapped_dll_memory,
                                void *raw_dll, IMAGE_NT_HEADERS *pe_header) {
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe_header);
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER section = sections[i];
    SIZE_T size_written;
    if (section.SizeOfRawData == 0) {
      continue;
    }
    WriteProcessMemory(process,
                       (void *)mapped_dll_memory + section.VirtualAddress,
                       raw_dll + section.PointerToRawData,
                       section.SizeOfRawData, &size_written);
    if (section.Misc.VirtualSize > section.SizeOfRawData) {
      void *buf =
          VirtualAlloc(0, section.Misc.VirtualSize - section.SizeOfRawData,
                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
      memset(buf, 0, section.Misc.VirtualSize - section.SizeOfRawData);
      WriteProcessMemory(process,
                         (void *)mapped_dll_memory + section.VirtualAddress +
                             section.Misc.VirtualSize,
                         buf, section.Misc.VirtualSize - section.SizeOfRawData,
                         &size_written);
      VirtualFree(buf, 0, MEM_RELEASE);
    }
  }
}

ULONGLONG reflective_load_remote(HANDLE process, void *dll) {
  IMAGE_NT_HEADERS64 *pe_header =
      ((void *)dll) + ((IMAGE_DOS_HEADER *)dll)->e_lfanew;
  ULONGLONG dll_memory = (ULONGLONG)VirtualAllocEx(
      process, 0, pe_header->OptionalHeader.SizeOfImage,
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  SIZE_T written = 0;
  WriteProcessMemory(process, (void *)dll_memory, dll,
                     pe_header->OptionalHeader.SizeOfHeaders, &written);
  copy_image_sections_remote(process, dll_memory, dll, pe_header);
  resolve_iat_imports_remote(process, dll_memory, pe_header);
  process_relocations_remote(process, dll_memory, pe_header);
  return dll_memory;
}

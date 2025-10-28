#include "local.h"
#include "util.h"
#include <stdio.h>

void copy_image_sections(void *mapped_dll_memory, void *raw_dll,
                         IMAGE_NT_HEADERS *pe_header) {
  IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(pe_header);
  for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++) {
    IMAGE_SECTION_HEADER section = sections[i];
    if (section.SizeOfRawData == 0) {
      continue;
    }
    memcpy(mapped_dll_memory + section.VirtualAddress,
           raw_dll + section.PointerToRawData, section.SizeOfRawData);
    if (section.Misc.VirtualSize > section.SizeOfRawData) {
      memset(mapped_dll_memory + section.VirtualAddress +
                 section.Misc.VirtualSize,
             0, section.Misc.VirtualSize - section.SizeOfRawData);
    }
  }
}

void resolve_iat_imports(void *mapped_dll, IMAGE_NT_HEADERS64 *pe_header) {
  IMAGE_DATA_DIRECTORY import_directory =
      pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  IMAGE_IMPORT_DESCRIPTOR *import_descriptor =
      mapped_dll + import_directory.VirtualAddress;
  while (import_descriptor->Name != 0) {
    char *name = mapped_dll + import_descriptor->Name;
    if (library_name_is_api_set(name)) {
      printf("[.] Need to load API set: %s ", name);
      name = resolve_api_set_to_dll(name);
      printf("(actually dll: %s)\n", name);
    } else {
      printf("Need to load dll: %s\n", name);
    }
    HANDLE module = LoadLibraryA(name);
    if (module == NULL) {
      fprintf(stderr, "[!] Failed to load module %s.\n", name);
      exit(1);
    }
    IMAGE_THUNK_DATA *iat = mapped_dll + import_descriptor->FirstThunk;
    IMAGE_THUNK_DATA *ilt;
    if (import_descriptor->OriginalFirstThunk != 0) {
      ilt = mapped_dll + import_descriptor->OriginalFirstThunk;
    } else {
      ilt = iat;
    }
    for (int i = 0;; i++) {
      IMAGE_THUNK_DATA *ilt_entry = &ilt[i];
      IMAGE_THUNK_DATA *iat_entry = &iat[i];
      if (ilt_entry->u1.AddressOfData == 0) {
        break;
      }
      FARPROC func_address;
      if (ilt_entry->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) {
        unsigned short ordinal = ilt_entry->u1.AddressOfData & 0xFFFF;
        func_address = GetProcAddress(module, (LPCSTR)(ULONGLONG)ordinal);
      } else {
        IMAGE_IMPORT_BY_NAME *function_name =
            mapped_dll + ilt_entry->u1.AddressOfData;
        printf("Need to resolve function: %s\n", function_name->Name);
        func_address = GetProcAddress(module, function_name->Name);
        printf("[DEBUG] function %s is at %p\n", function_name->Name,
               func_address);
        if (func_address == NULL) {
          fprintf(stderr, "[!] Failed to resolve function %s.\n",
                  function_name->Name);
          exit(1);
        }
      }
      iat_entry->u1.AddressOfData = (ULONGLONG)func_address;
    }
    import_descriptor++;
  }
}

void process_relocations(void *mapped_dll_memory,
                         IMAGE_NT_HEADERS64 *pe_header) {
  ULONGLONG delta =
      (ULONGLONG)mapped_dll_memory - pe_header->OptionalHeader.ImageBase;
  if (delta == 0) {
    printf("DLL is loaded at preferred base, no relocations required\n");
    return;
  }
  IMAGE_DATA_DIRECTORY relocation_directory =
      pe_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  IMAGE_BASE_RELOCATION *relocation_table_start =
      (IMAGE_BASE_RELOCATION *)(mapped_dll_memory +
                                relocation_directory.VirtualAddress);
  IMAGE_BASE_RELOCATION *current_block = relocation_table_start;
  while (current_block->SizeOfBlock > 0) {
    unsigned long number_of_relocations =
        (current_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
        sizeof(WORD);
    WORD *relocation_entry =
        (WORD *)(current_block + 1); // immediately after block header
    for (int i = 0; i < number_of_relocations; i++) {
      WORD entry = *relocation_entry;
      BYTE reloc_type = (entry & 0xf000) >> 12;
      WORD offset = entry & 0xfff;
      if (reloc_type == IMAGE_REL_BASED_DIR64) {
        ULONGLONG *target =
            (ULONGLONG *)(mapped_dll_memory + current_block->VirtualAddress +
                          offset);
        *target += delta;
      } else if (reloc_type == IMAGE_REL_BASED_ABSOLUTE) {
        // skip
      } else {
        perror("Unrecognised relocation type.\n");
        exit(1);
      }
      relocation_entry++;
    }
    current_block = (void *)current_block + current_block->SizeOfBlock;
  }
}

HANDLE reflective_load(void *dll) {
  IMAGE_NT_HEADERS64 *pe_header =
      ((void *)dll) + ((IMAGE_DOS_HEADER *)dll)->e_lfanew;
  void *dll_memory =
      VirtualAlloc(0, pe_header->OptionalHeader.SizeOfImage,
                   MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  memcpy(dll_memory, dll, pe_header->OptionalHeader.SizeOfHeaders);
  copy_image_sections(dll_memory, dll, pe_header);
  resolve_iat_imports(dll_memory, pe_header);
  process_relocations(dll_memory, pe_header);
  return dll_memory;
}

FARPROC get_proc_address(HANDLE module, const char *function) {
  IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)module;
  IMAGE_NT_HEADERS64 *nt_headers = module + dos_header->e_lfanew;
  IMAGE_EXPORT_DIRECTORY *export_table =
      module +
      nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
          .VirtualAddress;
  DWORD *export_names = module + export_table->AddressOfNames;
  INT64 function_export_name_ordinal_index = -1;
  for (int i = 0; i < export_table->NumberOfNames; i++) {
    const char *name = module + export_names[i];
    if (stricmp(name, function) == 0) {
      function_export_name_ordinal_index = i;
      break;
    }
  }
  if (function_export_name_ordinal_index == -1) {
    return NULL;
  }
  WORD *export_ordinals = module + export_table->AddressOfNameOrdinals;
  WORD function_export_ordinal =
      export_ordinals[function_export_name_ordinal_index];
  DWORD *export_functions = module + export_table->AddressOfFunctions;
  return (FARPROC)((BYTE *)module + export_functions[function_export_ordinal]);
}

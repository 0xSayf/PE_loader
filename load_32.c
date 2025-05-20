#include "include.h"
#include <stdbool.h>

void    ft_load_32(char *ptr)
{
    DWORD elfanew;
    DWORD size_of_headers;
    char *func_name;
    DWORD size_of_image;
    DWORD entrypoint;
    DWORD raw_size;
    WORD  num_of_sections;
    unsigned int section_RVA;
    WORD ordinal;
    void *address_fun;
    char *image_base;
    DWORD   VA_import;

    elfanew = *(DWORD *)(ptr + 0x3C);
    size_of_image = *(DWORD *)(ptr + elfanew + 0x50);
    size_of_headers = *(DWORD *)(ptr + elfanew + 0x54);
    entrypoint = *(DWORD*)(ptr + elfanew + 0x28);
    num_of_sections = *(WORD *)(ptr + elfanew + 0x6);
    VA_import = *(DWORD *)(ptr + elfanew + 0x80);
    image_base = VirtualAlloc(NULL,size_of_image, 0x00002000 | 0x00001000, 0x40);
    if(!image_base)
        exit(1);
    /*Load all headers from the Dos to NT_header*/
    
    memcpy(image_base, ptr , size_of_headers);
    
    /* load all sections*/

    WORD size_of_optional_header = *(WORD*)(ptr + elfanew + 0x14);
    section_RVA = elfanew + 0x18 + size_of_optional_header;
    int i = 0;
    while  ( i < num_of_sections) 
    {
        DWORD virtual_address = *(DWORD*)(ptr + section_RVA + 0x0C);
        DWORD raw_address   = *(DWORD*)(ptr + section_RVA + 0x14);  
        raw_size      = *(DWORD*)(ptr + section_RVA + 0x10);  
        memcpy(image_base + virtual_address, ptr + raw_address, raw_size);
        section_RVA += 40;
        i++;
    }

    /*Resolve IAT(import address table) each imported function 
    with his address from the DLL */
    
    IMAGE_IMPORT_DESCRIPTOR* import_dir = (IMAGE_IMPORT_DESCRIPTOR*) (image_base +  VA_import);
     i = 0;
    while (import_dir[i].OriginalFirstThunk != 0 || import_dir[i].FirstThunk != 0)
    {
        BYTE *name_dll = image_base + import_dir[i].Name;
        HMODULE dll_load = LoadLibraryA(name_dll);
        if(!dll_load)
            return ;
        IMAGE_THUNK_DATA32 *ILT32 = (IMAGE_THUNK_DATA32 *) (image_base + import_dir[i].OriginalFirstThunk);
        IMAGE_THUNK_DATA32 *IAT32 = (IMAGE_THUNK_DATA32 *) (image_base + import_dir[i].FirstThunk);
        int j = 0;
        while (ILT32[j].u1.AddressOfData != 0)
        {
            if(ILT32[j].u1.Ordinal & 0x80000000)
            {
                ordinal = (WORD)(ILT32[j].u1.Ordinal & 0xFFFF);
                address_fun = (void *)GetProcAddress(dll_load,(LPCSTR)ordinal);
            }
            else
            {
                IMAGE_IMPORT_BY_NAME *HINT_NAME = (IMAGE_IMPORT_BY_NAME *) (image_base + ILT32[j].u1.AddressOfData);
                func_name =  (char*) HINT_NAME->Name;
                address_fun = (void *)GetProcAddress(dll_load,func_name);
            }
            IAT32[j].u1.Function = (DWORD) address_fun;
            j++;
        } 
        i++;
    }
    /*Loading the Basereloc (.reloc)*/

    DWORD delta = (DWORD)image_base - (*(DWORD *)(ptr + 0x34));
    DWORD   reloc_va = *(DWORD *)(ptr + elfanew + 0xA0);
    if(reloc_va && delta)
    {
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)(image_base + *(DWORD *)(ptr + elfanew + 0xA0));
        while (reloc->VirtualAddress != 0)
        {
            unsigned int num_of_entry = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            WORD* offset = (WORD*) (reloc + 1);
            int i = 0;
            while (i < num_of_entry)
            {
                int type = offset[i] >> 12;
                int off_rv = offset[i] & 0x0fff;
                DWORD *ch_address =  (DWORD*) (image_base + reloc->VirtualAddress + off_rv);
               if (type == IMAGE_REL_BASED_HIGHLOW) 
                    *ch_address += delta;
                i++;
            }
            reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
        }
        
    }

    /* Setting permissions for headers and for each section*/
    
    DWORD oldprotect ;
    DWORD  protect = 0;
    VirtualProtect(image_base, size_of_headers, 0x02, &oldprotect);
    i = 0;
        section_RVA = elfanew + 0x18 + size_of_optional_header;
    while (i < num_of_sections)
    {
        DWORD   Characteristics = *(DWORD*)(ptr + section_RVA + 0x24);
        char *section_addr = image_base + *(DWORD*)(ptr + section_RVA + 0xC);
        raw_size      = *(DWORD*)(ptr + section_RVA + 0x10);
        bool    EXEc = Characteristics & IMAGE_SCN_MEM_EXECUTE;
        bool    readix = Characteristics & IMAGE_SCN_MEM_READ;
        bool    writex = Characteristics & IMAGE_SCN_MEM_WRITE;
        if (EXEc) {
            if (writex)
                protect = PAGE_EXECUTE_READWRITE;
            else if (readix)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        } else {
            if (writex)
                protect = PAGE_READWRITE;
            else if (readix)
                protect = PAGE_READONLY;
        }
        VirtualProtect(section_addr,raw_size , protect, &oldprotect);
        section_RVA += 40;
        i++;
    }
    printf("fdfds\n");
    void (*entry)() = (void (*)())(image_base + entrypoint);
    entry();
}
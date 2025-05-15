#include "include.h"

void    ft_load_32(char *ptr)
{
    DWORD elfanew;
    DWORD size_of_headers;
    DWORD size_of_image;
    DWORD entrypoint;
    WORD  num_of_sections;
    unsigned int section_RVA;
    char *sections_back;
    WORD ordinal;
    DWORD    ILT_BY_NAME;
    ILT_CUST_32 *RVA_ILT;
    char *image_base;
    BYTE flag;
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
    section_RVA = elfanew + 0xF8;
    int i = 0;
    while  ( i < num_of_sections) 
    {
        DWORD virtual_address   = *(DWORD*)(ptr + section_RVA + 0x0C);
        DWORD raw_address       = *(DWORD*)(ptr + section_RVA + 0x14);  
        DWORD raw_size          = *(DWORD*)(ptr + section_RVA + 0x10);  
        memcpy(image_base + virtual_address, ptr + raw_address, raw_size);
        section_RVA += 40;
        i++;
    }

    /*Resolve IAT(import address table) each imported function 
    with his address from the DLL */
    
    IMAGE_IMPORT_DESCRIPTOR* import_dir = (IMAGE_IMPORT_DESCRIPTOR*) (image_base +  VA_import);
     i = 0;
    while (import_dir[i].OriginalFirstThunk != 0)
    {
        BYTE *name_dll = image_base + import_dir[i].Name;
        printf("%s\n", name_dll);
        HMODULE dll_load = LoadLibraryA(name_dll);
        if(!dll_load)
            return ;
        IMAGE_THUNK_DATA32 *ILT32 = (IMAGE_THUNK_DATA32 *) image_base + import_dir[i].OriginalFirstThunk;
        IMAGE_THUNK_DATA32 *IAT32 = (IMAGE_THUNK_DATA32 *) image_base + import_dir[i].FirstThunk;
        int j = 0;
        while (ILT32[j].u1.AddressOfData != 0)
        {
            RVA_ILT = (ILT_CUST_32 *)ILT32[j].u1.AddressOfData;
            flag = RVA_ILT->myaw.flag;
            if(flag == 0x01)
                ordinal = RVA_ILT->myaw.ordinal;
            else if(flag == 0x0)
                ILT_BY_NAME = RVA_ILT->myaw.RVA_by_NAME;
            if(flag == 0x0)
            {
                IMAGE_IMPORT_BY_NAME *HINT_NAME = (IMAGE_IMPORT_BY_NAME *) image_base + ILT_BY_NAME;
                char *func_name =  (char*) HINT_NAME->Name;
            }
            j++;
        } 
        i++;
    }
    void (*entry)() = (void (*)())(image_base + entrypoint);
    entry();
}
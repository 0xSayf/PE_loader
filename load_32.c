#include "include.h"

void    ft_load_32(char *ptr)
{
    DWORD elfanew;
    DWORD size_of_headers;
    DWORD size_of_image;
    DWORD entrypoint;
    WORD  num_of_sections;
    char  *import_dir_table;
    unsigned int section_RVA;
    char *sections_back;
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
    section_RVA = elfanew + 0xF8;
    int i = 0;
    while (i < num_of_sections)
    {
        sections_back = image_base + *(DWORD*)(ptr + section_RVA + 0x14);
        memcpy(sections_back, ptr + *(DWORD*)(ptr + section_RVA + 0x14) ,*(DWORD*)(ptr + section_RVA + 0x10));
        section_RVA += 40;
        i++;
    }

    /*Resolve IAT(import address table) each imported function 
    with his address from the DLL */
    
    IMAGE_IMPORT_DESCRIPTOR* import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*) (image_base + *(DWORD *)(ptr + VA_import));

    void (*entry)() = (void (*)())(image_base + entrypoint);
    entry();
}
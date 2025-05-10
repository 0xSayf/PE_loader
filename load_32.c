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
    char *image_base;

    elfanew = *(DWORD *)(ptr + 0x3C);
    size_of_image = *(DWORD *)(ptr + elfanew + 0x50);
    size_of_headers = *(DWORD *)(ptr + elfanew + 0x54);
    entrypoint = *(DWORD*)(ptr + elfanew + 0x28);
    num_of_sections = *(WORD *)(ptr + elfanew + 0x6);
    image_base = VirtualAlloc(NULL,size_of_image, 0x00002000 | 0x00001000, 0x40);
    if(!image_base)
        exit(1);
    memcpy(image_base, ptr , size_of_headers);
    section_RVA = elfanew + 0xF8;
    int i = 0;
    while (i < num_of_sections)
    {
        sections_back = image_base + *(DWORD*)(section_RVA + 12);
        memcpy(sections_back, ptr + section_RVA + 0x14 , section_RVA + 0x10);
        section_RVA += 40;
        i++;
    }
    void (*entry)() = (void (*)())(image_base + entrypoint);
    entry();
}
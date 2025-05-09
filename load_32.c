#include "include.h"

void    ft_load_32(char *ptr)
{
    DWORD elfanew;
    DWORD size_of_headers;
    DWORD size_of_image;
    char *image_base;

    elfanew = *(DWORD *)(ptr + 0x3C);
    size_of_image = *(WORD *)(ptr + elfanew + 0x50);
    image_base = VirtualAlloc(NULL,size_of_image,0x00002000 | 0x00001000, 0x40);
    if(!image_base)
        exit(1);
    size_of_headers = *(DWORD *)(ptr + elfanew + 0x54);
    memcpy(image_base, ptr , size_of_headers);
}
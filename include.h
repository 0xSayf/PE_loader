#ifndef INCLUDE_H
#define INCLUDE_H

#include <stdio.h>
#include <windows.h>

void    ft_load_32(char *ptr);

typedef struct  _IMAGE_ILT_CUST_32
{
  union
  {
    DWORD flag : 1;
    DWORD ordinal : 16;
    DWORD RVA_by_NAME : 32;
  } myaw;
} ILT_CUST_32;

#endif
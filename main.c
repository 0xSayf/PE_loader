#include "include.h"

WORD ft_checking_arch(char *ptr)
{
    WORD magic_value;
    DWORD elfanew;

    elfanew = *(DWORD *)(ptr + 0x3C);
    magic_value = *(WORD *)(ptr + elfanew + 24);
    return magic_value;
}

int main(int ac, char **av)
{
    FILE *file;
    long int size_of_file_on_disk;
    WORD arch;

    if (ac != 2)
    {
        printf("Syntax : .exe path_to_file\n");
        return 0;
    }
    
    file = fopen(av[1], "rb");
    if (!file)
    {
        printf("Not a PE file :(\n");
        return 0;
    }

    fseek(file, 0L, SEEK_END);
    size_of_file_on_disk = ftell(file);
    if (size_of_file_on_disk == -1)
    {
        fclose(file);
        return 0;
    }
    
    char *ptr = (char*)malloc(size_of_file_on_disk + 1);
    if (!ptr)
    {
        fclose(file);
        return 0;
    }
    rewind(file); 
    fread(ptr, 1, size_of_file_on_disk, file);
    arch = ft_checking_arch(ptr);
    if(arch == 0x10B)
        ft_load_32(ptr);
    else if(arch == 0x20B)
        printf("hhhhhhhhhhhhh\n");
    else
        printf("Not a PE_FILE =)\n");
    fclose(file);
    free(ptr);
    return 0;
}

#include <stdio.h>
#include <Windows.h>
#include <winnt.h>

// void detect_arch()
// {
//     __asm
//     {
//             mov eax, esp
//             push 0
//             sub eax, esp
//             pop ecx
//             cmp eax, 8
//             je is_64bit

//         is_32bit:
//             mov pointer , 4
//             jmp end_label

//         is_64bit:
//             mov pointer , 8
//             jmp end_label

//         end_label:
//     }
// }

int main(int ac, char **av)
{
    FILE *file;
    long int size_of_file_on_disk;

    // detect_arch();
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
        printf("Memory allocation failed.\n");
        return 0;
    }
    rewind(file); 
    fread(ptr, 1, size_of_file_on_disk, file);
    
    fclose(file);
    free(ptr);
    return 0;
}

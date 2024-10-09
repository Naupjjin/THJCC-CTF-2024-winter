#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void print_slime() {
    printf("==========================================\n");
    printf("**************SlimeLoverNaup**************\n");
    printf("==========================================\n");
    printf("                ██████████                \n");
    printf("        ████████░░░░░░░░░░████████        \n");
    printf("      ██░░░░░░░░░░░░░░░░░░░░░░░░░░██      \n");
    printf("    ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██    \n");
    printf("  ██░░░░░░░░░░░░░░░░░░            ░░██    \n");
    printf("  ██░░░░░░░░░░░░░░                  ░░██  \n");
    printf("██░░░░░░░░░░                        ░░░░██\n");
    printf("██░░░░░░░░░░                        ░░░░██\n");
    printf("██░░░░░░░░░░        ██        ██      ░░██\n");
    printf("██░░░░░░░░          ██        ██      ░░██\n");
    printf("██░░░░░░░░          ██        ██      ░░██\n");
    printf("██░░░░░░░░                            ░░██\n");
    printf("██░░░░░░░░░░                          ░░██\n");
    printf("██░░░░░░░░░░░░                        ░░██\n");
    printf("██░░░░░░░░░░░░░░                      ░░██\n");
    printf("██░░░░░░░░░░░░░░░░░░                ░░░░██\n");
    printf("████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████\n");
    printf("    ██████████████████████████████████    \n");
    printf("==========================================\n");
}

int main() {
    void *place;
    int slime_core;
    char your_input[16];

    print_slime();
    
    slime_core = open("flag", O_RDONLY);
    if (slime_core < 0) {
        printf("Slime core not found, the wrong slime!\n");
        exit(0);
    }

    place = malloc(0x100);
    read(slime_core, place, 0x100);
    printf("Here is your slime core address: %p\n", place);
    printf("Do you accept the slime's embrace?");
    gets(your_input);
    printf("Great!!! Time for Project Sekai, goodbye~\n");

    return 0;
}

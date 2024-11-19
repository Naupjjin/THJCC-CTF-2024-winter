#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    void *stage;
    int AVEmujica;
    char your_input[16];

    AVEmujica = open("./flag", O_RDONLY);
    printf("=====================================================\n");
    printf("…ようこそ。Ave Mujica の世界へ\n");
    printf("=====================================================\n");
    if (AVEmujica < 0) {
        printf("CRYCHIC Funeral\n");
        exit(0);
    }

    stage = malloc(0x100);
    read(AVEmujica, stage, 0x100);
    printf("Where is AVE Mujica: %p\n", stage);
    printf("呪縛なの？\n救済なの？ ");
    gets(your_input);
    printf("Ave Musica…戻れない所まで\n");

    return 0;
}

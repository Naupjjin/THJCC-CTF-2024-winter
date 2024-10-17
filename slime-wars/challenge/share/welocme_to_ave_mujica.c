#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void print_Sakiko() {
    FILE *file;
    char line[0x100];  


    file = fopen("ave_mujica.txt", "r");

    if (file == NULL) {
        printf("CRYCHIC Funeral\n");
        return 1;
    }

    while (fgets(line, sizeof(line), file)) {
        printf("%s", line);
    }
    fclose(file);
}

int main() {
    void *stage;
    int AVEmujica;
    char your_input[16];

    print_Sakiko();
    
    AVEmujica = open("flag", O_RDONLY);
    if (AVEmujica < 0) {
        printf("…ようこそ。Ave Mujica の世界へ\n");
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

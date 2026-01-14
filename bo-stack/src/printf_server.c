#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<stdbool.h>

int main(int argc, char** argv);
const int secret1 = 0xABCD1234;
char* flag = "flag{this_is_a_fake_flag}";

void dump_self_map() {
    char cmd[256];
    sprintf(cmd, "cat /proc/%d/maps", getpid());
    system(cmd);
    printf("main is at %p\n", main);
}

void show_flag(const char flag_id) {
    char flag[256];
    char fname[256];
    sprintf(fname, "flag%c.txt", flag_id);
    FILE* f = fopen(fname, "r");
    if (f == NULL) {
        printf("Flag file is missing\n");
        exit(1);
    }
    fgets(flag, 256, f);
    fclose(f);
    printf("You got a flag: %s\n", flag);
}

void process() {
    unsigned int secret0 = 0xDEADBEEF;
    int* aux = &secret0;
    char buffer[64 + 4 + 1];

    printf("Main is at %p Secret is at %p\n", main, aux);

    int i = 0;
    // Allows buffer overflow
    while(true) {
        if(i == 0){
            memset(buffer, 0, 64 + 4 + 1);
            printf("# ", secret0); // To make it visible in the stack
        }

        char c = getchar();

        // Matches 0xdeadbeef as a little-endian local variable
        if(*(int*) buffer == secret0){
            show_flag('0');
            break;
        }
     
        // Matches 0x1234abcd as a little-endian global variable
        if(*(int*) buffer == secret1){
            show_flag('1');
            break;
        }
        
        // Matches ?\xca\xfe\xba\xbe
        if (buffer[1] == 0xca && buffer[2] == 0xfe && buffer[3] == 0xba && buffer[4] == 0xbe){
            show_flag('2');
            break;
        }

        buffer[i] = c;
        i++;

        if (i >= 4) {
            if(!strncmp(&buffer[i - 4], "end\n", 4)) {
                printf("\n");
                printf(buffer);
                printf("\n");
                i = 0;
                continue;
            }
        }    

        if ( i >= 5) {
            if(!strncmp(&buffer[i - 5], "exit\n", 5)) {
                return;
            }                
        }    
    }
}

void menu() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    printf("\nMenu\n");
    printf("1. Print self map\n");
    printf("2. Receive input\n");
    printf("3. Exit\n\n# ");

    int choice;
    scanf("%d", &choice);

    switch(choice) {
        case 1:
            dump_self_map();
            break;
        case 2:
            process();
            break;
        case 3:
            exit(0);
            break;
        default:
            printf("Invalid choice\n");
    }
}
int main(int argc, char** argv) {
    while(1) {
        menu();
    }
}

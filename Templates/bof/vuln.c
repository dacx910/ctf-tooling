#include <stdio.h>

#if __x86_64__
void gift() {
    __asm__("pop %rdi\nret");
}
#endif

void win(int isWinner) {
    printf("You got to win(), but are you a winner?\n");
    if (isWinner == 0x1337babe) {
        printf("I guess so...\n");
        FILE* file = fopen("flag.txt","r");
        if (file != NULL) {
            char flag[30];
            fread(flag,32,30,file);
            printf("%s\n",flag);
        } else {
            printf("Err: flag.txt not found.");
        }
    } else {
        printf("I guess not...\n");
    }
}

void vuln() {
	char buffer[16];
	scanf("%s", buffer);
	printf("You wrote: %s\n", buffer);
}

int main() {
    printf("> ");
	vuln();

    return 0;
}

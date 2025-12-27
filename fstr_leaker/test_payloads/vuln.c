#include <stdio.h>

int main(int argc, char* argv[], char* envp[]) {
	char buffer[1024];
	printf("Your gift is %p\n", buffer);
	printf("> ");
	fgets(buffer, 1023, stdin);
	printf("",main);
	printf(buffer);
	return 0;
}

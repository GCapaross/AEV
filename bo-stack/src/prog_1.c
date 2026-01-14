#include <stdio.h>

int main() {
	char username[32];
	puts("username:");
	scanf("%s", username);
	printf("Welcome %s!\n", username);
	return 0;
}


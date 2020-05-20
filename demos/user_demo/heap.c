#include <stdio.h>
#include <stdlib.h>

#define SIZE 15

void oob() {
	printf("LOG: Incoming out of bounds access\n");
	char *buf = (char*)malloc(SIZE);
	buf[SIZE] = 42; // boom
	free(buf);	
}

void uaf() {
	printf("LOG: Incoming use after free\n");
	char *buf = (char*)malloc(SIZE);
	free(buf);
	buf[SIZE/2] = 42; // boom
}

void usage(char *prog) {
	printf("%s {1|2}\n1: Out of bounds heap access\n"
		"2: Use after free heap access\n", prog);
	exit(-1);
}

int main(int argc, char* argv[]) {
	if (argc != 2) usage(argv[0]);
	switch (atoi(argv[1])) {
		case 1:
			oob();
			break;
		case 2:
			uaf();
			break;
		default:
			usage(argv[0]);
	}
	return 0;
}

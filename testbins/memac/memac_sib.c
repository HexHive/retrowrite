#include <stdio.h>
#include <stdlib.h>


// Access sizes: 1, 4, 8
char
load_1(void *buf, int i) {
    return *((char*) buf + i);
}

short
load_2(void *buf, int i) {
    return *((short *) buf + i);
}

int
load_4(void *buf, int i) {
    return *((int*) buf + i);
}

long int
load_8(void *buf, int i) {
    return *((long int*) buf + i);
}

int main() {

    long int number[] = { 0xcafebabedeadbeef, 0xcafebabedeadbeef };

    printf ("%x\n", load_1((void *) &number, 2));
    /*printf ("%x\n", load_2((void *) &number));*/
    printf ("%x\n", load_2((void *) &number, 2));
    printf ("%x\n", load_4((void *) &number, 2));
    printf ("%x\n", load_8((void *) &number, 2));

    return 0;
}

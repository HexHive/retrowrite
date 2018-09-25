#include <stdio.h>
#include <stdlib.h>


// Access sizes: 1, 4, 8
char
load_1(void *buf) {
    return *((char*) buf);
}

short
load_2(void *buf) {
    return *((short *) buf);
}

int
load_4(void *buf) {
    return *((int*) buf);
}

long int
load_8(void *buf) {
    return *((long int*) buf);
}

int main() {

    long int number = 0xcafebabedeadbeef;

    printf ("%x\n", load_1((void *) &number));
    /*printf ("%x\n", load_2((void *) &number));*/
    printf ("%x\n", load_2((void *) &number));
    printf ("%x\n", load_4((void *) &number));
    printf ("%x\n", load_8((void *) &number));

    return 0;
}

#include "tinylib.h"
#include <stdio.h>


int main() {

#ifdef HEAP_OVERFLOW
    if (do_heap()) {
        printf ("Yay heap!\n");
    }
#endif

#ifdef STACK_OVERFLOW
    if (do_stack()) {
        printf ("Yay stack!\n");
    }
#endif

#ifdef GLOBAL_OVERFLOW
    if (do_global()) {
        printf ("Yay global!\n");
    }
#endif

    return 0;
}

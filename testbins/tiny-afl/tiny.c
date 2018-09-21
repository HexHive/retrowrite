/*#include "tinylib.h"*/
#include <stdio.h>

extern int do_heap(void);
extern int do_stack(void);
extern int do_global(void);


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

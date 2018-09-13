#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tinylib.h"

int do_heap() {
    char *secret = malloc(32);
    scanf("%s", secret);

    if (strcmp(secret, KEY.KEY)) {
        int i = 0;
        while (KEY.KEY[i]) {
            secret[i] = KEY.KEY[i];
            i++;
        }
        return 0;
    }

    return 1;
}

int do_stack() {
    char secret[32];
    scanf("%s", secret);

    if (strcmp(secret, KEY.KEY)) {
        int i = 0;
        while (KEY.KEY[i]) {
            secret[i] = KEY.KEY[i];
            i++;
        }
        return 0;
    }

    return 1;
}

int do_global() {
    char secret[256];
    scanf("%s", secret);

    if (strcmp(secret, KEY.KEY)) {
        int i = 0;
        while (secret[i]) {
            KEY.KEY[i] = secret[i];
            i++;
        }
        return 0;
    }

    return 1;
}

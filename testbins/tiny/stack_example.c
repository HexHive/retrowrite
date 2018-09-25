#include <stdio.h>
#include <stdlib.h>

int main() {
    char pass[] = "SECRET_PASSWORD";
    char input[32];
    int admin = 0;

    char ch = 'a';
    int i = 0, j = 0;

    for (i = 0; i < 64 && ch != ' '; i++) {
        scanf("%c", &ch);
        input[i] = ch;
    }

    input[i] = '\0';

    for (j = 0; j < i; j++) {
        if (pass[j] != input[j])
            break;
    }

    if (i == j)
        admin = 1;

    if (admin) {
        printf ("Success!");
    }


    return 0;
}



    





#include <stdio.h>

int main(void) {
    FILE *f = fopen("dummy", "w");
    if (f) fclose(f);
    return 0;
}

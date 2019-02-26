#include <stdlib.h>
#include <stdbool.h>
#include "support.h"

bool
memequal_consttime(const void *a_, const void *b_, size_t n)
{
    unsigned char test = 0;
    const unsigned char *a = (const unsigned char *)a_;
    const unsigned char *b = (const unsigned char *)b_;
    for (size_t i = 0; i < n; i++) {
        test |= a[i] ^ b[i];
    }

    return test == 0;
}

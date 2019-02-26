#include <stdio.h>
#include <stdarg.h>
#include "2fserver-support.h"

void
twofserver_eprintf(const char *fmt, ...)
{
    char line[512];
    va_list va;
    va_start(va, fmt);
    vsnprintf(line, sizeof(line), fmt, va);
    va_end(va);
    fprintf(stderr, "2fserver: %s\n", line);
}

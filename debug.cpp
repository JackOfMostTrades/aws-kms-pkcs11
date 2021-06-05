#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "debug.h"

bool debug_enabled = false;
void debug(const char *fmt, ...) {
    va_list args;

    if (!debug_enabled) {
        return;
    }

    char* longer_fmt = (char*)malloc(strlen(fmt)+11);
    strcpy(longer_fmt, "AWS_KMS: ");
    strcpy(longer_fmt+9, fmt);
    longer_fmt[strlen(fmt)+9] = '\n';
    longer_fmt[strlen(fmt)+10] = '\0';

    va_start(args, fmt);
    vprintf(longer_fmt, args);
    va_end(args);

    free(longer_fmt);
}

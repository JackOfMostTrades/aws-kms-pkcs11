#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "debug.h"

FILE *debug_file = NULL;
void debug(const char *fmt, ...) {
    va_list args;

    if (debug_file == NULL) {
        return;
    }

    char* longer_fmt = (char*)malloc(strlen(fmt)+11);
    strcpy(longer_fmt, "AWS_KMS: ");
    strcpy(longer_fmt+9, fmt);
    longer_fmt[strlen(fmt)+9] = '\n';
    longer_fmt[strlen(fmt)+10] = '\0';

    va_start(args, fmt);
    vfprintf(debug_file, longer_fmt, args);
    va_end(args);

    free(longer_fmt);
}

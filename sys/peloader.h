#ifndef PELOADER_H
#define PELOADER_H

#include <stdint.h>

typedef struct {
    uint8_t* data;
    uint32_t size;
    uint32_t base_addr;
} pelib_t;

int pelib_load(const char* filename, pelib_t* lib);
void* pelib_getproc(pelib_t* lib, const char* name);
int pelib_close(pelib_t* lib);

#endif
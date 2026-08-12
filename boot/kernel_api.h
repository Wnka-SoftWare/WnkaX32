#ifndef KERNEL_API_H
#define KERNEL_API_H

// В начале boot/kernel.cpp добавь:
extern "C" int atoi(const char* str);

#include <stdint.h>

// ============================================================
// MULTIBOOT (если нет отдельного хедера)
// ============================================================
#define MULTIBOOT_INFO_MODS (1 << 3)

typedef struct {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    uint32_t syms[4];
    uint32_t mmap_length;
    uint32_t mmap_addr;
} multiboot_info_t;

typedef struct {
    uint32_t mod_start;
    uint32_t mod_end;
    uint32_t string;
    uint32_t reserved;
} multiboot_module_t;

typedef struct {
    void (*kprint)(const char* str);
    void (*kprint_char)(char c);
    void (*kprint_int)(uint32_t n);
    void (*kprint_hex32)(uint32_t n);
    void (*kprint_color)(const char* str, uint8_t color);
    void (*kprint_at)(const char* str, int x, int y, uint8_t color);
    void (*clear_screen)(void);
    void* (*malloc)(uint32_t size);
    void  (*free)(void* ptr);
    void* (*memset)(void* ptr, int val, uint32_t size);
    void* (*memcpy)(void* dest, const void* src, uint32_t size);
    void (*read_sector)(uint32_t lba, uint16_t* buffer);
    void (*write_sector)(uint32_t lba, uint16_t* buffer);
    unsigned int (*strlen)(const char* s);    
    char* (*strcpy)(char* d, const char* s);  
    int  (*strcmp)(const char* a, const char* b);
    int (*atoi)(const char* s);
    uint8_t (*inb)(uint16_t port);
    void    (*outb)(uint16_t port, uint8_t val);
    uint16_t (*inw)(uint16_t port);
    void     (*outw)(uint16_t port, uint16_t val);
    void (*reboot)(void);
    void (*shutdown)(void);
    uint32_t (*get_ticks)(void);
    void (*sleep_ms)(uint32_t ms);
    int  (*task_create)(int (*entry)(void*), void* arg, const char* name);
    void (*task_exit)(int code);
    void (*task_yield)(void);
    
} kernel_api_t;

typedef void (*module_init_t)(kernel_api_t* api);
extern kernel_api_t* g_api;

#endif
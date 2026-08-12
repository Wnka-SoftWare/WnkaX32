#include "peloader.h"
#include "video.h"
#include "ata.h"
#include "string_utils.h"

#define NULL 0

typedef struct {
    uint32_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} __attribute__((packed)) IMAGE_DOS_HEADER;

typedef struct {
    uint32_t Signature;
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} __attribute__((packed)) IMAGE_FILE_HEADER;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} __attribute__((packed)) IMAGE_OPTIONAL_HEADER32;

typedef struct {
    uint8_t  Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed)) IMAGE_SECTION_HEADER;

typedef struct {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} __attribute__((packed)) IMAGE_EXPORT_DIRECTORY;

int pelib_load(const char* filename, pelib_t* lib) {
    uint8_t buf[512];
    uint16_t dir_buf[256];
    
    read_sector(100, dir_buf);
    
    int slot = -1;
    for(int i = 0; i < 32; i++) {
        char name[12] = {0};
        for(int j = 0; j < 11; j++) name[j] = ((char*)dir_buf)[i*16 + j];
        if(my_strcmp(filename, name) == 0 && ((char*)dir_buf)[i*16 + 11] == 0) {
            slot = i;
            break;
        }
    }
    
    if(slot == -1) return -1;
    
    int file_sector = dir_buf[slot*8 + 6];
    int file_size = dir_buf[slot*8 + 7];
    
    uint8_t* pe_data = (uint8_t*)0x30000000;
    
    for(int s = 0; s < (file_size + 511) / 512; s++) {
        uint16_t buf[256];
        read_sector(file_sector + s, buf);
        for(int i = 0; i < 256 && (s * 512 + i * 2) < file_size; i++) {
            pe_data[s * 512 + i * 2] = buf[i] & 0xFF;
            if(s * 512 + i * 2 + 1 < file_size) {
                pe_data[s * 512 + i * 2 + 1] = (buf[i] >> 8) & 0xFF;
            }
        }
    }
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_data;
    if(dos->e_magic != 0x5A4D) return -2;
    
    IMAGE_FILE_HEADER* pe = (IMAGE_FILE_HEADER*)(pe_data + dos->e_lfanew + 4);
    if(pe->Signature != 0x00004550) return -3;
    
    IMAGE_OPTIONAL_HEADER32* opt = (IMAGE_OPTIONAL_HEADER32*)(pe + 1);
    
    uint32_t image_base = opt->ImageBase;
    if(image_base == 0) image_base = 0x10000000;
    
    uint8_t* load_addr = (uint8_t*)image_base;
    
    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uint8_t*)opt + pe->SizeOfOptionalHeader);
    
    for(int i = 0; i < pe->NumberOfSections; i++) {
        uint32_t size = sections[i].SizeOfRawData;
        uint32_t src = sections[i].PointerToRawData;
        uint32_t dst = sections[i].VirtualAddress;
        
        if(size > 0) {
            for(uint32_t j = 0; j < size; j++) {
                load_addr[dst + j] = pe_data[src + j];
            }
        }
    }
    
    lib->data = load_addr;
    lib->size = opt->SizeOfImage;
    lib->base_addr = image_base;
    
    kprint("[PE] ");
    kprint(filename);
    kprint(" loaded at 0x");
    kprint_hex32(image_base);
    kprint("\n");
    
    return 0;
}

void* pelib_getproc(pelib_t* lib, const char* name) {
    uint8_t* base = lib->data;
    
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    IMAGE_FILE_HEADER* pe = (IMAGE_FILE_HEADER*)(base + dos->e_lfanew + 4);
    IMAGE_OPTIONAL_HEADER32* opt = (IMAGE_OPTIONAL_HEADER32*)(pe + 1);
    
    uint32_t export_rva = opt->NumberOfRvaAndSizes > 0 ? 
        *(uint32_t*)((uint8_t*)opt + sizeof(IMAGE_OPTIONAL_HEADER32) - 16) : 0;
    
    if(export_rva == 0) return NULL;
    
    IMAGE_EXPORT_DIRECTORY* exports = (IMAGE_EXPORT_DIRECTORY*)(base + export_rva);
    
    uint32_t* funcs = (uint32_t*)(base + exports->AddressOfFunctions);
    uint32_t* names = (uint32_t*)(base + exports->AddressOfNames);
    uint16_t* ordinals = (uint16_t*)(base + exports->AddressOfNameOrdinals);
    
    for(uint32_t i = 0; i < exports->NumberOfNames; i++) {
        char* func_name = (char*)(base + names[i]);
        if(my_strcmp(func_name, name) == 0) {
            uint32_t func_rva = funcs[ordinals[i]];
            return (void*)(base + func_rva);
        }
    }
    
    return NULL;
}

int pelib_close(pelib_t* lib) {
    lib->data = NULL;
    lib->size = 0;
    return 0;
}
#include <data/mach-o/binary.h>
#include <data/mach-o/headers/loader.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if(argc != 2) {
        fprintf(stderr, "Usage: check_sanity macho\n");
        exit(1);
    }
    struct binary binary;
    b_init(&binary);
    b_prange_load_macho(&binary, load_file(argv[1], false, NULL), 0, argv[1]);
    int result = 0;
    CMD_ITERATE(binary.mach->hdr, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *seg = (void *) cmd;
            uint32_t start = seg->vmaddr;
            uint32_t end = seg->vmaddr + seg->vmsize;

            struct section *sections = (void *) (seg + 1);
            for(uint32_t i = 0; i < seg->nsects; i++) {
                struct section *sect = &sections[i];
                if(!(start <= sect->addr && sect->addr <= end && \
                     start <= (sect->addr + sect->size) && (sect->addr + sect->size) <= end)) {
                        printf("insane: segment %.16s section %d is out of bounds (vmaddr:%x vmsize:%x addr:%x size:%x)\n", seg->segname, i, seg->vmaddr, seg->vmsize, sect->addr, sect->size);
                        result = 1;
                }
            }
        }
    }
    return result;
}

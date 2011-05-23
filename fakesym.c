#include <data/binary.h>
#include <data/find.h>
#include <stdio.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

// Shorter-term thing than the other stuff;
// only for use on this device until the keys are found.

struct binary in;
uint32_t strx;
struct nlist *symtab;

void add(const char *name, addr_t addr) {
    printf("%s -> %x\n", name, addr);
    struct nlist nl;
    memset(&nl, 0, sizeof(nl));
    nl.n_un.n_strx = strx;
    strcpy(in.strtab + strx, name);
    strx += strlen(name) + 1;
    if(addr & 1) {
        addr &= ~1;
        nl.n_desc = N_ARM_THUMB_DEF;
    }
    nl.n_value = addr;
    *symtab++ = nl;
}

int main(int argc, char **argv) {
    (void) argc;
    b_init(&in);
    b_load_macho(&in, argv[1], true);

    symtab = in.ext_symtab;
    strx = 1;

    range_t text = b_macho_segrange(&in, "__TEXT");
    add("_IOLockAlloc", resolve_ldr(&in, find_data(text, "+ .. .. a8 47 a0 60 a8 47 e6 60 00 23", 0, true)));
    add("_IOLog", find_data(text, "+ 0f b4 b0 b5 02 af 82 b0 06 ac", 0, true));
    add("_IOMalloc", find_data(text, "+ 90 b5 01 af .. .. 04 46 98 47 03 46 18 b1", 0, true));
    add("_PE_i_can_has_debugger", find_data(text, "+ 48 b1 06 4a 13 68 13 b9 03 60", 0, true));
    add("_copyin", find_data(text, "- 00 00 52 e3 00 00 a0 03 1e ff 2f 01 02 01 50 e3", 0, true));
    add("_copyout", find_data(text, "- 00 00 52 e3 00 00 a0 03 1e ff 2f 01 02 01 51 e3", 0, true));
    add("_flush_dcache", resolve_ldr(&in, find_data(b_macho_segrange(&in, "__PRELINK_TEXT"), "21 60 20 46 04 21 00 22 +", 1, true)));
    add("_invalidate_icache", resolve_ldr(&in, find_data(text, "98 47 f3 6a 2a 46 d3 f8 94 00 d3 f8 98 10 +", 0, true)));
    add("_memcmp", find_data(text, "+ 42 b1 10 f8 01 cb 11 f8 01 3b", 0, true));
    add("_memcpy", find_data(text, "- 00 00 52 e3 01 00 50 11 1e ff 2f 01", 0, true));
    add("_proc_ucred", find_data(text, "+ d0 f8 84 00 70 47", 1, true));
    add("_vfs_getattr", 10);
    add("_vn_getpath", find_data(text, "+ f0 b5 03 af 4d f8 04 8d 82 b0 14 46 06 46 88 46 15 68 .. .. .. .. 01 23", 0, true));

    CMD_ITERATE(in.mach_hdr, cmd) {
        if(cmd->cmd == LC_SYMTAB) {
            struct symtab_command *sc = (void *) cmd;
            sc->nsyms = symtab - in.ext_symtab;
        }
    }

    b_macho_store(&in, argv[2]);
}

/* how trivial...
extract the symbols into a new mach-o
that contains just the symbols */

#include <data/mach-o/binary.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

struct header {
    struct mach_header mh;
    struct segment_command segment;
    struct symtab_command symtab;
    struct nlist nl[0];
} __attribute__((packed));

int main(int argc, char **argv) {
    assert(argc == 3);

    struct binary binary;
    b_init(&binary);
    b_load_macho(&binary, argv[1]);

    int out = open(argv[2], O_WRONLY | O_TRUNC | O_CREAT, 0755);
    assert(out != -1);

    int size = sizeof(struct header) + binary.mach->ext_nsyms * sizeof(struct nlist);
    struct header *hdr = calloc(1, size);
    lseek(out, size + 1, SEEK_SET);

    int off = 1;

    for(uint32_t i = 0; i < binary.mach->ext_nsyms; i++) {
        hdr->nl[i] = binary.mach->ext_symtab[i];
        const char *name = binary.mach->strtab + hdr->nl[i].n_un.n_strx;
        int diff = strlen(name) + 1;
        hdr->nl[i].n_un.n_strx = off;
        assert(write(out, name, diff) == diff);
        off += diff;
         
    }
    size_t end = lseek(out, 0, SEEK_CUR);

    memcpy(&hdr->mh, binary.mach->hdr, sizeof(hdr->mh));
    hdr->mh.ncmds = 2;
    hdr->mh.sizeofcmds = sizeof(*hdr) - sizeof(hdr->mh);

    hdr->segment.cmd = LC_SEGMENT;
    hdr->segment.cmdsize = sizeof(hdr->segment);
    strcpy(hdr->segment.segname, "__LINKEDIT");
    hdr->segment.vmaddr = 0;
    hdr->segment.vmsize = (end + 0xfff) & ~0xfff;
    hdr->segment.fileoff = 0;
    hdr->segment.filesize = end;
    hdr->segment.maxprot = PROT_READ | PROT_EXEC;
    hdr->segment.initprot = PROT_READ | PROT_EXEC;
    hdr->segment.nsects = 0;
    hdr->segment.flags = 0;

    hdr->symtab.cmd = LC_SYMTAB;
    hdr->symtab.cmdsize = sizeof(hdr->symtab);
    hdr->symtab.symoff = sizeof(*hdr);
    hdr->symtab.nsyms = binary.mach->ext_nsyms;
    hdr->symtab.stroff = size;
    hdr->symtab.strsize = end - size;

    assert(pwrite(out, hdr, size, 0) == size);
}

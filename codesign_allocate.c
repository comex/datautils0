#include <assert.h>
#include <data/mach-o/binary.h>
#include <mach-o/loader.h>
#include <copyfile.h>

int main(int argc, char **argv) {
    const char *infile = NULL, *outfile = NULL;
    size_t size = 0;
    for(char **p = argv; *p; p++) {
        if(!strcmp(*p, "-i")) {
            infile = *p++;
        } else if(!strcmp(*p, "-a")) {
            p++;
            size = strtol(*p++, NULL, 0);
        } else if(!strcmp(*p, "-o")) {
            outfile = *p++;
        } else {
            die("??");
    }

    assert(!copyfile(infile, outfile, NULL, COPYFILE_ALL));

    int fd = open(outfile, O_RDWR);
    assert(fd != -1);
    off_t fend = lseek(fd, 0, SEEK_END);
    ftruncate(fd, fend + size);
    void *file = mmap(NULL, (size_t) fend, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(file != MAP_FAILED);
    
    struct mach_header *mh = file;
    mh->ncmds++;
    mh->sizeofcmds += sizeof(struct linkedit_data_command);
    CMD_ITERATE(mh, cmd) {
        if(cmd->cmd == LC_SEGMENT) {
            struct segment_command *sc = (void *) cmd;
            if(!strncmp(sc->segname, "__LINKEDIT", 16)) {
                sc->filesize += size;
                sc->vmsize += size;
            }
        } else if(cmd->cmd == 0) {
            struct linkedit_data_command *dc = (void *) cmd;
            dc->cmd = LC_CODE_SIGNATURE;
            dc->cmdsize = sizeof(*dc);
            dc->dataoff = (uint32_t) fend;
            dc->datasize = (uint32_t) size;
        }
    }

}

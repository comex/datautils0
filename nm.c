#include <data/mach-o/binary.h>
#include <data/dyldcache/binary.h>
#include <stdio.h>
#include <stdlib.h>

static void usage() {
    fprintf(stderr, "Usage: nm [-ixp] [-c subfile] binary [symbol]\n");
    exit(1);
}

int main(int argc, char **argv) {
    int flags = 0;

    const char *subfile = NULL;

    int c;
    while((c = getopt(argc, argv, "ixpc:")) != -1) switch(c) {
    case 'i': flags |= IMPORTED_SYM; break;
    case 'x': flags |= TO_EXECUTE; break;
    case 'p': flags |= PRIVATE_SYM; break;
    case 'c': subfile = optarg; break;
    default: usage();
    }

    if(!argv[optind] || (argv[optind + 1] && argv[optind + 2])) usage();

    struct binary binary;
    b_init(&binary);
    if(subfile) {
        struct binary other;
        b_init(&other);
        b_load_dyldcache(&other, argv[optind]);
        b_dyldcache_load_macho(&other, subfile, &binary);
    } else {
        b_load_macho(&binary, argv[optind]);
    }


    if(argv[optind + 1]) {
        printf("%8llx\n", (long long) b_sym(&binary, argv[optind + 1], flags));
    } else {
        struct data_sym *syms;
        uint32_t nsyms;
        b_copy_syms(&binary, &syms, &nsyms, flags);
        while(nsyms--) {
            printf("%8llx %s\n", (long long) syms->address, syms->name);
            syms++;
        }
    }
    return 0;
}

#include <data/mach-o/binary.h>

static void dump(range_t range) {
    prange_t pr = rangeconv(range, MUST_FIND);
    write(1, pr.start, pr.size);
}

int main(int argc, char **argv) {
    if(argc < 2) goto usage;
    struct binary binary;
    b_init(&binary);
    for(int pass = 1; pass <= 2; pass++) {
        for(char **arg = &argv[1]; *arg;) {
            if(!strcmp(*arg, "-a")) {
                if(!arg[1] || !arg[2]) goto usage;
                if(pass == 2) {
                    dump((range_t) {&binary, parse_hex_uint32(arg[1]), parse_hex_uint32(arg[2])});
                }
                arg += 3;
            } else if(!strcmp(*arg, "-A")) {
                if(!arg[1] || !arg[2]) goto usage;
                if(pass == 2) {
                    uint32_t start = parse_hex_uint32(arg[1]);
                    dump((range_t) {&binary, start, parse_hex_uint32(arg[2]) - start});
                }
                arg += 3;
            } else if(!strcmp(*arg, "-s")) {
                if(!arg[1]) goto usage;
                if(pass == 2) {
                    dump(b_macho_segrange(&binary, arg[1]));
                }
                arg += 2;
            } else if((*arg)[0] == '-') {
                goto usage;
            } else {
                if(pass == 1) {
                    if(binary.valid) goto usage;
                    b_load_macho(&binary, *arg);
                }
                arg++;
            }
        }
        if(!binary.valid) goto usage;
    }

    return 0;

    usage:
    fprintf(stderr, "Usage: dump binary [-a start len] [-A start end] [-s segname]\n");
    return 1;
}

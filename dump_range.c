#include <data/mach-o/binary.h>

int main(int argc, char **argv) {
    if(argc != 4) {
        fprintf(stderr, "Usage: dump_range binary start len\n");
        return 1;
    }
    struct binary binary;
    b_init(&binary);
    b_load_macho(&binary, argv[1]);
    prange_t pr = rangeconv((range_t) {&binary, parse_hex_uint32(argv[2]), parse_hex_uint32(argv[3])}, MUST_FIND);
    write(1, pr.start, pr.size);
    return 0;
}

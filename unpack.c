#include <data/cc.h>
int main(int argc, char **argv) {
    if(argc < 3 || argc > 5) goto usage;

    prange_t data = unpack(load_file(argv[1], false, NULL), argv[3], argv[4]);
    store_file(data, argv[2], 0644);
    return 0;

    usage:
    fprintf(stderr, "Usage: unpack <infile> <outfile> [<key> <iv> | <arch>]\n");
    return 1;
}

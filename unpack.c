#include <data/cc.h>
int main(int argc, char **argv) {
    if(argc < 3 || argc > 5) goto usage;

    const char *key = argv[3], *iv = argv[4];
    if(key && iv && strlen(iv) > strlen(key)) { // maybe you specified it backwards
        key = argv[4]; iv = argv[3];
    }
    prange_t data = unpack(load_file(argv[1], false, NULL), key, iv);
    store_file(data, argv[2], 0644);
    return 0;

    usage:
    fprintf(stderr, "Usage: unpack <infile> <outfile> [<key> <iv> | <arch>]\n");
    return 1;
}

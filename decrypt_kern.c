#include <data/cc.h>
int main(int argc, char **argv) {
    if(argc != 5) {
        fprintf(stderr, "Usage: decrypt_kern <img3> <key> <iv> <outfile>\n");
        return 1;
    }
    uint32_t key_bits;
    char *kern_fn;
    prange_t data = parse_img3_file(kern_fn = argv[1], &key_bits);
    prange_t key = parse_hex_string(argv[2]);
    prange_t iv = parse_hex_string(argv[3]);
    prange_t decompressed = decrypt_and_decompress(key_bits, key, iv, data);
    store_file(decompressed, argv[4], 0644);
    return 0;
}

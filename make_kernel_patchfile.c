#include <data/common.h>
#include <data/find.h>
#include <data/mach-o/binary.h>
#include <data/mach-o/link.h>
#include "lambda.h"

extern unsigned char sandbox_armv6_o[], sandbox_armv7_o[];
extern unsigned int sandbox_armv6_o_len, sandbox_armv7_o_len;

int patchfd;

static inline void patch_with_range(const char *name, addr_t addr, prange_t pr) {
    uint32_t len = strlen(name);
    write(patchfd, &len, sizeof(len));
    write(patchfd, name, len);
    write(patchfd, &addr, sizeof(addr));
    uint32_t size = pr.size; // size_t no good
    write(patchfd, &size, sizeof(size));
    write(patchfd, pr.start, pr.size);
}

#define patch(name, addr, typeof_to, to...) \
    ({ typeof_to to_[] = to; \
       patch_with_range(name, addr, (prange_t) {&to_[0], sizeof(to_)}); })

// the spec macro chooses between alternatives depending on the "class"
// possible "classes": armv6 pre 4.3, armv7 pre 4.3, 4.3.x, 5.0.x

static unsigned int _armv6 = 0;
static unsigned int _armv7 = 1;
static unsigned int _43 = 2;
static unsigned int _50 = 3;

#define spec_(c1, v1, c2, v2, c3, v3, c4, v4, ...) \
    (class >= (c1) ? (v1) : \
     class >= (c2) ? (v2) : \
     class >= (c3) ? (v3) : \
     class >= (c4) ? (v4) : \
     (die("no valid alternative"), (typeof(v1+0)) 0))
#define spec(args...) spec_(args, 10, 0, 10, 0, 10, 0)

#define is_armv7(binary) (binary->actual_cpusubtype == 9)

addr_t find_sysctl(struct binary *binary, const char *name) {
    addr_t cs = find_string(b_macho_segrange(binary, "__TEXT"), name, 0, MUST_FIND);
    addr_t csref = find_int32(b_macho_segrange(binary, "__DATA"), cs, MUST_FIND);
    return b_read32(binary, csref - 8);
}

void do_kernel(struct binary *binary, struct binary *sandbox) {
    unsigned int class;
    if(!is_armv7(binary)) class = _armv6;
    else if(!b_sym(binary, "_vfs_getattr", 0)) class = _armv7;
    else if(!b_sym(binary, "_buf_attr", 0)) class = _43;
    else class = _50;

    addr_t _PE_i_can_has_debugger, _vn_getpath, _memcmp;

    struct findmany *text = findmany_init(b_macho_segrange(binary, "__TEXT"));

    _PE_i_can_has_debugger = b_sym(binary, "_PE_i_can_has_debugger", MUST_FIND | TO_EXECUTE);
    _vn_getpath = b_sym(binary, "_vn_getpath", MUST_FIND | TO_EXECUTE);
    _memcmp = b_sym(binary, "_memcmp", MUST_FIND | TO_EXECUTE);

    addr_t vme; findmany_add(&vme, text, spec(_50, "01 f0 - 06 00 06 28",
                                              _armv7, "- 02 0f .. .. 63 08 03 f0 01 05 e3 0a 13 f0 01 03",
                                              _armv6, "- .. .. .. .. .. 08 1e 1c .. 0a 01 22 .. 1c 16 40 .. 40"));
    addr_t vmp; findmany_add(&vmp, text, spec(_50, "- 26 f0 04 06 00 20 29 46",
                                              _armv7, "- 25 f0 04 05 .. e7 92 45 98 bf 02 99 .. d8",
                                              _armv6, "?"));

    // this function checks the baked list of hashes
    addr_t mystery = find_data(b_macho_segrange(binary, "__PRELINK_TEXT"), spec(_50, "- f0 b5 03 af 2d e9 00 05 04 46 .. .. 14 f8 01 0b 4f f0 13 0c",
                                                                                _43, "- f0 b5 03 af 4d f8 04 8d .. .. 03 78 80 46",
                                                                                _armv7, "- 90 b5 01 af 14 29 .. .. .. .. 90 f8 00 c0",
                                                                                _armv6, "?"),
                                                                          0, MUST_FIND);
    addr_t dei; findmany_add(&dei, text, spec(_50, "24 bf 04 22 01 92 00 98 .. .. -",
                                              _armv7, "04 22 01 92 00 98 .. 49 -",
                                              _armv6, "?"));
    addr_t tfp0; findmany_add(&tfp0, text, spec(_50, "91 e8 01 04 d1 f8 08 80 00 21 02 91 ba f1 00 0f 01 91 - 06 d1 02 a8",
                                                _armv7, "85 68 00 23 .. 93 .. 93 - 5c b9 02 a8 29 46 04 22",
                                                _armv6, "85 68 .. 93 .. 93 - 00 2c 0b d1"));
    addr_t csedp; findmany_add(&csedp, text, spec(_50, "- df f8 88 33 1d ee 90 0f",
                                                  _43, "1d ee 90 3f d3 f8 80 33 93 f8 94 30 1b 09 03 f0 01 02 + .. .. .. ..",
                                                  _armv7, "1d ee 90 3f d3 f8 4c 33 d3 f8 9c 20 + .. .. .. .. 19 68 00 29",
                                                  _armv6, "9c 22 03 59 99 58 + .. .. 1a 68 00 2a"));
    addr_t power = 0; if(class >= _43) power = find_data(b_macho_segrange(binary, "__PRELINK_TEXT"), 
                                                    spec(_50, "- 32 20 00 21 20 22",
                                                         _43, "- 32 20 98 47 .. 68"),
                                                         0, MUST_FIND);
    
    findmany_go(text);


    // vm_map_enter (patch1) - allow RWX pages
    patch("vm_map_enter", vme, uint32_t, {spec(_50, 0x28080006,
                                               _armv7, 0x46c00f02,
                                               _armv6, 0x46c046c0)});
    // vm_map_protect - allow vm_protect etc. to create RWX pages
    patch("vm_map_protect", vmp, uint32_t, {spec(_armv7, 0x46c046c0,
                                                 _armv6, 42)});
    // AMFI (patch3) - disable the predefined list of executable stuff
    patch("AMFI", mystery, uint32_t, {spec(_armv7, 0x47702001,
                                           _armv6, 0xe3a00001)});
    // PE_i_can_has_debugger (patch4) - so AMFI allows non-ldid'd binaries (and some other stuff is allowed)
    // switching to patching the actual thing, and the startup code
    // why? debug_enabled is used directly in kdp, and I was not emulating PE_i_can_has's behavior correctly anyway
    patch("+debug_enabled", resolve_ldr(binary, _PE_i_can_has_debugger + 2), uint32_t, {1});
    patch("-debug_enabled initializer", dei, uint32_t, {spec(_armv7, 0x60082001,
                                                             _armv6, 42)});
    // task_for_pid 0
    // this choice of patch was necessary so that a reboot wasn't required after
    // using the screwed up version from jailbreakme 2.0; no reason to change it
    patch("task_for_pid 0", tfp0, uint32_t, {spec(_50, 0xa802e006,
                                                  _armv7, 0xa802e00b,
                                                  _armv6, 0xe00b2c00)});
    if(class >= _50) {
        // it moved into BSS?
        patch("cs_enforcement_disable check", csedp, uint32_t, {0x23012301});
    } else {
        patch("cs_enforcement_disable", resolve_ldr(binary, csedp), uint32_t, {1});
    }

    addr_t scratch = resolve_ldr(binary, spec(_50, mystery + 11,
                                              _armv7, mystery + 9,
                                              _armv6, 42));
    scratch = (scratch + 3) & ~3;

    // patches

    patch("proc_enforce",
          find_sysctl(binary, "proc_enforce"),
          uint32_t, {0});
    
    /*patch("vnode_enforce",
          find_sysctl(binary, "vnode_enforce"),
          uint32_t, {0});*/
    
    if(class >= _43) {
        // br0x's camera kit patch    
        patch("USB power", power, uint8_t, {0xfa});
    }
    
    // sandbox
    range_t range = b_macho_segrange(binary, "__PRELINK_TEXT");
    addr_t sb_evaluate = find_bof(range, find_int32(range, find_string(range, "bad opcode", 0, MUST_FIND), MUST_FIND), class >= _armv7) & ~1;
    
   
    DECL_LAMBDA(l, uint32_t, (const char *name), {
        if(!strcmp(name, "c_sb_evaluate_orig1")) return b_read32(binary, sb_evaluate);
        if(!strcmp(name, "c_sb_evaluate_orig2")) return b_read32(binary, sb_evaluate + 4);
        if(!strcmp(name, "c_sb_evaluate_orig3")) return b_read32(binary, sb_evaluate + 8);
        if(!strcmp(name, "c_sb_evaluate_orig4")) return b_read32(binary, sb_evaluate + 12);
        if(!strcmp(name, "c_sb_evaluate_jumpto")) return sb_evaluate + spec(_armv7, 17,
                                                                            _armv6, 16);

        if(!strcmp(name, "c_memcmp")) return _memcmp;
        if(!strcmp(name, "c_vn_getpath")) return _vn_getpath;
        die("? %s", name);
    })
    b_relocate(sandbox, (void *) l.arg, RELOC_DEFAULT, (void *) l.func, 0);
    prange_t sandbox_pr = rangeconv_off(sandbox->segments[0].file_range, MUST_FIND);
    store_file(sandbox_pr, "/tmp/wtf.o", 0644);
    patch_with_range("sb_evaluate hook",
                     scratch,
                     sandbox_pr);
    
    patch("sb_evaluate",
          sb_evaluate,
          uint32_t, {spec(_armv7, 0xf000f8df,
                          _armv6, 0xe51ff004),
                     scratch | 1});

#ifndef __arm__
    // this is not a real patch but the address is included for something else to use
    patch("scratch", 0, uint32_t, {(scratch + sandbox_pr.size + 0xfff) & ~0xfff});
#endif

}


int main(int argc, char **argv) {
    (void) argc;
    struct binary kernel, sandbox;
    b_init(&kernel);
    b_init(&sandbox);
    b_load_macho(&kernel, argv[1]);
    b_prange_load_macho(&sandbox, kernel.actual_cpusubtype == 9 ? (prange_t) {sandbox_armv7_o, sandbox_armv7_o_len} : (prange_t) {sandbox_armv6_o, sandbox_armv6_o_len}, 0, "sandbox.o");

    patchfd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if(patchfd == -1) {
        edie("could not open patchfd");
    }

    do_kernel(&kernel, &sandbox);

    close(patchfd);
    return 0;
}


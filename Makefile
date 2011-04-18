DATA = $(word 1,$(wildcard ./data ../data))
include $(DATA)/Makefile.common

BINS := check_sanity make_kernel_patchfile apply_patchfile dump_range sandboxc.c
all: .settings .data $(BINS)
.data:
	make -C $(DATA)
%.o: %.c
	$(GCC) -c -o $@ $< -I$(DATA)
sandbox.o: sandbox.S
	$(SDK_GCC) -c -o $@ $<
sandboxc.c: sandbox.o
	xxd -i sandbox.o > sandboxc.c

check_sanity: check_sanity.o $(DATA)/libdata.a
	$(GCC) -o $@ $^ $(DATA)/libdata.a
apply_patchfile: apply_patchfile.o $(DATA)/libdata.a
	$(GCC) -o $@ $^ $(DATA)/libdata.a
make_kernel_patchfile: make_kernel_patchfile.o sandboxc.o $(DATA)/libdata.a
	$(GCC) -o $@ $^ $(DATA)/libdata.a
dump_range: dump_range.o $(DATA)/libdata.a
	$(GCC) -o $@ $^ $(DATA)/libdata.a

clean:
	rm -f $(BINS) *.o

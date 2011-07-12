DATA = $(word 1,$(wildcard ./data ../data))
override CFLAGS += -I$(DATA)
include $(DATA)/Makefile.common

BINS := $(OUTDIR)/check_sanity $(OUTDIR)/make_kernel_patchfile $(OUTDIR)/apply_patchfile $(OUTDIR)/dump $(OUTDIR)/nm $(OUTDIR)/decrypt_kern sandboxc-armv6.c sandboxc-armv7.c
ifneq "$(GXX)" ""
BINS += $(OUTDIR)/grapher
endif

all: .data $(OUTDIR) $(BINS)

$(OUTDIR):
	mkdir $(OUTDIR)

sandbox-armv6.o: sandbox.S
	$(SDK_GCC) -arch armv6 -c -o $@ $<
sandbox-armv7.o: sandbox.S
	$(SDK_GCC) -arch armv7 -c -o $@ $<
sandboxc-%.c: sandbox-%.o
	xxd -i $< > $@

$(OUTDIR)/check_sanity: $(OUTDIR)/check_sanity.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/apply_patchfile: $(OUTDIR)/apply_patchfile.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/make_kernel_patchfile: $(OUTDIR)/make_kernel_patchfile.o $(OUTDIR)/sandboxc-armv6.o $(OUTDIR)/sandboxc-armv7.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/dump: $(OUTDIR)/dump.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/nm: $(OUTDIR)/nm.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/grapher: $(OUTDIR)/grapher.o $(DATA)/$(OUTDIR)/libdata.a
	$(GXX) -o $@ $^ -O3
$(OUTDIR)/decrypt_kern: $(OUTDIR)/decrypt_kern.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^ -O3
$(OUTDIR)/codesign_allocate: $(OUTDIR)/codesign_allocate.o
	$(GCC) -o $@ $^ -O3

clean: .clean
	rm -f sandboxc-{armv6,armv7}.c sandbox-{armv6,armv7}.o

DATA = $(word 1,$(wildcard ./data ../data))
CFLAGS += -I$(DATA)
include $(DATA)/Makefile.common

BINS := $(OUTDIR)/check_sanity $(OUTDIR)/make_kernel_patchfile $(OUTDIR)/apply_patchfile sandboxc.c

all: .data $(OUTDIR) $(BINS)
.data:
	make -C $(DATA)
$(OUTDIR):
	mkdir $(OUTDIR)

sandbox.o: sandbox.S
	$(SDK_GCC) -c -o $@ $<
sandboxc.c: sandbox.o
	xxd -i sandbox.o > sandboxc.c

$(OUTDIR)/check_sanity: $(OUTDIR)/check_sanity.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/apply_patchfile: $(OUTDIR)/apply_patchfile.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^
$(OUTDIR)/make_kernel_patchfile: $(OUTDIR)/make_kernel_patchfile.o $(OUTDIR)/sandboxc.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $^

clean: .clean
	rm -f sandbox.o sandboxc.c

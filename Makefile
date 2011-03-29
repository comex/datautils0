DATA = $(word 1,$(wildcard ./data ../data))
include $(DATA)/Makefile.common
OBJS = check_sanity make_kernel_patchfile apply_patchfile
all: .settings $(OBJS)
%: %.c
	make -C $(DATA)
	$(GCC) $(CFLAGS) -o $@ $< -I$(DATA) $(DATA)/libdata.a
clean:
	rm -f $(OBJS)

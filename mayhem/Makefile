# Fuzz harness build for nanos, reusing upstream's make machinery (vars.mk/rules.mk:
# closure_templates.h generation via contgen, object layout under output/).
# Driven by mayhem/build.sh; objects land in output/mayhem/fuzz-$(VARIANT) (gitignored /output).
#   FUZZ_CFLAGS   compile flags for every object (sanitizers, coverage, DWARF)
#   FUZZ_LDFLAGS  link flags (libFuzzer or the standalone driver)
#   FUZZ_EXTRA    extra objects/sources to link (standalone main, lsan_off)
include ../vars.mk

override ARCH=$(HOST_ARCH)
override CROSS_COMPILE=

VARIANT?=	fuzz
override OBJDIR:=	$(OUTDIR)/mayhem/$(VARIANT)

HARNESSES=	fuzz_tuple_parser fuzz_json fuzz_http_parser fuzz_http_listener fuzz_tfs fuzz_xml fuzz_dtb
PROGRAMS=	$(HARNESSES)

# src/runtime/memops.c is swapped for mayhem/fuzz/memops_libc.c (see that file: upstream's
# word-at-a-time copy over-reads the source by design, which ASan flags on every input).
COMMON=	$(filter-out $(SRCDIR)/runtime/memops.c,$(RUNTIME)) $(CURDIR)/fuzz/memops_libc.c \
	$(SRCDIR)/unix_process/unix_process_runtime.c

SRCS-fuzz_tuple_parser=	$(CURDIR)/fuzz/fuzz_tuple_parser.c $(COMMON)
SRCS-fuzz_json=		$(CURDIR)/fuzz/fuzz_json.c $(COMMON)
SRCS-fuzz_http_parser=	$(CURDIR)/fuzz/fuzz_http_parser.c $(SRCDIR)/http/http.c $(COMMON)
SRCS-fuzz_http_listener=	$(CURDIR)/fuzz/fuzz_http_listener.c $(SRCDIR)/http/http.c $(COMMON)
SRCS-fuzz_xml=		$(CURDIR)/fuzz/fuzz_xml.c $(ROOTDIR)/klib/xml.c $(COMMON)
SRCS-fuzz_dtb=		$(CURDIR)/fuzz/fuzz_dtb.c $(SRCDIR)/devicetree/devicetree.c $(COMMON)
SRCS-fuzz_tfs=		$(CURDIR)/fuzz/fuzz_tfs.c $(SRCDIR)/fs/fs.c $(SRCDIR)/fs/tfs.c $(SRCDIR)/fs/tlog.c $(COMMON)

$(foreach p,$(HARNESSES),$(eval LIBS-$(p)= $(FUZZ_EXTRA) $(FUZZ_LDFLAGS)))

CFLAGS+=	-O1 \
		-I$(ARCHDIR) \
		-I$(SRCDIR) \
		-I$(SRCDIR)/runtime \
		-I$(SRCDIR)/fs \
		-I$(SRCDIR)/http \
		-I$(SRCDIR)/unix_process \
		-I$(SRCDIR)/devicetree \
		-I$(ROOTDIR)/klib

all: $(PROGRAMS)

include ../rules.mk

# after rules.mk: sanitizer/coverage/DWARF flags win over upstream's -g, and clang
# warnings that gcc does not emit must not stop the build
CFLAGS+=	$(FUZZ_CFLAGS) -Wno-error
LDFLAGS+=	$(FUZZ_CFLAGS)

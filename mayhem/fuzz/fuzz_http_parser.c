/* HTTP/1.x message parser: allocate_http_parser() (src/http/http.c), as used by the
 * kernel's HTTP clients (cloud metadata, klibs) and the HTTP listener.
 * Byte 0: bit0 = headers_only, bits 1-2 = number of chunks (1-3) the rest is fed in. */
#include "fuzz_common.h"
#include <http.h>

closure_function(0, 1, void, fz_value,
                 value v)
{
    buffer out = allocate_buffer(fuzz_heap, 128);
    bprintf(out, "%v", v);
    deallocate_buffer(out);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    FUZZ_BEGIN();
    boolean headers_only = data[0] & 1;
    int chunks = 1 + ((data[0] >> 1) % 3);
    data++; size--;
    buffer_handler bh = allocate_http_parser(fuzz_heap, headers_only, closure(fuzz_heap, fz_value));
    if (bh == INVALID_ADDRESS)
        abort();
    size_t off = 0;
    boolean failed = false;
    for (int i = 0; i < chunks && !failed; i++) {
        size_t n = (i == chunks - 1) ? size - off : (size - off) / (chunks - i);
        buffer b = fuzz_buffer(data + off, n);
        off += n;
        status s = apply(bh, b);
        if (s != STATUS_OK) {
            timm_dealloc(s);
            failed = true;
        }
        deallocate_buffer(b);
    }
    /* end of stream: the parser frees itself */
    status s = apply(bh, 0);
    if (s != STATUS_OK)
        timm_dealloc(s);
    FUZZ_END();
    return 0;
}

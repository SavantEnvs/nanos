/* HTTP server side: the connection handler from connection_handler_from_http_listener()
 * (src/http/http.c each_http_request: request parsing, URI split, registrant lookup,
 * 404/505 responses), fed raw request bytes. Handlers reply with send_http_response.
 * Byte 0 % 4 + 1 = number of chunks the rest is fed in. */
#include "fuzz_common.h"
#include <http.h>

static connection_handler ch;

closure_function(0, 1, status, fz_sink,
                 buffer b)
{
    /* response bytes from the server; the server owns nothing we keep */
    return STATUS_OK;
}

closure_function(1, 3, void, fz_handler,
                 sstring, name,
                 http_method m, http_responder out, value v)
{
    buffer body = aprintf(fuzz_heap, "%s %d %v\r\n", bound(name), m, v);
    send_http_response(out, timm("ContentType", "text/plain"), body);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    http_listener hl = allocate_http_listener(fuzz_heap, 8080);
    if (hl == INVALID_ADDRESS)
        abort();
    http_register_default_handler(hl, closure(fuzz_heap, fz_handler, ss("default")));
    http_register_uri_handler(hl, ss("api"), closure(fuzz_heap, fz_handler, ss("api")));
    http_register_uri_handler(hl, ss("status"), closure(fuzz_heap, fz_handler, ss("status")));
    ch = connection_handler_from_http_listener(hl);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1)
        return 0;
    FUZZ_BEGIN();
    int chunks = 1 + (data[0] % 4);
    data++; size--;
    /* a fresh connection per input */
    input_buffer_handler ibh = apply(ch, closure(fuzz_heap, fz_sink));
    if (ibh == INVALID_ADDRESS)
        abort();
    size_t off = 0;
    boolean closed = false;
    for (int i = 0; i < chunks && !closed; i++) {
        size_t n = (i == chunks - 1) ? size - off : (size - off) / (chunks - i);
        buffer b = fuzz_buffer(data + off, n);
        off += n;
        closed = apply(ibh, b);
        deallocate_buffer(b);
    }
    /* connection closed by peer */
    apply(ibh, 0);
    FUZZ_END();
    return 0;
}

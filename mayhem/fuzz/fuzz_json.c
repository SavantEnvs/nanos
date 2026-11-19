/* JSON parser: json_parser() + parser_feed() (src/runtime/json.c), used for cloud
 * metadata and klib config responses. Modeled on test/unit/parser_test.c. */
#include "fuzz_common.h"

closure_function(0, 1, void, fz_finish,
                 void *v)
{
    if (v) {
        buffer out = allocate_buffer(fuzz_heap, 128);
        bprintf(out, "%v", v);
        deallocate_buffer(out);
        destruct_value(v, true);
    }
}

closure_function(0, 1, void, fz_err,
                 string s)
{
    (void)s;
}

static parse_finish finish;
static parse_error err;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    finish = closure(fuzz_heap, fz_finish);
    err = closure(fuzz_heap, fz_err);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FUZZ_BEGIN();
    parser p = json_parser(fuzz_heap, finish, err);
    if (p == INVALID_ADDRESS)
        abort();
    parser start = p;
    buffer b = fuzz_buffer(data, size);
    p = parser_feed(p, b);
    apply(p, CHARACTER_INVALID);
    deallocate_buffer(b);
    json_parser_free(start);
    FUZZ_END();
    return 0;
}

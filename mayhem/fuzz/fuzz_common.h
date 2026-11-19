/* Shared setup for the nanos libFuzzer harnesses (host build via src/unix_process).
 *
 * The nanos runtime reports fatal conditions (halt(), failed assert()) through
 * halt_with_code() -> exit(2) in src/unix_process/unix_process_runtime.c. Inside the
 * kernel these halt the whole VM, so a halt reached from untrusted data is a finding;
 * we lift that exit() to abort() while an input is being processed so it is reported
 * as a crash with a backtrace (docs: lift exit() on assert to abort()). Outside an
 * input (libFuzzer's own exit at the end of -runs=N) exit stays a normal exit.
 */
#ifndef NANOS_FUZZ_COMMON_H
#define NANOS_FUZZ_COMMON_H
#include <runtime.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

static heap fuzz_heap;
static volatile int fuzz_in_input;

static void fuzz_exit_hook(void)
{
    if (fuzz_in_input)
        abort();
}

static void fuzz_runtime_init(void)
{
    fuzz_heap = init_process_runtime();
}

/* registered on the first input, i.e. after libFuzzer's own exit hook, so that (atexit
   handlers run last-registered-first) ours aborts before libFuzzer reports a plain exit */
static inline void fuzz_begin(void)
{
    static int registered;
    if (!registered) {
        registered = 1;
        atexit(fuzz_exit_hook);
    }
    fuzz_in_input = 1;
}

#define FUZZ_BEGIN() fuzz_begin()
#define FUZZ_END()   (fuzz_in_input = 0)

/* copy the fuzz bytes into a runtime buffer owned by the caller */
static buffer fuzz_buffer(const uint8_t *data, size_t size)
{
    buffer b = allocate_buffer(fuzz_heap, size ? size : 1);
    if (b == INVALID_ADDRESS)
        abort();
    if (size)
        buffer_write(b, data, size);
    return b;
}
#endif

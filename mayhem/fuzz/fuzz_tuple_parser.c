/* nanos manifest / tuple text syntax: value_parser() + parser_feed()
 * (src/runtime/tuple_parser.c), the format mkfs and the kernel command line use.
 * Modeled on test/unit/parser_test.c parse_string(). */
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

/* Per-input arena over fuzz_heap. value_parser() allocates its closures from the heap
   it is given (a few per input character: ignore_whitespace(), terminal(), ...) and
   upstream never frees them -- there is no value_parser destructor -- so on the
   process heap RSS grows by ~1 GB within a few hundred inputs. Every allocation the
   parser makes from this heap is tracked and released after the input; individual
   deallocations the parser does make still free immediately. */
struct arena_hdr {
    struct arena_hdr *prev, *next;
    bytes size;
    u64 pad;    /* keep the returned block 16-byte aligned */
};

static struct heap arena;
static struct arena_hdr arena_list = { &arena_list, &arena_list, 0, 0 };

static u64 arena_alloc(heap h, bytes b)
{
    (void)h;
    u64 a = allocate_u64(fuzz_heap, b + sizeof(struct arena_hdr));
    if (a == INVALID_PHYSICAL)
        return a;
    struct arena_hdr *n = pointer_from_u64(a);
    n->size = b + sizeof(struct arena_hdr);
    n->next = arena_list.next;
    n->prev = &arena_list;
    arena_list.next->prev = n;
    arena_list.next = n;
    return a + sizeof(struct arena_hdr);
}

static void arena_dealloc(heap h, u64 a, bytes b)
{
    (void)h;
    struct arena_hdr *n = pointer_from_u64(a - sizeof(struct arena_hdr));
    n->prev->next = n->next;
    n->next->prev = n->prev;
    deallocate_u64(fuzz_heap, u64_from_pointer(n), n->size);
}

static void arena_reset(void)
{
    while (arena_list.next != &arena_list) {
        struct arena_hdr *n = arena_list.next;
        arena_list.next = n->next;
        deallocate_u64(fuzz_heap, u64_from_pointer(n), n->size);
    }
    arena_list.prev = &arena_list;
}

static parse_finish finish;
static parse_error err;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    finish = closure(fuzz_heap, fz_finish);
    err = closure(fuzz_heap, fz_err);
    arena.alloc = arena_alloc;
    arena.dealloc = arena_dealloc;
    arena.pagesize = fuzz_heap->pagesize;
    /* init_parser() builds the process-global charsets (whitespace, name_terminal, ...)
       on the heap of the first parser ever created; create that one on the process
       heap so the charsets outlive the per-input arena */
    (void)value_parser(fuzz_heap, finish, err);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FUZZ_BEGIN();
    /* a fresh parser per input: after a parse error value_parser() is left in its
       absorbing "kill" state, and an unterminated string or '#' comment keeps
       consuming whatever follows, so a parser shared across inputs would make each
       result depend on earlier inputs. Its closures live in the arena, freed below. */
    parser p = value_parser(&arena, finish, err);
    buffer b = fuzz_buffer(data, size);
    p = parser_feed(p, b);
    apply(p, CHARACTER_INVALID);
    deallocate_buffer(b);
    arena_reset();
    FUZZ_END();
    return 0;
}

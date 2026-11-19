/* TFS disk image: create_filesystem() over a memory-backed block device (tlog replay,
 * binary tuple decoding, tfs extent maps), then — like `tools/dump -t -d` — walk the
 * whole tree, print the metadata, read every file's contents into memory, and resolve
 * every entry's path from the root with filesystem_resolve_sstring_follow() so symlink
 * chains/loops stored in the image are followed (src/fs/fs.c). The input is the start of
 * a raw filesystem image (as made by `mkfs`) on a FUZZ_DISK_SIZE disk whose remaining
 * sectors read as zeros, so seeds can be a truncated image (mkfs puts file data ~1.5 MB
 * in); reads past the disk end fail like a short disk. */
#include "fuzz_common.h"
#include <storage.h>
#include <tfs.h>

static const uint8_t *img;
static size_t img_len;
static filesystem cur_fs;
static int walk_budget;

#define FUZZ_DISK_SIZE (64ull * MB)

static filesystem fz_get_root_fs(void)
{
    return cur_fs;
}

closure_function(0, 1, void, fz_bread,
                 storage_req req)
{
    if (req->op != STORAGE_OP_READSG) {
        apply(req->completion, timm("result", "unsupported op %d", req->op));
        return;
    }
    sg_list sg = req->data;
    u64 offset = req->blocks.start << SECTOR_OFFSET;
    u64 total = range_span(req->blocks) << SECTOR_OFFSET;
    if (offset > FUZZ_DISK_SIZE || total > FUZZ_DISK_SIZE - offset) {
        apply(req->completion, timm("result", "end of file"));
        return;
    }
    while (total > 0) {
        sg_buf sgb = sg_list_head_peek(sg);
        if (!sgb) {
            apply(req->completion, timm("result", "sg list too short"));
            return;
        }
        u64 n = MIN(sg_buf_len(sgb), total);
        u8 *dst = sgb->buf + sgb->offset;
        u64 have = offset < img_len ? MIN(n, img_len - offset) : 0;
        if (have)
            runtime_memcpy(dst, img + offset, have);
        if (have < n)
            runtime_memset(dst + have, 0, n - have);
        sg_consume(sg, n);
        offset += n;
        total -= n;
    }
    apply(req->completion, STATUS_OK);
}

closure_function(0, 1, status, fz_file_data,
                 buffer b)
{
    /* consume the contents, as dump -d would write them out */
    volatile u8 sum = 0;
    for (bytes i = 0; i < buffer_length(b); i++)
        sum += *(u8 *)buffer_ref(b, i);
    deallocate_buffer(b);
    return STATUS_OK;
}

closure_function(0, 1, void, fz_status,
                 status s)
{
    if (!is_ok(s))
        timm_dealloc(s);
}

static void walk(filesystem fs, tuple root, tuple w, buffer path, int depth);

closure_function(4, 2, boolean, fz_each_child,
                 filesystem, fs, tuple, root, buffer, path, int, depth,
                 value k, value v)
{
    if (!is_symbol(k) || !is_tuple(v))
        return true;
    if (k == sym_this(".") || k == sym_this(".."))
        return true;
    buffer p = allocate_buffer(fuzz_heap, buffer_length(bound(path)) + 32);
    if (buffer_length(bound(path)))
        bprintf(p, "%b/", bound(path));
    bprintf(p, "%b", symbol_string(k));
    walk(bound(fs), bound(root), (tuple)v, p, bound(depth) + 1);
    deallocate_buffer(p);
    return walk_budget > 0;
}

static void walk(filesystem fs, tuple root, tuple w, buffer path, int depth)
{
    if (--walk_budget < 0 || depth > 32)
        return;
    if (buffer_length(path)) {
        filesystem rfs = fs;
        tuple entry = 0, parent = 0;
        filesystem_resolve_sstring_follow(&rfs, root, buffer_to_sstring(path), &entry, &parent);
    }
    tuple c = children(w);
    if (c) {
        iterate(c, stack_closure(fz_each_child, fs, root, path, depth));
    } else if (get_tuple(w, sym(extents))) {
        filesystem_read_entire(fs, w, fuzz_heap, stack_closure(fz_file_data),
                               stack_closure(fz_status));
    }
}

static filesystem mounted;

closure_function(0, 2, void, fz_fs_complete,
                 filesystem fs, status s)
{
    if (!is_ok(s)) {
        timm_dealloc(s);
        return;
    }
    mounted = fs;
}

/* runs after create_filesystem() has returned: the completion may be invoked before
   create_filesystem() is done with the filesystem, so it must not be destroyed there */
static void use_filesystem(filesystem fs)
{
    cur_fs = fs;
    tuple root = filesystem_getroot(fs);
    u8 uuid[UUID_LEN];
    filesystem_get_uuid(fs, uuid);
    buffer rb = allocate_buffer(fuzz_heap, PAGESIZE);
    bprintf(rb, "Label: %s\n", filesystem_get_label(fs));
    print_value(rb, root, 0);
    deallocate_buffer(rb);
    walk_budget = 4096;
    buffer path = allocate_buffer(fuzz_heap, 64);
    walk(fs, root, root, path, 0);
    deallocate_buffer(path);
    cur_fs = 0;
    destroy_filesystem(fs);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    fs_set_path_helper(fz_get_root_fs, 0);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FUZZ_BEGIN();
    img = data;
    img_len = size;
    create_filesystem(fuzz_heap, SECTOR_SIZE, FUZZ_DISK_SIZE, stack_closure(fz_bread),
                      true, sstring_null(), stack_closure(fz_fs_complete));
    if (mounted) {
        filesystem fs = mounted;
        mounted = 0;
        use_filesystem(fs);
    }
    img = 0;
    img_len = 0;
    FUZZ_END();
    return 0;
}

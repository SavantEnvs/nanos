/* Flattened devicetree blob (src/devicetree/devicetree.c): the FDT walker the aarch64 and
 * riscv64 kernels run on the blob the hypervisor/firmware hands them at boot. Runs the
 * same entry points the kernel uses: dtb_blob_size(), devicetree_dump(),
 * dtb_read_memory_range(), dtb_find_node_by_path(), and an fdt_* walk of every node with
 * its reg/cells. */
#include "fuzz_common.h"
#include <devicetree.h>
#include <string.h>

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* the boot code maps and parses exactly dtb_blob_size() bytes, read from the
       header's magic + totalsize: the blob must hold at least that header word pair... */
    if (size < 8)
        return -1;
    FUZZ_BEGIN();
    void *dtb = malloc(size);
    memcpy(dtb, data, size);
    u32 blob = dtb_blob_size(dtb);
    /* ...and the declared totalsize must lie within the memory it was given */
    if (blob == 0 || blob > size) {
        free(dtb);
        FUZZ_END();
        return -1;
    }
    devicetree_dump(dtb);
    range mem = dtb_read_memory_range(dtb);
    (void)mem;
    dt_node chosen = dtb_find_node_by_path(dtb, ss("/chosen"));
    if (chosen) {
        dt_prop p = dtb_get_prop(dtb, chosen, ss("bootargs"));
        if (p)
            (void)dtb_read_value(dtb, chosen, p);
    }
    struct fdt f;
    if (dtb_parse_init(dtb, &f)) {
        int budget = 4096;
        for (dt_node n = fdt_get_node(&f); n && budget-- > 0; n = fdt_next_node(&f)) {
            sstring name = fdt_node_name(&f, n);
            (void)name;
            u32 acells, scells;
            fdt_get_cells(&f, &acells, &scells);
            dt_reg_iterator ri;
            if (fdt_get_reg(&f, acells, scells, &ri)) {
                int regs = 64;
                dt_reg_foreach(ri, r) {
                    if (regs-- <= 0)
                        break;
                }
            }
        }
    }
    free(dtb);
    FUZZ_END();
    return 0;
}

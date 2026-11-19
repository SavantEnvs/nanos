/* Mini XML scanner: xml_get_elem() / xml_elem_get_attr() (klib/xml.c), which parses the
 * XML bodies of cloud HTTP responses (Azure wireserver goal state / extensions config).
 * Drives it the way klib/cloud_azure.c does: find an element, take its data as a
 * sub-buffer, iterate child elements, read attributes and the element data. */
#include "fuzz_common.h"
#include <xml.h>

static void read_range(buffer b, bytes start, bytes len)
{
    volatile u8 sum = 0;
    for (bytes i = 0; i < len; i++)
        sum += *(u8 *)buffer_ref(b, start + i);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fuzz_runtime_init();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FUZZ_BEGIN();
    buffer content = fuzz_buffer(data, size);
    struct xml_elem e;
    if (xml_get_elem(content, ss("StatusUploadBlob"), &e))
        read_range(content, e.data_start, e.data_len);
    struct xml_elem ext_settings;
    if (xml_get_elem(content, ss("PluginSettings"), &ext_settings)) {
        buffer settings = alloca_wrap_buffer(buffer_ref(content, ext_settings.data_start),
                                             ext_settings.data_len);
        struct xml_elem plugin;
        while (xml_get_elem(settings, ss("Plugin"), &plugin)) {
            bytes s, l;
            if (xml_elem_get_attr(settings, &plugin, ss("name"), &s, &l))
                read_range(settings, s, l);
            if (xml_elem_get_attr(settings, &plugin, ss("version"), &s, &l))
                read_range(settings, s, l);
            buffer_consume(settings, plugin.data_start);
            struct xml_elem rt;
            if (xml_get_elem(settings, ss("RuntimeSettings"), &rt)) {
                if (xml_elem_get_attr(settings, &rt, ss("seqNo"), &s, &l))
                    read_range(settings, s, l);
                read_range(settings, rt.data_start, rt.data_len);
            }
            /* skip past the end of this element, as cloud_azure.c does */
            bytes end = plugin.start + plugin.len;
            if (end <= plugin.data_start)
                break;
            bytes skip = end - plugin.data_start;
            if (skip > buffer_length(settings))
                break;
            buffer_consume(settings, skip);
        }
    }
    deallocate_buffer(content);
    FUZZ_END();
    return 0;
}

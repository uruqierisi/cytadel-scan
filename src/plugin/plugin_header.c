#include "plugin_header.h"

#include <stdlib.h>
#include <string.h>

#include "field_utils.h"

void cytadel_plugin_header_free(cytadel_plugin_header_t *hdr) {
    if (hdr == NULL) {
        return;
    }
    free(hdr->script_name);
    free(hdr->script_version);
    free(hdr->family);
    free(hdr->dependencies);
    cytadel_plugin_free_string_array(hdr->required_keys, hdr->required_key_count);
    cytadel_plugin_free_string_array(hdr->cve, hdr->cve_count);
    free(hdr->cvss_vector);
    free(hdr->description);
    free(hdr->solution);
    free(hdr->source_path);
    memset(hdr, 0, sizeof(*hdr));
}

bool cytadel_plugin_severity_from_name(const char *name, int *out) {
    /* plugin-api.md §0: "Info=0, Low=1, Medium=2, High=3, Critical=4" --
     * §1.2's risk_factor field must match these names exactly,
     * case-sensitive. */
    static const struct {
        const char *name;
        int value;
    } table[] = {
        {"Info", 0}, {"Low", 1}, {"Medium", 2}, {"High", 3}, {"Critical", 4},
    };
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (strcmp(name, table[i].name) == 0) {
            *out = table[i].value;
            return true;
        }
    }
    return false;
}

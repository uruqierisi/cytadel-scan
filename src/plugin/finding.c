#include "finding_internal.h"

#include <stdlib.h>
#include <string.h>

#include "field_utils.h"
#include "log.h"

static void cytadel_finding_free_fields(cytadel_finding_t *f) {
    free(f->title);
    free(f->description);
    free(f->evidence);
    free(f->solution);
    cytadel_plugin_free_string_array(f->cve, f->cve_count);
    free(f->cpe);
    free(f->cvss_vector);
    free(f->script_name);
    memset(f, 0, sizeof(*f));
}

void cytadel_finding_list_free(cytadel_finding_list_t *list) {
    if (list == NULL) {
        return;
    }
    for (size_t i = 0; i < list->count; i++) {
        cytadel_finding_free_fields(&list->items[i]);
    }
    free(list->items);
    memset(list, 0, sizeof(*list));
}

int cytadel_finding_list_append(cytadel_finding_list_t *list, cytadel_finding_t *finding) {
    if (list->count == list->capacity) {
        size_t new_capacity = (list->capacity == 0) ? 4 : list->capacity * 2;
        cytadel_finding_t *grown = realloc(list->items, new_capacity * sizeof(*grown));
        if (grown == NULL) {
            cytadel_log_error("plugin: out of memory growing findings list past %zu entr%s",
                               list->capacity, (list->capacity == 1) ? "y" : "ies");
            cytadel_finding_free_fields(finding);
            return -1;
        }
        list->items = grown;
        list->capacity = new_capacity;
    }

    list->items[list->count] = *finding; /* ownership transfer -- see header comment */
    list->count++;
    memset(finding, 0, sizeof(*finding)); /* caller's copy no longer owns anything */
    return 0;
}

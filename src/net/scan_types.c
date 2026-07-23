#include "cytadel/net/scan_types.h"

#include <stdlib.h>
#include <string.h>

void cytadel_host_result_free(cytadel_host_result_t *result) {
    if (result == NULL) {
        return;
    }
    free(result->ports);
    cytadel_kb_free(result->kb);
    cytadel_finding_list_free(&result->findings);
    memset(result, 0, sizeof(*result));
}

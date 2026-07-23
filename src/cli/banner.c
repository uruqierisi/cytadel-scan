#include "banner.h"

#include "cytadel/core/version.h"

/* This file must never reference the C standard library's "standard
 * output" stream by name -- see banner.h's own doc comment, and
 * tests/unit/test_banner.c's structural check, which reads this exact
 * source file's text and asserts that literal token never appears. Every
 * write below goes through the caller-supplied `stream` parameter only. */

bool cytadel_banner_should_print(bool no_banner_flag, bool stderr_is_tty) {
    if (no_banner_flag) {
        return false;
    }
    return stderr_is_tty;
}

void cytadel_banner_print(FILE *stream) {
    if (stream == NULL) {
        return;
    }

    /* Plain-ASCII 5x7 dot-matrix "CYTADEL" wordmark (no non-ASCII bytes --
     * stays legible/portable across any terminal encoding/locale). */
    fputs(
        "\n"
        " ###  #   # #####  ###  ####  ##### #    \n"
        "#   # #   #   #   #   # #   # #     #    \n"
        "#      # #    #   #   # #   # ####  #    \n"
        "#       #     #   ##### #   # #     #    \n"
        "#       #     #   #   # #   # #     #    \n"
        "#   #   #     #   #   # #   # #     #    \n"
        " ###    #     #   #   # ####  ##### #####\n"
        "\n",
        stream);

    fprintf(stream, "  Cytadel Scan v%s -- detection-only vulnerability scanner\n\n",
            CYTADEL_VERSION_STRING);
}

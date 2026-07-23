#ifndef CYTADEL_BANNER_H
#define CYTADEL_BANNER_H

#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Cosmetic startup ASCII-art banner for `cytadel-scan`'s live-scan path
 * ONLY (main.c never calls this from the `report`/`sync` subcommand
 * dispatch -- those are read-only/self-sync paths that must stay byte-clean
 * on stdout for machine consumption, and are handled entirely before this
 * module is ever reached; see main.c's dispatch order).
 *
 * Split out of main.c (rather than inlined) purely so the print/suppress
 * DECISION is a small, pure, directly unit-testable function -- see
 * cytadel_banner_should_print() below -- independent of any real isatty()/
 * terminal state.
 */

/* Decides whether the startup banner should be printed, given:
 *   - no_banner_flag: true if --no-banner was passed on the command line.
 *   - stderr_is_tty: true if the destination stream (stderr, in production)
 *     is an interactive terminal (isatty(fileno(stderr)) != 0). Callers
 *     compute this themselves -- this function never calls isatty() itself,
 *     which is exactly what makes it unit-testable without a real terminal
 *     or any FILE stream / fd plumbing.
 *
 * The banner is suppressed whenever EITHER --no-banner was given OR the
 * destination is not a TTY -- redirected/piped output and CI logs must
 * never be polluted with cosmetic banner bytes. */
bool cytadel_banner_should_print(bool no_banner_flag, bool stderr_is_tty);

/* Writes the Cytadel ASCII-art startup banner (wordmark + version tagline)
 * to `stream`. Purely cosmetic and best-effort:
 *   - Never writes to any stream other than the one passed in -- callers
 *     MUST pass stderr in production; this function never references
 *     stdout in any way, by construction (grep-verifiable: banner.c
 *     contains no reference to `stdout`).
 *   - Never checks/propagates a write failure -- a cosmetic banner losing a
 *     few bytes to a full disk/broken pipe on stderr is not worth turning
 *     into a hard failure of the scan itself.
 * A NULL stream is a no-op. */
void cytadel_banner_print(FILE *stream);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_BANNER_H */

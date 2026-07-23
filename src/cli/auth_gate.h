#ifndef CYTADEL_AUTH_GATE_H
#define CYTADEL_AUTH_GATE_H

#include <stdbool.h>
#include <stddef.h>

/* Mandatory startup authorization gate (the mandatory authorization-gate rule;
 * docs/contracts/db-schema.md §6 `scans.authorization_method`). The tool
 * must refuse to scan until the operator explicitly confirms authorization,
 * either via --i-am-authorized or an interactive stdin prompt when stdin is
 * a TTY. Non-TTY + no flag is always a refusal -- authorization is never
 * assumed. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_AUTH_METHOD_FLAG = 0,        /* db-schema.md: authorization_method = 'flag' */
    CYTADEL_AUTH_METHOD_INTERACTIVE = 1  /* db-schema.md: authorization_method = 'interactive' */
} cytadel_auth_method_t;

typedef enum {
    CYTADEL_AUTH_RESULT_AUTHORIZED = 0,
    CYTADEL_AUTH_RESULT_REFUSED = 1
} cytadel_auth_result_t;

typedef struct {
    cytadel_auth_result_t result;
    cytadel_auth_method_t method;  /* only meaningful when result == AUTHORIZED */
    const char *reason;            /* static string explaining a REFUSED outcome;
                                     * NULL when result == AUTHORIZED. */
} cytadel_auth_decision_t;

/* Injectable interactive-prompt callback: returns true iff the operator
 * confirmed authorization at the prompt. A function pointer so the decision
 * logic below is unit-testable without a real TTY/stdin. */
typedef bool (*cytadel_auth_prompt_fn)(void);

/* Pure decision function -- the only I/O it performs is optionally invoking
 * prompt_fn(). Never assumes authorization: the only paths that return
 * AUTHORIZED are (a) is_flag_present, or (b) is_stdin_tty and prompt_fn()
 * returns true. If is_stdin_tty is true and prompt_fn is NULL, refuses
 * defensively rather than assuming authorization. */
cytadel_auth_decision_t cytadel_auth_gate_decide(bool is_flag_present,
                                                  bool is_stdin_tty,
                                                  cytadel_auth_prompt_fn prompt_fn);

/* Real interactive prompt: reads a line from stdin, asks the operator to
 * type "yes" to confirm. This is the prompt_fn passed by main() in
 * production; unit tests inject their own stub instead. */
bool cytadel_auth_gate_default_prompt(void);

/* Best-effort default operator identity for --authorized-by when the flag
 * is omitted: the OS user running the process (the password-database entry
 * for the real uid, falling back to $USER / $LOGNAME -- see S2 note in
 * auth_gate.c: the passwd entry is preferred because environment variables
 * are spoofable). Writes into buf (NUL-terminated, truncated if necessary)
 * and always returns buf. Falls back to the literal string "unknown" if no
 * identity can be determined. This value is advisory only, never a proof
 * of identity. */
const char *cytadel_auth_default_operator(char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_AUTH_GATE_H */

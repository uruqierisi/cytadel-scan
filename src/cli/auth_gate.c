#define _POSIX_C_SOURCE 200809L

#include "auth_gate.h"

#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

cytadel_auth_decision_t cytadel_auth_gate_decide(bool is_flag_present,
                                                  bool is_stdin_tty,
                                                  cytadel_auth_prompt_fn prompt_fn) {
    cytadel_auth_decision_t decision;
    memset(&decision, 0, sizeof(decision));

    if (is_flag_present) {
        decision.result = CYTADEL_AUTH_RESULT_AUTHORIZED;
        decision.method = CYTADEL_AUTH_METHOD_FLAG;
        decision.reason = NULL;
        return decision;
    }

    if (is_stdin_tty) {
        if (prompt_fn == NULL) {
            /* Defensive: never assume authorization just because no prompt
             * function was supplied. This should not happen in production
             * (main() always passes cytadel_auth_gate_default_prompt). */
            decision.result = CYTADEL_AUTH_RESULT_REFUSED;
            decision.reason = "internal error: no interactive prompt function was provided";
            return decision;
        }
        if (prompt_fn()) {
            decision.result = CYTADEL_AUTH_RESULT_AUTHORIZED;
            decision.method = CYTADEL_AUTH_METHOD_INTERACTIVE;
            decision.reason = NULL;
            return decision;
        }
        decision.result = CYTADEL_AUTH_RESULT_REFUSED;
        decision.reason = "operator declined interactive authorization confirmation";
        return decision;
    }

    /* Not a TTY and no --i-am-authorized flag: never assume authorization. */
    decision.result = CYTADEL_AUTH_RESULT_REFUSED;
    decision.reason = "stdin is not a TTY and --i-am-authorized was not provided; "
                       "refusing to assume authorization";
    return decision;
}

bool cytadel_auth_gate_default_prompt(void) {
    fprintf(stderr,
            "This tool performs detection-only vulnerability scanning. You must be\n"
            "explicitly authorized to scan the specified target(s).\n"
            "Type 'yes' to confirm you are authorized, anything else to abort: ");
    fflush(stderr);

    char line[64];
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return false;
    }

    size_t len = strlen(line);
    if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
    } else {
        /* The typed line was longer than our buffer; drain the remainder
         * so leftover bytes don't confuse anything that reads stdin later. */
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {
            /* discard */
        }
    }

    return strcmp(line, "yes") == 0;
}

const char *cytadel_auth_default_operator(char *buf, size_t buf_len) {
    if (buf == NULL || buf_len == 0) {
        return buf;
    }
    buf[0] = '\0';

    /* S2: prefer the passwd-database name for the real uid over
     * $USER/$LOGNAME. Environment variables are trivially spoofable by the
     * invoking user (e.g. `USER=root cytadel-scan ...`), whereas
     * getpwuid(getuid()) reflects the account that actually owns the
     * process. Note this value is advisory only, not an attestation: in
     * Milestone 1 it is only logged (main.c, via cytadel_log_audit()); it
     * will become the equally-advisory `scans.authorized_by` column in
     * Milestone 7 (docs/contracts/db-schema.md §6), which nothing treats
     * as a cryptographic proof of identity. */
    struct passwd *pw = getpwuid(getuid());
    if (pw != NULL && pw->pw_name != NULL && pw->pw_name[0] != '\0') {
        strncpy(buf, pw->pw_name, buf_len - 1);
        buf[buf_len - 1] = '\0';
        return buf;
    }

    const char *env_user = getenv("USER");
    if (env_user == NULL || env_user[0] == '\0') {
        env_user = getenv("LOGNAME");
    }
    if (env_user != NULL && env_user[0] != '\0') {
        strncpy(buf, env_user, buf_len - 1);
        buf[buf_len - 1] = '\0';
        return buf;
    }

    strncpy(buf, "unknown", buf_len - 1);
    buf[buf_len - 1] = '\0';
    return buf;
}

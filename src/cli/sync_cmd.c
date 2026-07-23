#include "sync_cmd.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

/* M9 Phase 4a: see sync_cmd.h for the full design/contract this file
 * implements. This comment covers implementation details only.
 */

/* If argv[*i] is a flag that requires a value, consumes and returns
 * argv[*i + 1] (advancing *i), or returns NULL and prints an error if no
 * value follows. Private duplicate of report_cmd.c's own helper of the same
 * shape -- see that file's own comment for why this project keeps one copy
 * per subcommand rather than sharing it. */
static const char *cytadel_sync_cmd_arg_value(int argc, char *const argv[], int *i, const char *flag_name) {
    if (*i + 1 >= argc) {
        fprintf(stderr, "cytadel-scan sync: error: %s requires an argument\n", flag_name);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

void cytadel_sync_cmd_print_usage(FILE *stream, const char *prog_name) {
    const char *name = (prog_name != NULL) ? prog_name : "cytadel-scan";
    fprintf(stream,
            "Usage: %s sync [--db PATH] [--now ISO8601] [-h]\n"
            "\n"
            "Catches this tool's local vulnerability database up to the live NVD CVE\n"
            "feed (CYTADEL_DB_PATH -- see .env.example). This only reaches out to the\n"
            "public NVD API to update the LOCAL database -- it never scans or contacts\n"
            "any operator-specified target, so the mandatory startup authorization gate\n"
            "does not apply here.\n"
            "\n"
            "Options:\n"
            "  --db <PATH>       DB path to open+migrate (default: CYTADEL_DB_PATH env).\n"
            "  --now <ISO8601>   Catch up to this instant instead of the real current\n"
            "                    time (\"YYYY-MM-DDTHH:MM:SS.sssZ\" or \"YYYY-MM-DD\") --\n"
            "                    for backfilling or testing only.\n"
            "  -h, --help        Show this help text and exit.\n",
            name);
}

cytadel_sync_cmd_parse_status_t cytadel_sync_cmd_parse_args(int argc, char *const argv[],
                                                             cytadel_sync_cmd_args_t *out_args) {
    if (out_args == NULL) {
        return CYTADEL_SYNC_CMD_PARSE_ERROR;
    }

    memset(out_args, 0, sizeof(*out_args));

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            out_args->want_help = true;
            return CYTADEL_SYNC_CMD_PARSE_HELP;
        }
        if (strcmp(arg, "--db") == 0) {
            const char *val = cytadel_sync_cmd_arg_value(argc, argv, &i, "--db");
            if (val == NULL) {
                return CYTADEL_SYNC_CMD_PARSE_ERROR;
            }
            out_args->db_path = val;
            continue;
        }
        if (strcmp(arg, "--now") == 0) {
            const char *val = cytadel_sync_cmd_arg_value(argc, argv, &i, "--now");
            if (val == NULL) {
                return CYTADEL_SYNC_CMD_PARSE_ERROR;
            }
            out_args->now_override = val;
            continue;
        }

        fprintf(stderr, "cytadel-scan sync: error: unknown or unexpected argument '%s'\n", arg);
        return CYTADEL_SYNC_CMD_PARSE_ERROR;
    }

    return CYTADEL_SYNC_CMD_PARSE_OK;
}

bool cytadel_sync_cmd_resolve_db_path(const cytadel_sync_cmd_args_t *args, const char **out_db_path) {
    if (args == NULL || out_db_path == NULL) {
        return false;
    }

    if (args->db_path != NULL && args->db_path[0] != '\0') {
        *out_db_path = args->db_path;
        return true;
    }

    const char *env_path = getenv("CYTADEL_DB_PATH");
    if (env_path != NULL && env_path[0] != '\0') {
        *out_db_path = env_path;
        return true;
    }

    return false;
}

bool cytadel_sync_cmd_resolve_now(const cytadel_sync_cmd_args_t *args, char *out_wallclock_buf,
                                   size_t out_wallclock_buf_len, const char **out_now) {
    if (args == NULL || out_now == NULL) {
        return false;
    }

    if (args->now_override != NULL && args->now_override[0] != '\0') {
        *out_now = args->now_override;
        return true;
    }

    if (out_wallclock_buf == NULL || out_wallclock_buf_len < CYTADEL_ISO8601_BUF_LEN) {
        return false;
    }
    if (cytadel_log_format_timestamp_utc(out_wallclock_buf, out_wallclock_buf_len) != 0) {
        return false;
    }
    *out_now = out_wallclock_buf;
    return true;
}

void cytadel_sync_cmd_build_fetch_config(cytadel_nvd_fetch_config_t *out_cfg) {
    if (out_cfg == NULL) {
        return;
    }

    cytadel_nvd_fetch_config_init_default(out_cfg);

    const char *base_url_override = getenv("CYTADEL_NVD_API_URL");
    if (base_url_override != NULL && base_url_override[0] != '\0') {
        out_cfg->base_url = base_url_override;
    }
}

int cytadel_sync_cmd_run(const cytadel_sync_cmd_args_t *args) {
    if (args == NULL) {
        fprintf(stderr, "cytadel-scan sync: error: internal error (no arguments)\n");
        return EXIT_FAILURE;
    }

    const char *db_path = NULL;
    if (!cytadel_sync_cmd_resolve_db_path(args, &db_path)) {
        fprintf(stderr,
                "cytadel-scan sync: error: no DB path given -- pass --db PATH or set "
                "CYTADEL_DB_PATH (see .env.example)\n");
        return EXIT_FAILURE;
    }

    cytadel_db_t *db = NULL;
    cytadel_db_status_t db_status = cytadel_db_open(db_path, &db);
    if (db_status != CYTADEL_DB_OK) {
        fprintf(stderr, "cytadel-scan sync: error: could not open DB '%s' (%s)\n", db_path,
                cytadel_db_status_to_string(db_status));
        return EXIT_FAILURE;
    }

    db_status = cytadel_db_migrate(db);
    if (db_status != CYTADEL_DB_OK) {
        fprintf(stderr, "cytadel-scan sync: error: could not migrate DB '%s' (%s)\n", db_path,
                cytadel_db_status_to_string(db_status));
        cytadel_db_close(db);
        return EXIT_FAILURE;
    }

    cytadel_nvd_fetch_config_t cfg;
    cytadel_sync_cmd_build_fetch_config(&cfg);

    char now_wallclock_buf[CYTADEL_ISO8601_BUF_LEN];
    const char *now = NULL;
    if (!cytadel_sync_cmd_resolve_now(args, now_wallclock_buf, sizeof(now_wallclock_buf), &now)) {
        fprintf(stderr, "cytadel-scan sync: error: could not resolve the current time\n");
        cytadel_db_close(db);
        return EXIT_FAILURE;
    }

    cytadel_nvd_catchup_counts_t counts;
    memset(&counts, 0, sizeof(counts));
    cytadel_nvd_catchup_status_t status = cytadel_nvd_catchup(db, &cfg, now, &counts);

    cytadel_db_close(db);
    db = NULL;

    printf("cytadel-scan sync: %zu window(s) completed, %zu page(s) fetched, %zu CVE(s) ingested, "
           "%zu CVE(s) skipped\n",
           counts.windows_completed, counts.pages_fetched, counts.cve_ingested, counts.cve_skipped);

    if (status == CYTADEL_NVD_CATCHUP_OK) {
        /* nvd_catchup.h's own loop invariant: a fully successful catch-up
         * (this OK status) only ever stops once its cursor has reached
         * `now` exactly -- so whenever at least one window ran, the
         * durably-committed watermark this call just advanced IS `now`
         * itself; this is reported without any extra DB read (no accessor
         * for it exists, or is needed, beyond this). Zero windows means the
         * watermark was already at or beyond `now` before this call ever
         * started -- its exact prior value is simply left alone and not
         * fabricated here. */
        if (counts.windows_completed > 0) {
            printf("cytadel-scan sync: watermark advanced to %s\n", now);
        } else {
            printf("cytadel-scan sync: watermark already current -- no sync needed\n");
        }
        return EXIT_SUCCESS;
    }

    fprintf(stderr,
            "cytadel-scan sync: error: catch-up failed after %zu completed window(s) (%s)\n",
            counts.windows_completed, cytadel_nvd_catchup_status_to_string(status));
    return EXIT_FAILURE;
}

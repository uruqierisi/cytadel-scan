#include "report_cmd.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* Milestone 8 slice 5: see report_cmd.h for the full design/contract this
 * file implements. This comment covers implementation details only.
 */

/* If argv[*i] is a flag that requires a value, consumes and returns
 * argv[*i + 1] (advancing *i), or returns NULL and prints an error if no
 * value follows. Mirrors cli_args.c's own cytadel_cli_arg_value() -- kept
 * as a private duplicate (not shared) since the two parsers are otherwise
 * fully independent and this is the only piece of logic they'd otherwise
 * need to share. */
static const char *cytadel_report_cmd_arg_value(int argc, char *const argv[], int *i, const char *flag_name) {
    if (*i + 1 >= argc) {
        fprintf(stderr, "cytadel-scan report: error: %s requires an argument\n", flag_name);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

void cytadel_report_cmd_print_usage(FILE *stream, const char *prog_name) {
    const char *name = (prog_name != NULL) ? prog_name : "cytadel-scan";
    fprintf(stream,
            "Usage: %s report (--latest | --scan-id N) [--format html|json] [-o FILE]\n"
            "\n"
            "Renders a previously-run scan's findings from the local vuln DB\n"
            "(CYTADEL_DB_PATH -- see .env.example). Read-only: this subcommand does not\n"
            "scan (no packet ever leaves the host), so the mandatory startup\n"
            "authorization gate does not apply here.\n"
            "\n"
            "Options:\n"
            "  --latest          Report the most recently started scan\n"
            "                    (ORDER BY started_at DESC LIMIT 1).\n"
            "  --scan-id <N>     Report exactly this scan_id. Exactly one of --latest\n"
            "                    or --scan-id is required.\n"
            "  --format <fmt>    One of: html, json (default: html).\n"
            "  -o <FILE>         Write the report to FILE (default: stdout).\n"
            "  --help            Show this help text and exit.\n",
            name);
}

cytadel_report_cmd_parse_status_t cytadel_report_cmd_parse_args(int argc, char *const argv[],
                                                                 cytadel_report_cmd_args_t *out_args) {
    if (out_args == NULL) {
        return CYTADEL_REPORT_CMD_PARSE_ERROR;
    }

    memset(out_args, 0, sizeof(*out_args));
    out_args->format = CYTADEL_REPORT_CMD_FORMAT_HTML;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            out_args->want_help = true;
            return CYTADEL_REPORT_CMD_PARSE_HELP;
        }
        if (strcmp(arg, "--latest") == 0) {
            out_args->has_latest = true;
            continue;
        }
        if (strcmp(arg, "--scan-id") == 0) {
            const char *val = cytadel_report_cmd_arg_value(argc, argv, &i, "--scan-id");
            if (val == NULL) {
                return CYTADEL_REPORT_CMD_PARSE_ERROR;
            }
            errno = 0;
            char *end = NULL;
            long long parsed = strtoll(val, &end, 10);
            if (end == val || *end != '\0' || errno == ERANGE || parsed <= 0) {
                fprintf(stderr,
                        "cytadel-scan report: error: invalid --scan-id '%s' "
                        "(expected a positive integer scan_id)\n",
                        val);
                return CYTADEL_REPORT_CMD_PARSE_ERROR;
            }
            out_args->scan_id = parsed;
            out_args->has_scan_id = true;
            continue;
        }
        if (strcmp(arg, "--format") == 0) {
            const char *val = cytadel_report_cmd_arg_value(argc, argv, &i, "--format");
            if (val == NULL) {
                return CYTADEL_REPORT_CMD_PARSE_ERROR;
            }
            if (strcmp(val, "html") == 0) {
                out_args->format = CYTADEL_REPORT_CMD_FORMAT_HTML;
            } else if (strcmp(val, "json") == 0) {
                out_args->format = CYTADEL_REPORT_CMD_FORMAT_JSON;
            } else {
                fprintf(stderr, "cytadel-scan report: error: invalid --format '%s' (expected html or json)\n", val);
                return CYTADEL_REPORT_CMD_PARSE_ERROR;
            }
            continue;
        }
        if (strcmp(arg, "-o") == 0) {
            const char *val = cytadel_report_cmd_arg_value(argc, argv, &i, "-o");
            if (val == NULL) {
                return CYTADEL_REPORT_CMD_PARSE_ERROR;
            }
            out_args->output_path = val;
            continue;
        }

        fprintf(stderr, "cytadel-scan report: error: unknown or unexpected argument '%s'\n", arg);
        return CYTADEL_REPORT_CMD_PARSE_ERROR;
    }

    /* Exactly one of --latest / --scan-id is required: both true or both
     * false are both rejected by this single equality check. */
    if (out_args->has_latest == out_args->has_scan_id) {
        fprintf(stderr, "cytadel-scan report: error: give exactly one of --latest or --scan-id <N>\n");
        return CYTADEL_REPORT_CMD_PARSE_ERROR;
    }

    return CYTADEL_REPORT_CMD_PARSE_OK;
}

cytadel_report_status_t cytadel_report_cmd_resolve_scan_id(cytadel_db_t *db, const cytadel_report_cmd_args_t *args,
                                                            long long *out_scan_id) {
    if (db == NULL || args == NULL || out_scan_id == NULL) {
        return CYTADEL_REPORT_ERR_INVALID_ARG;
    }
    if (args->has_scan_id) {
        *out_scan_id = args->scan_id;
        return CYTADEL_REPORT_OK;
    }
    return cytadel_report_find_latest_scan_id(db, out_scan_id);
}

cytadel_report_status_t cytadel_report_cmd_render(cytadel_db_t *db, long long scan_id,
                                                   cytadel_report_cmd_format_t format, cytadel_report_buf_t *out) {
    switch (format) {
        case CYTADEL_REPORT_CMD_FORMAT_HTML:
            return cytadel_report_html(db, scan_id, out);
        case CYTADEL_REPORT_CMD_FORMAT_JSON:
            return cytadel_report_json(db, scan_id, out);
    }
    /* Unreachable given cytadel_report_cmd_parse_args() only ever sets one
     * of the two enumerators above -- kept (not a `default:` label, per
     * this project's exhaustive-switch convention -- scan_persist.h's own
     * accumulate_outcome() comment) purely so this function always has a
     * well-defined return for every cytadel_report_cmd_format_t value a
     * future caller might construct directly. */
    return CYTADEL_REPORT_ERR_INVALID_ARG;
}

int cytadel_report_cmd_run(const cytadel_report_cmd_args_t *args) {
    if (args == NULL) {
        fprintf(stderr, "cytadel-scan report: error: internal error (no arguments)\n");
        return EXIT_FAILURE;
    }

    const char *db_path = getenv("CYTADEL_DB_PATH");
    if (db_path == NULL || db_path[0] == '\0') {
        fprintf(stderr,
                "cytadel-scan report: error: CYTADEL_DB_PATH is not set (see .env.example)\n");
        return EXIT_FAILURE;
    }

    cytadel_db_t *db = NULL;
    cytadel_db_status_t db_status = cytadel_db_open(db_path, &db);
    if (db_status != CYTADEL_DB_OK) {
        fprintf(stderr, "cytadel-scan report: error: could not open DB '%s' (%s)\n", db_path,
                cytadel_db_status_to_string(db_status));
        return EXIT_FAILURE;
    }

    db_status = cytadel_db_migrate(db);
    if (db_status != CYTADEL_DB_OK) {
        fprintf(stderr, "cytadel-scan report: error: could not migrate DB '%s' (%s)\n", db_path,
                cytadel_db_status_to_string(db_status));
        cytadel_db_close(db);
        return EXIT_FAILURE;
    }

    long long scan_id = 0;
    cytadel_report_status_t status = cytadel_report_cmd_resolve_scan_id(db, args, &scan_id);
    if (status == CYTADEL_REPORT_ERR_NOT_FOUND) {
        if (args->has_scan_id) {
            fprintf(stderr, "cytadel-scan report: error: no scan with scan_id=%lld exists\n", args->scan_id);
        } else {
            fprintf(stderr, "cytadel-scan report: error: no scans exist yet in '%s' -- nothing to report on\n",
                    db_path);
        }
        cytadel_db_close(db);
        return EXIT_FAILURE;
    }
    if (status != CYTADEL_REPORT_OK) {
        fprintf(stderr, "cytadel-scan report: error: could not resolve scan_id (%s)\n",
                cytadel_report_status_to_string(status));
        cytadel_db_close(db);
        return EXIT_FAILURE;
    }

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    status = cytadel_report_cmd_render(db, scan_id, args->format, &out);
    cytadel_db_close(db);
    db = NULL;

    if (status == CYTADEL_REPORT_ERR_NOT_FOUND) {
        fprintf(stderr, "cytadel-scan report: error: no scan with scan_id=%lld exists\n", scan_id);
        cytadel_report_buf_free(&out);
        return EXIT_FAILURE;
    }
    if (status != CYTADEL_REPORT_OK) {
        fprintf(stderr, "cytadel-scan report: error: could not render report (%s)\n",
                cytadel_report_status_to_string(status));
        cytadel_report_buf_free(&out);
        return EXIT_FAILURE;
    }

    FILE *out_stream = stdout;
    bool close_stream = false;
    if (args->output_path != NULL) {
        out_stream = fopen(args->output_path, "wb");
        if (out_stream == NULL) {
            fprintf(stderr, "cytadel-scan report: error: could not open '%s' for writing\n", args->output_path);
            cytadel_report_buf_free(&out);
            return EXIT_FAILURE;
        }
        close_stream = true;
    }

    bool write_ok = true;
    if (out.len > 0) {
        size_t written = fwrite(out.data, 1, out.len, out_stream);
        write_ok = (written == out.len);
    }

    if (close_stream) {
        if (fclose(out_stream) != 0) {
            write_ok = false;
        }
    } else if (fflush(out_stream) != 0) {
        write_ok = false;
    }

    cytadel_report_buf_free(&out);

    if (!write_ok) {
        fprintf(stderr, "cytadel-scan report: error: failed writing report output\n");
        /* A partial write (e.g. disk full mid-report) must not leave a
         * truncated file that looks like a complete report -- for a
         * client-facing deliverable a half-report is worse than none. Remove
         * the file we created so a failed run leaves no misleading artifact.
         * Only unlink a path we opened ourselves (never stdout). */
        if (args->output_path != NULL) {
            remove(args->output_path);
        }
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

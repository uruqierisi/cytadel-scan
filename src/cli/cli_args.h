#ifndef CYTADEL_CLI_ARGS_H
#define CYTADEL_CLI_ARGS_H

#include <stdbool.h>
#include <stdio.h>

#include "cytadel/core/worker_pool.h"
#include "log.h"

/* CLI surface. Milestone 1: parse/store only. Milestone 2 added single-host
 * scan flags. Milestone 3 adds multi-target expansion (CIDR/host-list/
 * --targets-file, via cytadel_target_list_parse() -- target_spec here is
 * just the raw, unexpanded spec string) and worker-pool flags. */

#ifdef __cplusplus
extern "C" {
#endif

/* Default TCP connect() timeout in milliseconds, used when
 * --connect-timeout-ms is not given. Mirrors CYTADEL_CONNECT_TIMEOUT_MS's
 * documented default in .env.example; there is no .env loader yet (that is
 * a future milestone), so this is the compiled-in fallback until one
 * exists. */
#define CYTADEL_CLI_DEFAULT_CONNECT_TIMEOUT_MS 3000

/* Default discovery-probe timeout in milliseconds, used when
 * --discovery-timeout-ms is not given. Matches host_scan.c's own
 * independent fallback (cytadel_host_scan() defaults discovery_timeout_ms
 * to 1000 when opts is NULL) -- Milestone 2 folded this into
 * --connect-timeout-ms; Milestone 3 gives it its own flag/default so the
 * two timeouts are no longer silently tied together. */
#define CYTADEL_CLI_DEFAULT_DISCOVERY_TIMEOUT_MS 1000

/* Default --max-workers, mirroring CYTADEL_MAX_WORKERS in .env.example.
 * The hard ceiling (CYTADEL_WORKER_POOL_HARD_CAP_WORKERS) lives in
 * worker_pool.h, shared by both the CLI validator below and the pool
 * itself so the two never drift apart. */
#define CYTADEL_CLI_DEFAULT_MAX_WORKERS CYTADEL_WORKER_POOL_DEFAULT_MAX_WORKERS

typedef struct {
    const char *target_spec;      /* positional; the raw, unexpanded target spec
                                    * (single host, CIDR, or comma-separated list).
                                    * NULL if omitted -- valid only when
                                    * targets_file is given instead (or as well).
                                    * Aliases into argv -- not owned, not allocated. */
    const char *targets_file;     /* --targets-file <path>; NULL if not given.
                                    * Combined with target_spec (both may supply
                                    * targets at once) by cytadel_target_list_parse(). */
    bool has_i_am_authorized;
    const char *authorized_by;    /* NULL if --authorized-by was not given;
                                    * caller applies the OS-user default. */
    cytadel_log_level_t log_level;
    bool has_log_level;           /* false -> log_level holds the default (INFO) */
    const char *log_file;         /* NULL if --log-file was not given */

    /* Milestone 2: single-host scan flags. port_spec/connect_timeout_ms
     * alias into argv or hold compiled-in defaults -- see cli_args.c for
     * the exact default values/grammar (also documented in
     * cytadel_cli_print_usage()). */
    const char *port_spec;        /* NULL -> CYTADEL_DEFAULT_PORT_SPEC (see port_range.h) */
    bool skip_discovery;          /* --skip-discovery: treat host as up, no probe */
    int connect_timeout_ms;
    bool has_connect_timeout_ms;  /* false -> connect_timeout_ms holds the default */

    /* Milestone 3: multi-target worker-pool flags. */
    int discovery_timeout_ms;
    bool has_discovery_timeout_ms;  /* false -> discovery_timeout_ms holds the default */
    int max_workers;
    bool has_max_workers;           /* false -> max_workers holds the default */

    /* Milestone 5: --plugins-dir <path>. NULL if not given -- main.c then
     * tries the compiled-in default ("plugins", relative to CWD) as a
     * best-effort (missing default directory is not an error: the scan
     * simply runs without any plugin phase). An EXPLICITLY given
     * --plugins-dir that fails to load IS a hard CLI error (the operator
     * asked for a specific plugin set that could not be honored). */
    const char *plugins_dir;

    /* --no-banner: unconditionally suppresses the startup ASCII-art banner
     * (src/cli/banner.h), regardless of whether stderr is a TTY. See
     * cytadel_banner_should_print(). */
    bool no_banner;

    bool want_help;
    bool want_version;
} cytadel_cli_args_t;

typedef enum {
    CYTADEL_CLI_PARSE_OK = 0,
    CYTADEL_CLI_PARSE_HELP,
    CYTADEL_CLI_PARSE_VERSION,
    CYTADEL_CLI_PARSE_ERROR
} cytadel_cli_parse_status_t;

/* Parses argv[1..argc-1]. On CYTADEL_CLI_PARSE_ERROR a human-readable
 * message has already been written to stderr. On CYTADEL_CLI_PARSE_HELP /
 * CYTADEL_CLI_PARSE_VERSION, out_args->want_help / want_version is set and
 * the caller should print usage/version and exit 0 without inspecting the
 * rest of *out_args. Never allocates: every string field in *out_args
 * aliases into argv, whose lifetime the caller (main()) owns. */
cytadel_cli_parse_status_t cytadel_cli_parse_args(int argc, char *const argv[],
                                                   cytadel_cli_args_t *out_args);

void cytadel_cli_print_usage(FILE *stream, const char *prog_name);
void cytadel_cli_print_version(FILE *stream);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CLI_ARGS_H */

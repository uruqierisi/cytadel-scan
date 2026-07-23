#ifndef CYTADEL_PLUGIN_PLUGIN_H
#define CYTADEL_PLUGIN_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* Lua 5.4 plugin engine (Milestone 5) -- the first code realization of
 * docs/contracts/plugin-api.md (FROZEN CONTRACT). Every phase/step number
 * cited in comments throughout src/plugin ("§4.1 step 3", "§2.9", ...)
 * refers to that document; where a comment cites a section, that section is
 * the authoritative source and the C code is just this milestone's
 * implementation of it.
 *
 * Part 1: a minimal embedding smoke check -- cytadel_plugin_lua_smoke_test()
 * below creates a lua_State, evaluates a one-line chunk, and tears the
 * state down, proving the CMake/Lua::Lua link is wired correctly before any
 * sandboxing/scheduling code is built on top of it.
 *
 * Part 2/4: cytadel_plugin_registry_t -- load every plugins/ *.lua file
 * (registration phase, §4.1), validate each header, and compute one fixed
 * topological run order.
 *
 * Part 3/4: cytadel_finding_t/cytadel_finding_list_t -- the findings a
 * target's plugin run collects (§2.9's report_vuln{}/security_report{}),
 * and cytadel_plugin_run_all_for_host() -- the per-host scheduler entry
 * point src/net/host_scan.c calls (§4.2/§4.6).
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Creates a fresh lua_State, evaluates "return 1+1" via luaL_dostring(),
 * verifies the result is the Lua integer 2, then closes the state
 * unconditionally (success or failure). Returns 0 if every step succeeded
 * (state created, chunk compiled+ran without error, result was exactly the
 * integer 2), -1 otherwise. Exists purely to prove the embedding/toolchain
 * link works end to end (Milestone 5 Part 1) -- not used by any later part
 * of the engine, which builds its own sandboxed lua_State lifecycle instead
 * (see plugin-api.md §4.1/§4.2 and this module's sandbox.c). */
int cytadel_plugin_lua_smoke_test(void);

/* ------------------------------------------------------------------ *
 * Registration phase (plugin-api.md §4.1).
 * ------------------------------------------------------------------ */

typedef struct cytadel_plugin_registry cytadel_plugin_registry_t;

/* Scans `plugins_dir` for every "*.lua" file (sorted by filename for
 * deterministic ordering), registers each (§4.1 steps 1-6: fresh
 * lua_State, metadata-phase sandbox, luaL_loadfile + _ENV rebind +
 * lua_pcall, capture the register{...} header, confirm a global `run`
 * function was defined, lua_close() unconditionally), and -- once every
 * file has been attempted -- builds the dependency graph from every
 * successfully registered header's `dependencies` list and computes one
 * fixed topological run order (§4.1's closing paragraphs).
 *
 * A broken individual plugin file (compile error, a register{} validation
 * error, a duplicate script_id, or a missing `run` function) is logged and
 * skipped -- §4.1 step 7: "a broken plugin never aborts the scan." This
 * function itself only fails (returns -1, *out_registry left NULL) on a
 * hard STARTUP error that leaves no well-defined schedule to run at all: a
 * `dependencies` entry referencing a script_id no loaded plugin declared,
 * or a dependency cycle (both logged by name/id before returning, per
 * §4.1's "a cycle is a hard startup error naming the plugins involved").
 * `plugins_dir` itself being unreadable (missing directory, permission
 * denied) is also a hard startup error (there is nothing to schedule).
 *
 * On success, returns 0 and a non-NULL *out_registry the caller must
 * release exactly once via cytadel_plugin_registry_free(). `plugins_dir`
 * is only read during this call; it may be freed/reused immediately after
 * this function returns. */
int cytadel_plugin_registry_load(const char *plugins_dir, cytadel_plugin_registry_t **out_registry);

/* Releases every resource owned by `registry`. Safe to call with
 * registry == NULL (no-op), matching this codebase's free-function idiom
 * (cytadel_kb_free(), cytadel_host_result_free(), ...). */
void cytadel_plugin_registry_free(cytadel_plugin_registry_t *registry);

/* Number of successfully registered plugins (i.e. how many *.lua files
 * under plugins_dir passed registration -- broken files are not counted).
 * Returns 0 if registry is NULL. */
size_t cytadel_plugin_registry_count(const cytadel_plugin_registry_t *registry);

/* ------------------------------------------------------------------ *
 * Findings (plugin-api.md §2.9's report_vuln{}/security_report{}).
 * ------------------------------------------------------------------ */

typedef struct {
    int severity;         /* 0-4 canon severity (plugin-api.md §0), required */
    char *title;           /* owned, required */
    char *description;     /* owned, nullable */
    char *evidence;         /* owned, required */
    int64_t port;            /* required; 0 = host-level finding */
    char *solution;            /* owned, required (falls back to the plugin header's solution) */
    char **cve;                 /* owned array of owned strings, may be NULL if cve_count == 0 */
    size_t cve_count;
    char *cpe;                   /* owned, nullable */
    char *cvss_vector;             /* owned, nullable (falls back to the plugin header's cvss_vector) */
    int64_t script_id;               /* which plugin produced this finding */
    char *script_name;                /* owned -- copy of the plugin's catalog script_name */
} cytadel_finding_t;

typedef struct {
    cytadel_finding_t *items; /* owned, NULL if capacity == 0 */
    size_t count;
    size_t capacity;
} cytadel_finding_list_t;

/* Frees every owned field of every finding in *list, then list->items, and
 * zeroes *list. Safe on an already-freed/zero-initialized list and on
 * list == NULL. A caller collecting findings across a host's plugin
 * schedule should zero-initialize a cytadel_finding_list_t (e.g.
 * `cytadel_finding_list_t findings = {0};`) and pass its address to
 * cytadel_plugin_run_all_for_host() below; this is the matching release
 * call. */
void cytadel_finding_list_free(cytadel_finding_list_t *list);

/* ------------------------------------------------------------------ *
 * Run phase / scheduler (plugin-api.md §4.2, §4.6).
 * ------------------------------------------------------------------ */

typedef enum {
    /* run() executed to completion without raising an error. This does
     * NOT imply a finding was reported -- most invocations of most
     * plugins against most targets legitimately find nothing (§2.11). */
    CYTADEL_PLUGIN_RESULT_OK = 0,
    /* required_keys (§4.6) was not satisfied for this target -- no
     * lua_State was even created (§4.2 step 1's "cheap short-circuit"). */
    CYTADEL_PLUGIN_RESULT_SKIPPED = 1,
    /* A registration-phase-equivalent re-load error, or run() itself
     * raised (including the §4.5 runtime-limit hook firing) -- a distinct
     * execution-status value from OK, per §4.3: "marks that (plugin,
     * target) as FAILED (not a finding, not 'not applicable')." */
    CYTADEL_PLUGIN_RESULT_FAILED = 2
} cytadel_plugin_result_status_t;

/* Optional per-invocation observer callback. `bound_port` is the
 * service-wildcard-dispatched port (§2.2a/§4.6) for that invocation, or -1
 * for an ordinary exact-key plugin (which runs at most once per target).
 * Called once per (plugin, target[, port]) invocation attempted --
 * including SKIPPED ones -- in the exact order the scheduler walks them
 * (topological plugin order; ascending port order within a
 * service-wildcard plugin's dispatch). May be NULL if the caller does not
 * need this level of observability (src/cli/main.c's production use does
 * not; the Milestone 5 test suite does). */
typedef void (*cytadel_plugin_result_fn)(int64_t script_id, const char *script_name,
                                          int bound_port, cytadel_plugin_result_status_t status,
                                          void *user_data);

/* Runs every registered plugin in `registry`, in the fixed topological
 * order computed by cytadel_plugin_registry_load(), against one target's
 * KB (§4.2: required_keys gating, §4.6: service-wildcard per-port
 * dispatch), appending every finding any invocation reports to
 * *out_findings (caller-owned; see cytadel_finding_list_free() above).
 * `ip` is the resolved IPv4 literal used only for this target's
 * open_sock_tcp()/http_get() connections (the KB itself has no notion of
 * which host it belongs to). `on_result`/`user_data` are optional (may be
 * NULL together) -- see cytadel_plugin_result_fn's comment.
 *
 * kb-schema.md §6: exactly one thread owns `kb` for the duration of this
 * call (one worker per host) -- this function itself does not add any
 * locking, matching that single-writer-thread invariant; do not call this
 * concurrently against the same kb/out_findings from multiple threads. */
void cytadel_plugin_run_all_for_host(const cytadel_plugin_registry_t *registry, const char *ip,
                                      cytadel_kb_t *kb, cytadel_finding_list_t *out_findings,
                                      cytadel_plugin_result_fn on_result, void *user_data);

/* Security-review round-4 finding W-3: the TEST-SUPPORT-ONLY debug-check
 * functions that used to be declared here (cytadel_plugin_debug_check_
 * env_isolated() and friends) are no longer part of this public header --
 * production code never called them, and a public, load-and-execute-
 * arbitrary-Lua-file entry point has no business being structurally
 * reachable from this library's public surface at all, regardless of
 * whether anything currently ships it. They now live in the private
 * src/plugin/debug_support.h (only reachable from src/plugin's own
 * translation units and the specific tests/unit executables that need
 * them), and debug_support.c is only compiled into `cytadel` at all under
 * `if(BUILD_TESTING)` (src/plugin/CMakeLists.txt). See that header's own
 * top-of-file comment for the full rationale. */

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_PLUGIN_H */

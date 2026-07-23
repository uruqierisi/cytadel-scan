# tests/integration/CMakeLists.txt -- M9 Phase 2.
#
# Registers the full end-to-end Docker-backed integration test
# (run_integration_test.sh) as a single CTest case, labeled "integration" so
# it can be run independently of the unit suite:
#
#   ctest -L integration --output-on-failure
#
# This directory is only add_subdirectory()'d by the top-level CMakeLists.txt
# when BOTH BUILD_TESTING and CYTADEL_ENABLE_INTEGRATION_TESTS are ON --
# CYTADEL_ENABLE_INTEGRATION_TESTS defaults OFF (docs/build-plan.md SS5), so
# a plain `ctest` / `ctest -L unit` run in an environment without Docker (or
# where the operator simply didn't ask for it) never even sees this test
# registered, let alone attempts to run it. CI (Phase 4) enables it
# explicitly where Docker is available.
#
# No C test executable here (unlike tests/unit/tests/plugins) -- this test
# needs `docker`, `docker compose`, and `jq` on the host, none of which this
# project links against; a bash script orchestrator is the correct shape
# per docs/build-plan.md SS1's own "tests/integration/ *.sh" note.

find_program(CYTADEL_BASH_EXECUTABLE bash)
if(NOT CYTADEL_BASH_EXECUTABLE)
    message(WARNING
        "CYTADEL_ENABLE_INTEGRATION_TESTS is ON but no 'bash' was found -- "
        "the integration test will be registered but will fail to launch.")
    set(CYTADEL_BASH_EXECUTABLE bash)
endif()

add_test(
    NAME integration_e2e_docker_scan
    COMMAND ${CYTADEL_BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_integration_test.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(integration_e2e_docker_scan PROPERTIES
    LABELS "integration"
    # Docker image builds (esp. the ssh-vulnerable apt install + scanner
    # builder stage) plus 5 sqlite3/report round trips comfortably exceed
    # CTest's 1500s default only on a stone-cold Docker layer cache; give
    # this generous headroom rather than a flaky default timeout.
    TIMEOUT 1800
    RUN_SERIAL TRUE
)

# M9 Phase 3: proves (by observed log output, not assumption) that
# src/net/discovery.c's TCP-ping fallback fires when raw ICMP sockets are
# unavailable, and -- via a contrast/negative-control run against a
# separately-built raw-capable image -- that the same test would catch a
# regression where the fallback silently stopped working. See
# run_unprivileged_fallback_test.sh's own header comment and
# docker/docker-compose.scanner-unprivileged.yml for the full design.
# Same gating (CYTADEL_ENABLE_INTEGRATION_TESTS + "-L integration") as
# integration_e2e_docker_scan above; a separate CTest case (not folded into
# it) so either can be run/triaged independently.
add_test(
    NAME integration_e2e_unprivileged_fallback
    COMMAND ${CYTADEL_BASH_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/run_unprivileged_fallback_test.sh
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
set_tests_properties(integration_e2e_unprivileged_fallback PROPERTIES
    LABELS "integration"
    # Two full image builds (scanner-unprivileged + scanner-rawcapable,
    # sharing the builder-stage cache) plus two scan runs and one report
    # round trip -- generous headroom for a stone-cold Docker layer cache,
    # matching integration_e2e_docker_scan's own reasoning above.
    TIMEOUT 1800
    RUN_SERIAL TRUE
)

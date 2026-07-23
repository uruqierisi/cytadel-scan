# docker/scanner/Dockerfile -- M9 Phase 2: the REAL cytadel-scan binary,
# built and run as a container that joins the Phase-1 vulnerable test
# target's internal-only network (cytadel-test-net) as a sidecar, exactly
# the network position docker/sidecar/ already models.
#
# BUILD CONTEXT: this Dockerfile is built with the REPO ROOT as its context
# (see docker/docker-compose.scanner.yml's `build.context: ..`), because the
# builder stage needs CMakeLists.txt, cmake/, include/, src/, third_party/,
# and plugins/ from the repo root -- unlike every other docker/*/Dockerfile
# in this project, which only need their own subdirectory.
#
# TWO-STAGE BUILD:
#   1. `builder` -- compiles the real cytadel-scan binary against system
#      dev packages (liblua5.4-dev, libssl-dev, libcurl4-openssl-dev) --
#      this container has real root/apt access, unlike the reference WSL
#      dev environment (see MEMORY.md's build-environment.md), so the
#      simpler system-package path is used here instead of that
#      environment's vendored-static ($HOME/lua-local, $HOME/curl-local)
#      workaround. SQLite3/cJSON are vendored in-tree (third_party/) and
#      always built from source regardless of environment -- untouched.
#      libpcap is NEVER linked: as of this milestone the engine's
#      port-scanner has only a TCP-connect backend
#      (src/net/scan_backend.c's cytadel_scan_backend_select() always
#      returns the connect backend; the raw-socket/SYN path is an explicit
#      TODO, not yet implemented) -- there is no optional pcap dependency
#      to satisfy yet, and this build passes no pcap flags at all.
#   2. `runtime` -- copies ONLY the compiled binary + plugins/ (data, per
#      docs/build-plan.md SS4 -- "plugins are data, not a target") into a
#      slim image carrying just the runtime shared libraries + the sqlite3
#      CLI (needed by the integration-test harness to seed/inspect the
#      fixture DB directly against the same CYTADEL_DB_PATH the scanner
#      writes to). Runs as a non-root user.
#
# CAPABILITIES / UNPRIVILEGED-CONTAINER NOTE (read before changing how this
# scans): this container runs with NO added capabilities (no
# --cap-add=NET_RAW, no privileged mode) and, more importantly, runs as the
# non-root `cytadel` user (USER below). CORRECTION (M9 Phase 3, verified
# empirically against this exact base image -- see
# docker/docker-compose.scanner-unprivileged.yml's header comment for the
# real test transcript): Docker's DEFAULT capability set actually DOES
# include CAP_NET_RAW in the container's bounding set -- dropping it is not
# what makes raw ICMP unavailable here. What actually makes it unavailable
# is running as non-root with no file capability on the binary: Linux only
# populates a non-root process's permitted/effective capability sets from
# the exec'd file's own capability xattr (or from root's legacy
# "permitted = bounding" exec rule, which only applies when the process IS
# root) -- a non-root process in a container whose bounding set still has
# CAP_NET_RAW gets EPERM on socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) all the
# same, confirmed with a minimal raw-socket probe binary under both
# capability postures. So this image is unconditionally TCP-ping-fallback
# only, by virtue of the `USER cytadel` line alone -- the explicit
# `cap_drop: [ALL]` in docker-compose.scanner-unprivileged.yml's
# `scanner-unprivileged` service is deliberate defense-in-depth /
# explicit-intent (and what M9 Phase 3 was asked to add), not what actually
# flips the behavior for THIS image. The engine already handles the
# unavailable-raw-socket case gracefully at two layers:
#   - src/net/discovery.c falls back from ICMP to a plain TCP-connect probe
#     automatically when raw sockets are unavailable (no flag needed) --
#     this is the general-purpose graceful-degradation path.
#   - For THIS deterministic integration test we go one step further and
#     pass --skip-discovery explicitly (tests/integration/run_integration_
#     test.sh): the compose topology already guarantees every target is up
#     before the scanner runs, so discovery would only add latency/flakiness
#     for no benefit here. --skip-discovery needs no capability at all.
#   - The TCP-connect port scan itself (src/net/tcp_connect.c) never needed
#     raw sockets in the first place -- only a hypothetical future SYN-scan
#     backend would, and per the comment above that backend does not exist
#     yet in this codebase.
#   - M9 Phase 3 (tests/integration/run_unprivileged_fallback_test.sh) runs
#     discovery for REAL (no --skip-discovery) specifically to observe and
#     assert on the fallback marker itself -- see that script and
#     docker/docker-compose.scanner-unprivileged.yml for the full scenario,
#     including the `scanner-rawcapable` CONTRAST image (this Dockerfile's
#     CYTADEL_TEST_SETCAP_NET_RAW build arg below) used to prove the
#     fallback marker is genuinely absent when raw ICMP actually works.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS builder

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        build-essential cmake pkg-config ca-certificates \
        liblua5.4-dev libssl-dev libcurl4-openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy only what the build actually needs (not the whole repo -- tests/,
# docker/, docs/ are irrelevant to compiling the cytadel-scan binary and
# would only bust layer cache more often).
COPY CMakeLists.txt ./
COPY cmake/ ./cmake/
COPY include/ ./include/
COPY src/ ./src/
COPY third_party/ ./third_party/

# CYTADEL_CURL_INCLUDE_DIR / CYTADEL_CURL_LIBRARY are pre-seeded on the
# cmake command line (not via CYTADEL_CURL_ROOT) so the top-level
# CMakeLists.txt's find_path()/find_library() calls for those two cache
# variables become no-ops (CMake never re-runs a find_*() whose cache
# variable is already set) and resolve straight to the apt-installed system
# libcurl instead of requiring a vendored $HOME/curl-local static build.
# BUILD_TESTING=OFF: production build, matches build-plan.md's own
# BUILD_TESTING=OFF guidance and skips tests/unit entirely (no test-only
# debug_support.c code compiled in either, per its own BUILD_TESTING gate).
RUN CURL_LIB="$(find /usr/lib -name 'libcurl.so*' 2>/dev/null | sort | head -n1)" \
    && if [ -z "$CURL_LIB" ]; then echo "system libcurl.so not found" >&2; exit 1; fi \
    && cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF \
        -DCYTADEL_CURL_INCLUDE_DIR=/usr/include \
        -DCYTADEL_CURL_LIBRARY="$CURL_LIB" \
    && cmake --build build --target cytadel-scan -j"$(nproc)"

# -----------------------------------------------------------------------------
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

# Runtime counterparts of the builder's -dev packages, plus the sqlite3 CLI
# (used by tests/integration/run_integration_test.sh to seed the fixture
# CVE DB and to run point-in-time snapshot-mutation checks directly against
# CYTADEL_DB_PATH -- the same file cytadel-scan itself reads/writes).
RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends \
        liblua5.4-0 libssl3 libcurl4 sqlite3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home --home-dir /home/cytadel \
        --shell /usr/sbin/nologin cytadel

COPY --from=builder /src/build/src/cli/cytadel-scan /usr/local/bin/cytadel-scan
# Plugins are data (docs/build-plan.md SS4), loaded at runtime from the
# compiled-in default relative path "plugins" under the process's CWD
# (src/cli/main.c) -- WORKDIR below matches that expectation exactly, no
# --plugins-dir flag needed.
COPY plugins/ /opt/cytadel/plugins/

# M9 Phase 3 -- TEST-ONLY, opt-in negative-control knob. Defaults to "0"
# (no-op): every existing build (docker-compose.scanner.yml, Phase 2's
# integration test, and any operator build with no --build-arg) gets
# EXACTLY the same image as before this ARG was added -- no new packages,
# no new layer content, no behavior change.
#
# Read this before ever setting it to "1" outside tests/integration/
# run_unprivileged_fallback_test.sh's contrast run:
#   `setcap cap_net_raw+ep` on the binary is what lets a NON-ROOT process
#   open a raw ICMP socket at all (src/net/capability.c's
#   cytadel_net_can_use_raw_sockets()) -- Linux only grants capabilities to
#   a non-root exec from the file's own capability xattr or from root's
#   legacy "permitted = bounding" exec rule; being non-root with the
#   container's capability BOUNDING set intact (CAP_NET_RAW not dropped)
#   is not sufficient by itself. This has been verified empirically (not
#   assumed) against this exact base image: a non-root exec of an
#   unmodified binary with the default (non-dropped) capability set still
#   gets EPERM on socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); only adding this
#   file capability makes it succeed. Setting it to "1" is ONLY ever used
#   to build docker/docker-compose.scanner-unprivileged.yml's
#   `scanner-rawcapable` contrast service, whose entire purpose is proving
#   the TCP-ping fallback marker is ABSENT when raw ICMP genuinely IS
#   available -- i.e. that the fallback test has teeth, not that this is a
#   capability the shipped scanner image should ever carry. If the
#   container's capability bounding set is later dropped (`--cap-drop`)
#   while this ARG is "1", execve() of this binary fails outright
#   (EPERM) rather than gracefully degrading -- confirmed empirically --
#   which is exactly why the real fallback scenario
#   (`scanner-unprivileged`) is built from the DEFAULT ARG value (no
#   setcap at all), never this branch.
ARG CYTADEL_TEST_SETCAP_NET_RAW=0
RUN if [ "$CYTADEL_TEST_SETCAP_NET_RAW" = "1" ]; then \
        apt-get update -qq \
        && apt-get install -y --no-install-recommends libcap2-bin \
        && setcap cap_net_raw+ep /usr/local/bin/cytadel-scan \
        && apt-get purge -y --auto-remove libcap2-bin \
        && rm -rf /var/lib/apt/lists/* ; \
    fi

RUN mkdir -p /data && chown -R cytadel:cytadel /data /opt/cytadel

WORKDIR /opt/cytadel
ENV CYTADEL_DB_PATH=/data/cytadel-test.sqlite

USER cytadel

ENTRYPOINT ["cytadel-scan"]

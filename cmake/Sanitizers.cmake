# cytadel_sanitizers: an INTERFACE target carrying sanitizer flags when
# CYTADEL_SANITIZE (ASan+UBSan) or CYTADEL_TSAN (ThreadSanitizer) is ON
# (docs/build-plan.md §3). Linked PUBLIC into `cytadel` (see top-level
# CMakeLists.txt) so every target that links against the engine library
# also gets the sanitizer compile/link flags — mixing sanitized and
# non-sanitized objects in one binary is unsafe. When both options are OFF
# (the default) this target carries no flags at all, so linking it PUBLIC
# everywhere is a safe no-op.
#
# CYTADEL_SANITIZE and CYTADEL_TSAN are mutually exclusive: ASan/UBSan and
# ThreadSanitizer are separate runtimes that cannot be linked into the same
# binary (each instruments memory access differently and they conflict at
# link time / corrupt each other's shadow memory if both are requested).
# Pick one per build: `cmake -DCYTADEL_SANITIZE=ON` for the memory/UB pass,
# `cmake -DCYTADEL_TSAN=ON` for the concurrency pass (this milestone's
# worker pool + logger mutex is exactly the kind of code ASan/UBSan cannot
# check -- it catches memory/UB bugs, not data races).

add_library(cytadel_sanitizers INTERFACE)

if(CYTADEL_SANITIZE AND CYTADEL_TSAN)
    message(FATAL_ERROR
        "CYTADEL_SANITIZE (ASan+UBSan) and CYTADEL_TSAN (ThreadSanitizer) are "
        "mutually exclusive -- their runtimes cannot be linked into the same "
        "binary. Configure one at a time.")
endif()

if(CYTADEL_SANITIZE OR CYTADEL_TSAN)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        if(CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE MATCHES "^(Debug|RelWithDebInfo)$")
            message(WARNING
                "CYTADEL_SANITIZE/CYTADEL_TSAN is only meaningful for Debug/RelWithDebInfo "
                "builds; current CMAKE_BUILD_TYPE='${CMAKE_BUILD_TYPE}'.")
        endif()

        if(CYTADEL_SANITIZE)
            # -fsanitize=undefined does NOT imply float-cast-overflow on GCC
            # (verified on GCC 15: a double->long cast that overflows, e.g.
            # 1e30 -> long, is silent under plain -fsanitize=undefined and
            # only reported once float-cast-overflow is requested
            # explicitly) -- it must be listed separately, alongside
            # float-divide-by-zero (also not implied), or this build is
            # blind to exactly this UB class.
            target_compile_options(cytadel_sanitizers INTERFACE
                -fsanitize=address,undefined,float-cast-overflow,float-divide-by-zero
                -fno-omit-frame-pointer
                -g
            )
            target_link_options(cytadel_sanitizers INTERFACE
                -fsanitize=address,undefined,float-cast-overflow,float-divide-by-zero
            )
        else() # CYTADEL_TSAN
            target_compile_options(cytadel_sanitizers INTERFACE
                -fsanitize=thread
                -fno-omit-frame-pointer
                -g
            )
            target_link_options(cytadel_sanitizers INTERFACE
                -fsanitize=thread
            )
        endif()
    else()
        message(WARNING
            "CYTADEL_SANITIZE/CYTADEL_TSAN requested but compiler '${CMAKE_C_COMPILER_ID}' "
            "is not GCC/Clang; ignoring.")
    endif()
endif()

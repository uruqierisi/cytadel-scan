# cytadel_warnings: an INTERFACE target carrying the project's warning flags
# (docs/build-plan.md §3). Every first-party target links this PRIVATE so
# the flags apply to that target's own compilation without leaking into
# consumers that link against it.

add_library(cytadel_warnings INTERFACE)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(cytadel_warnings INTERFACE
        -Wall
        -Wextra
        -Wpedantic
    )
    if(CYTADEL_WERROR)
        target_compile_options(cytadel_warnings INTERFACE -Werror)
    endif()
else()
    message(WARNING "Unrecognized compiler '${CMAKE_C_COMPILER_ID}': cytadel_warnings adds no flags for it.")
endif()

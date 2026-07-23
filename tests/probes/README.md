# Independent verification probes

These are **not** part of `ctest`. They are deliberately out-of-tree, standalone programs
linked against the built `libcytadel.a`, written by a reviewer rather than by the author of
the code under test.

## Why they exist

The in-tree truth tables for the CPE matching slice were **green while containing real
false-negative defects**, twice:

1. `test_version_compare.c` was 45/45 green while the comparator guessed `GREATER` for
   unrecognized detached pre-release spellings (`1.0.0-cr1`, `1.0.0-M1`). A host running an
   affected release candidate was judged outside the vulnerable range.
2. After that was fixed, both the in-tree table *and* `probe_vercmp.c` were green while
   attached pre-release spellings (`3.11.0rc1`, `7.4.0RC1`, `1.0.0beta1`) ranked **above**
   their own release — the same defect class, on the other side of the very distinction the
   fix introduced. CPython and PHP ship exactly those strings.

The lesson both times: **a truth table written by the author of the code cannot find the case
the author did not think of.** Green build is not correctness; green truth table is not
correctness either. Only cases chosen by someone who did not write the implementation, plus
mutation testing, have actually caught defects in this component.

## How to run

```sh
# from the repo root, in WSL, with the venv active
cmake -S . -B ~/probebuild -DCMAKE_BUILD_TYPE=Debug \
      -DCYTADEL_LUA_ROOT=$HOME/lua-local -DOPENSSL_ROOT_DIR=$HOME/openssl-local
cmake --build ~/probebuild -j8

gcc -std=c11 -I include -o ~/probe_vercmp tests/probes/probe_vercmp.c ~/probebuild/libcytadel.a -lpthread
gcc -std=c11 -I include -o ~/probe_cpe    tests/probes/probe_cpe.c    ~/probebuild/libcytadel.a -lpthread
~/probe_vercmp
~/probe_cpe
```

Each prints a per-case verdict and a trailing mismatch count. A probe reporting `MISMATCHES: 0`
means the implementation agreed with the reviewer's expectations — it does **not** mean the
comparator is correct, only that it is correct on the cases someone thought to write down.

## Known gaps in these probes

`probe_vercmp.c` as committed does **not** cover attached pre-release spellings; that omission
is how defect (2) above escaped. Anyone extending these should add, at minimum:
`3.11.0rc1`, `3.9.0a1`, `3.9.0b2`, `7.4.0RC1`, `1.0.0beta1`, `2.0.0dev`, `1.0.0+build5`,
`v2.1.0`, `1:` (bare epoch), and same-position keyword pairs such as `1.0.0-ga` vs `1.0.0-rc`.

When adding a case, prefer real version strings shipped by real projects over invented ones,
and cite the project. A fabricated expectation bakes a wrong answer into the definition of
correctness.

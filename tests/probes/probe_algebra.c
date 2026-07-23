/* Exhaustive antisymmetry + transitivity sweep over a corpus. C-2 introduced
 * 597 transitivity violations; this must report 0 on the decidable set. */
#include <stdio.h>
#include <string.h>
#include "cytadel/match/version_compare.h"

static const char *CORPUS[] = {
    "1.0", "1.0.0", "1.0.1", "1.0.1f", "1.0.1g", "1.0.2", "1.0.2k", "1.0.2l",
    "2.4", "2.4.0", "2.4.6", "2.4.7", "2.4.6-2ubuntu2.2", "1:2.4.6", "2:1.0",
    "7.2", "7.2p2", "7.2p3", "8.5p1", "9.7", "9.8p1", "4.4p1",
    "1.0.0-alpha", "1.0.0-beta", "1.0.0-rc", "1.0.0-rc1", "1.0.0-ga",
    "1.0.0-final", "1.0.0-release", "1.0.0-stable", "1.0.0-snapshot",
    "3.11.0", "3.11.0rc1", "1.0.0+build5", "v1.0",
};
enum { N = sizeof(CORPUS) / sizeof(CORPUS[0]) };

static cytadel_vercmp_t C(const char *a, const char *b) {
    return cytadel_version_compare(a, strlen(a), b, strlen(b));
}

int main(void) {
    int asym = 0, trans = 0, decidable_triples = 0;
    /* antisymmetry: C(a,b) must be the mirror of C(b,a); UNDEC symmetric */
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++) {
            cytadel_vercmp_t ab = C(CORPUS[i], CORPUS[j]), ba = C(CORPUS[j], CORPUS[i]);
            cytadel_vercmp_t mir = ab == CYTADEL_VERCMP_LESS      ? CYTADEL_VERCMP_GREATER
                                   : ab == CYTADEL_VERCMP_GREATER ? CYTADEL_VERCMP_LESS
                                                                  : ab;
            if (ba != mir) {
                asym++;
                if (asym <= 5) printf("ASYM: %s vs %s\n", CORPUS[i], CORPUS[j]);
            }
        }
    /* transitivity on the decidable set: a<=b & b<=c => a<=c, treating
     * EQUAL/LESS as <=. Only count triples where all three pairs are decidable. */
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            for (int k = 0; k < N; k++) {
                cytadel_vercmp_t ab = C(CORPUS[i], CORPUS[j]);
                cytadel_vercmp_t bc = C(CORPUS[j], CORPUS[k]);
                cytadel_vercmp_t ac = C(CORPUS[i], CORPUS[k]);
                if (ab == CYTADEL_VERCMP_UNDECIDABLE || bc == CYTADEL_VERCMP_UNDECIDABLE ||
                    ac == CYTADEL_VERCMP_UNDECIDABLE)
                    continue;
                decidable_triples++;
                int ab_le = (ab != CYTADEL_VERCMP_GREATER);
                int bc_le = (bc != CYTADEL_VERCMP_GREATER);
                int ac_le = (ac != CYTADEL_VERCMP_GREATER);
                if (ab_le && bc_le && !ac_le) {
                    trans++;
                    if (trans <= 5)
                        printf("TRANS: %s <= %s <= %s but not <= end\n", CORPUS[i], CORPUS[j],
                               CORPUS[k]);
                }
            }
    printf("\ncorpus=%d  antisymmetry_violations=%d  transitivity_violations=%d "
           "(of %d decidable triples)\n",
           N, asym, trans, decidable_triples);
    return (asym || trans) ? 1 : 0;
}

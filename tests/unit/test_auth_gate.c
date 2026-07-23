#include "cytadel_test.h"

#include "auth_gate.h"

static bool always_confirm(void) { return true; }
static bool always_decline(void) { return false; }

static void test_flag_present_authorizes_without_prompt(void) {
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(true, false, NULL);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_AUTHORIZED);
    CYTADEL_ASSERT_EQ(d.method, CYTADEL_AUTH_METHOD_FLAG);
    CYTADEL_ASSERT(d.reason == NULL);
}

static void test_no_flag_non_tty_refuses(void) {
    /* Non-interactive session (e.g. piped/CI/cron) with no
     * --i-am-authorized flag must refuse -- authorization is never
     * assumed. */
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(false, false, always_confirm);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_REFUSED);
    CYTADEL_ASSERT(d.reason != NULL);
}

static void test_interactive_confirm_authorizes(void) {
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(false, true, always_confirm);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_AUTHORIZED);
    CYTADEL_ASSERT_EQ(d.method, CYTADEL_AUTH_METHOD_INTERACTIVE);
    CYTADEL_ASSERT(d.reason == NULL);
}

static void test_interactive_decline_refuses(void) {
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(false, true, always_decline);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_REFUSED);
    CYTADEL_ASSERT(d.reason != NULL);
}

static void test_flag_present_wins_even_when_tty(void) {
    /* --i-am-authorized short-circuits the interactive prompt entirely. */
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(true, true, always_decline);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_AUTHORIZED);
    CYTADEL_ASSERT_EQ(d.method, CYTADEL_AUTH_METHOD_FLAG);
}

static void test_tty_without_prompt_fn_refuses_defensively(void) {
    cytadel_auth_decision_t d = cytadel_auth_gate_decide(false, true, NULL);
    CYTADEL_ASSERT_EQ(d.result, CYTADEL_AUTH_RESULT_REFUSED);
    CYTADEL_ASSERT(d.reason != NULL);
}

static void test_default_operator_never_returns_null_or_empty(void) {
    char buf[256];
    const char *name = cytadel_auth_default_operator(buf, sizeof(buf));
    CYTADEL_ASSERT(name != NULL);
    CYTADEL_ASSERT(name[0] != '\0');
}

int main(void) {
    test_flag_present_authorizes_without_prompt();
    test_no_flag_non_tty_refuses();
    test_interactive_confirm_authorizes();
    test_interactive_decline_refuses();
    test_flag_present_wins_even_when_tty();
    test_tty_without_prompt_fn_refuses_defensively();
    test_default_operator_never_returns_null_or_empty();
    CYTADEL_TEST_PASS();
}

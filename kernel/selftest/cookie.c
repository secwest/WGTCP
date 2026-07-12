// SPDX-License-Identifier: GPL-2.0

#ifdef DEBUG
bool __init wg_cookie_policy_selftest(void)
{
	static const struct {
		bool under_load;
		enum cookie_mac_state state;
		enum cookie_validation_action expected;
	} cases[] = {
		{ false, INVALID_MAC, WG_COOKIE_DROP },
		{ false, VALID_MAC_BUT_NO_COOKIE, WG_COOKIE_ACCEPT },
		{ false, VALID_MAC_WITH_COOKIE_BUT_RATELIMITED, WG_COOKIE_DROP },
		{ false, VALID_MAC_WITH_COOKIE, WG_COOKIE_DROP },
		{ true, INVALID_MAC, WG_COOKIE_DROP },
		{ true, VALID_MAC_BUT_NO_COOKIE, WG_COOKIE_CHALLENGE },
		{ true, VALID_MAC_WITH_COOKIE_BUT_RATELIMITED, WG_COOKIE_DROP },
		{ true, VALID_MAC_WITH_COOKIE, WG_COOKIE_ACCEPT }
	};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(cases); ++i) {
		if (wg_cookie_validation_action(cases[i].under_load,
						cases[i].state) != cases[i].expected) {
			pr_err("cookie policy self-test %zu: FAIL\n", i + 1);
			return false;
		}
	}
	pr_info("cookie policy self-tests: pass\n");
	return true;
}
#endif

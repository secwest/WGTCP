"""Contract guards for the focused TCP parity runtime modes."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tests" / "tcp-parity-netns.sh").read_text(encoding="utf-8")
GUEST = (ROOT / "tests" / "hyperv" / "guest-node.sh").read_text(encoding="utf-8")
RUNNER = (ROOT / "tests" / "hyperv" / "regression.py").read_text(encoding="utf-8")


class TcpParityNewModesContract(unittest.TestCase):
    def assert_ordered(self, text: str, *needles: str) -> None:
        position = -1
        for needle in needles:
            next_position = text.find(needle, position + 1)
            self.assertNotEqual(next_position, -1, f"missing ordered source: {needle}")
            self.assertGreater(next_position, position, f"out-of-order source: {needle}")
            position = next_position

    def test_modes_are_independently_registered(self) -> None:
        self.assertIn("config-roundtrip)", SCRIPT)
        self.assertIn("ipv6-link-local)", SCRIPT)
        self.assertIn("$mode == config-roundtrip", GUEST)
        self.assertIn("$mode == ipv6-link-local", GUEST)
        self.assertIn('"tcp-config-roundtrip"', RUNNER)
        self.assertIn('self.tcp_parity_netns_case("config-roundtrip")', RUNNER)
        self.assertIn('"tcp-ipv6-link-local-scope"', RUNNER)
        self.assertIn('self.tcp_parity_netns_case("ipv6-link-local")', RUNNER)
        self.assertIn("fault-injection)", SCRIPT)
        self.assertIn("$mode == fault-injection", GUEST)
        self.assertIn('"tcp-debug-hostile-stream"', RUNNER)
        self.assertIn('"$module_helper" fork-fault', GUEST)
        self.assertIn('"$module_helper" fork', GUEST)
        self.assertIn("trap restore_fault_module EXIT", GUEST)
        self.assertIn('fields.get("restored_kernel_variant") != "fork"', RUNNER)

    def test_secret_configuration_never_leaves_guest_local_files(self) -> None:
        self.assertIn('showconf wga >"$tmpdir/a.conf"', SCRIPT)
        self.assertIn('showconf wgb >"$tmpdir/b.conf"', SCRIPT)
        self.assertIn("showconf files are not mode 0600", SCRIPT)
        self.assertIn('setconf wga "$tmpdir/a.conf"', SCRIPT)
        self.assertIn('syncconf wga "$tmpdir/a.conf"', SCRIPT)
        self.assertIn('cmp -s "$tmpdir/a.conf" "$tmpdir/a.syncconf"', SCRIPT)
        self.assertIn('install -m 0700 "$wg_quick" "$tmpdir/bin/wg-quick"', SCRIPT)
        self.assertIn('"$tmpdir/bin/wg-quick" save', SCRIPT)
        self.assertIn('"$tmpdir/bin/wg-quick" down', SCRIPT)
        self.assertIn('"$tmpdir/bin/wg-quick" up', SCRIPT)
        self.assertIn('cmp -s "$tmpdir/a.conf" "$tmpdir/a.wg-quick"', SCRIPT)
        self.assertIn('stat -c \'%a\' "$tmpdir/wga.conf"', SCRIPT)
        self.assertIn("wg-quick SaveConfig omitted TCP transport", SCRIPT)
        self.assertIn("wg_quick_roundtrip=pass", SCRIPT)
        self.assertNotIn("wg_quick_save=skip", SCRIPT)
        self.assertNotIn('cat "$tmpdir/a.conf"', SCRIPT)
        self.assertNotIn('cat "$tmpdir/b.conf"', SCRIPT)

    def test_link_local_carrier_requires_named_scopes(self) -> None:
        self.assertIn('ip -6 addr flush dev "$p0a" scope link', SCRIPT)
        self.assertIn('$route_a == *"src fe80::a"*', SCRIPT)
        self.assertIn('expected_a="[fe80::b%$p0a]:$port_b"', SCRIPT)
        self.assertIn('expected_b="[fe80::a%$p0b]:$port_a"', SCRIPT)
        self.assertIn(
            'wait_tcp_address_pair "$ns_a" 6 "[fe80::a]%$p0a" "[fe80::b]"',
            SCRIPT,
        )
        self.assertIn(
            'wait_tcp_address_pair "$ns_b" 6 "[fe80::b]%$p0b" "[fe80::a]"',
            SCRIPT,
        )
        self.assertIn("scoped_endpoints=pass", SCRIPT)
        self.assertIn("link_local_carrier=pass", SCRIPT)

    def test_source_uplink_preserves_the_configured_dial_target(self) -> None:
        source_uplink = SCRIPT[
            SCRIPT.index("source-uplink)") : SCRIPT.index("policy-churn)")
        ]
        self.assert_ordered(
            source_uplink,
            'ip link set "$p0a" down',
            'wait_tcp_endpoint "$ns_a" 4 203.0.113.2',
            'wait_peer_endpoint "$ns_a" wga "$b_pub" "203.0.113.2:$port"',
            'wait_ping "$ns_a" wga 10.210.0.2',
        )
        self.assertIn("configured_dial_target_preserved=pass", source_uplink)
        self.assertNotIn("authenticated_dial_target_update=pass", source_uplink)
        self.assertIn("uplink_dial_target=%s", source_uplink)

    def test_route_change_preserves_the_configured_remote_address(self) -> None:
        route = SCRIPT[SCRIPT.index("route)") : SCRIPT.index("source-uplink)")]
        self.assertIn(
            'wait_tcp_endpoint "$ns_a" 4 203.0.113.2 "$port" 198.51.100.1:',
            route,
        )
        self.assertNotIn(
            'wait_tcp_endpoint "$ns_a" 4 198.51.100.2 "$port" 198.51.100.1:',
            route,
        )
        self.assertIn(
            'ip route replace 203.0.113.2/32 via 198.51.100.2', route
        )

    def test_fault_mode_proves_each_injected_path_and_recovers(self) -> None:
        self.assertIn('tcp_test_max_send_bytes"', SCRIPT)
        self.assertIn('tcp_test_garbage_prefix_bytes"', SCRIPT)
        self.assertIn('tcp_test_write_delay_ms"', SCRIPT)
        self.assertIn('tcp_test_queue_limit"', SCRIPT)
        self.assertIn("short_after > short_before", SCRIPT)
        self.assertIn("prefix_after > prefix_before", SCRIPT)
        self.assertIn("resync_after > resync_before", SCRIPT)
        self.assertIn("queue_after > queue_before", SCRIPT)
        self.assertIn("recovery=pass", SCRIPT)

    def test_policy_churn_repeats_single_carrier_reconnect_triggers(self) -> None:
        self.assertIn("source-uplink|policy-churn|ipv6", SCRIPT)
        policy = SCRIPT[
            SCRIPT.index("policy-churn)") : SCRIPT.index("carrier-lifetime)")
        ]

        self.assertIn("port_a=52205", policy)
        self.assertIn("port_b=52206", policy)
        self.assertIn(
            'setup_policy_churn_pair "$port_a" "$port_b" "$mark_a1" "$mark_b1"',
            policy,
        )
        self.assertEqual(policy.count("settle_policy_baseline"), 3)
        self.assertEqual(policy.count("prove_policy_a_connect"), 3)
        self.assertNotIn("prove_policy_b_connect", policy)
        self.assertGreaterEqual(policy.count("assert_policy_path_activity"), 4)
        self.assertGreaterEqual(policy.count('set wga fwmark "$mark_a2"'), 2)
        self.assertIn('set wga fwmark "$mark_a1"', policy)
        self.assertIn("transitions == 3", policy)
        self.assertIn("connect_proofs == 3", policy)
        self.assertIn("fwmark_syn_proofs == 3", policy)
        self.assertIn("policy_transitions=%s", policy)
        self.assertIn("syn_observability=pass", policy)
        self.assertIn("stable_route=pass", policy)
        self.assertIn("fwmark_socket_reconnect=pass", policy)
        self.assertIn("bidirectional_traffic=pass", policy)
        self.assertIn("asymmetric_ports=%s,%s", policy)
        self.assertIn("final_path=path0", policy)

    def test_policy_churn_uses_one_configured_dialer_and_owned_cleanup(self) -> None:
        setup = SCRIPT[
            SCRIPT.index("setup_policy_churn_pair()") : SCRIPT.index(
                "assert_policy_path_activity()"
            )
        ]

        self.assertIn('endpoint 203.0.113.2:"$listen_b"', setup)
        self.assertIn("allowed-ips 10.215.0.1/32", setup)
        self.assertNotIn('endpoint 192.0.2.1:"$listen_a"', setup)
        self.assertIn('install_policy_syn_observer "$ns_a"', setup)
        self.assertNotIn('install_policy_syn_observer "$ns_b"', setup)
        self.assertLess(
            setup.index("ip route add 203.0.113.2/32 via 192.0.2.2"),
            setup.index('"$WG_FORK" set wga peer'),
        )
        self.assertIn("trap cleanup EXIT", SCRIPT)
        self.assertLess(
            SCRIPT.index('record_owned netns "$ns_a"'),
            SCRIPT.index('ip netns add "$ns_a"'),
        )
        self.assertLess(
            SCRIPT.index('record_owned extra-ifaces "$iface"'),
            SCRIPT.index('ip link add "$p0a" type veth'),
        )

    def test_policy_churn_observes_new_marked_syns(self) -> None:
        observer = SCRIPT[
            SCRIPT.index("install_policy_syn_observer()") : SCRIPT.index(
                "tcp_tuple_set()"
            )
        ]
        policy = SCRIPT[
            SCRIPT.index("policy-churn)") : SCRIPT.index("carrier-lifetime)")
        ]

        self.assertIn("nft add table ip wgtcp_policy", observer)
        self.assertIn("nft add counter ip wgtcp_policy syn_all", observer)
        self.assertIn("nft add counter ip wgtcp_policy syn_mark1", observer)
        self.assertIn("nft add counter ip wgtcp_policy syn_mark2", observer)
        self.assertIn("type filter hook output", observer)
        self.assertIn('meta mark "$mark1"', observer)
        self.assertIn('meta mark "$mark2"', observer)
        self.assertIn("wait_policy_syn_advance", observer)
        self.assertIn("policy_exact_carrier", observer)
        self.assertIn(r"/^[0-9][0-9.]*:[0-9]+$/", observer)
        self.assertIn("settle_policy_baseline", observer)
        self.assertIn('policy_syn_packets "$namespace" syn_all', observer)
        self.assertIn("quiet_seconds=3", observer)
        self.assertIn('observed_carrier == "$last_carrier"', observer)
        self.assertIn("SECONDS - quiet_since >= quiet_seconds", observer)
        self.assertIn('confirm_all == "$observed_all"', observer)
        self.assertEqual(policy.count("settle_policy_baseline"), 3)
        self.assertEqual(policy.count("prove_policy_a_connect"), 3)
        self.assertEqual(policy.count("prove_policy_b_connect"), 0)

        proof_a = SCRIPT[
            SCRIPT.index("prove_policy_a_connect()") : SCRIPT.index(
                "prove_policy_b_connect()"
            )
        ]
        self.assert_ordered(
            proof_a,
            "wait_policy_syn_advance",
            "wait_policy_exact_carrier",
            "wait_ping",
            "wait_peer_endpoint_address",
        )

    def test_policy_churn_orders_each_mutation_after_its_syn_baseline(self) -> None:
        policy = SCRIPT[
            SCRIPT.index("policy-churn)") : SCRIPT.index("carrier-lifetime)")
        ]
        phases = (
            (
                "read -r mark2_syn_before",
                'set wga fwmark "$mark_a2"',
                "prove_policy_a_connect",
            ),
            (
                "read -r mark1_syn_before",
                'set wga fwmark "$mark_a1"',
                "prove_policy_a_connect",
            ),
            (
                "read -r mark2_repeat_syn_before",
                'set wga fwmark "$mark_a2"',
                "prove_policy_a_connect",
            ),
        )
        for baseline, mutation, proof in phases:
            self.assert_ordered(policy, baseline, mutation, proof)
            start = policy.index(baseline)
            end = policy.index(mutation, start)
            self.assertIn("settle_policy_baseline", policy[start:end])

    def test_policy_churn_keeps_one_configured_remote_across_paths(self) -> None:
        policy = SCRIPT[
            SCRIPT.index("policy-churn)") : SCRIPT.index("carrier-lifetime)")
        ]
        self.assertEqual(policy.count("prove_policy_a_connect 203.0.113.2"), 3)
        self.assertIn("203.0.113.2 192.0.2.1", policy)
        self.assertNotIn("203.0.113.2 198.51.100.9", policy)
        self.assertNotIn("wait_tcp_remote_absent", policy)


if __name__ == "__main__":
    unittest.main()

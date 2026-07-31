"""Contract guards for the isolated TCP NAT44 runtime regression."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tests" / "tcp-nat-netns.sh").read_text(encoding="utf-8")
GUEST = (ROOT / "tests" / "hyperv" / "guest-node.sh").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "tests" / "hyperv" / "guest-bootstrap.sh").read_text(
    encoding="utf-8"
)
RUNNER = (ROOT / "tests" / "hyperv" / "regression.py").read_text(encoding="utf-8")


class TcpNatContract(unittest.TestCase):
    def test_nat_case_is_selectable_and_has_explicit_dependencies(self) -> None:
        self.assertIn("\tconntrack\n", BOOTSTRAP)
        self.assertIn("\tnftables\n", BOOTSTRAP)
        self.assertIn("tcp-nat-netns)", GUEST)
        self.assertIn("$mode == dual-reachable", GUEST)
        self.assertIn('"tcp-nat44-dual-reachable"', RUNNER)
        self.assertIn('self.tcp_nat_netns_case("dual-reachable")', RUNNER)

    def test_router_mutations_are_namespace_scoped_and_owned(self) -> None:
        self.assertIn('create_namespace "$ns_router"', SCRIPT)
        self.assertIn('record_owned netns "$namespace"', SCRIPT)
        self.assertLess(
            SCRIPT.index('record_owned netns "$namespace"'),
            SCRIPT.index('ip netns add "$namespace"'),
        )
        self.assertIn('run "$ns_router" sysctl -qw net.ipv4.ip_forward=1', SCRIPT)
        self.assertIn('run "$ns_router" nft add table ip wgtcp_nat', SCRIPT)
        self.assertNotIn("sysctl -w net.ipv4.ip_forward=1", SCRIPT)
        self.assertIn('run "$ns_router" conntrack -F', SCRIPT)

    def test_dual_reachable_nat_proves_translation_and_port_separation(self) -> None:
        self.assertIn("initial_snat_port=41001", SCRIPT)
        self.assertIn("rebound_snat_port=41002", SCRIPT)
        self.assertIn("forwarded_port=52241", SCRIPT)
        self.assertIn("client_listen_port=52221", SCRIPT)
        self.assertIn('counter dnat to', SCRIPT)
        self.assertIn('counter snat to', SCRIPT)
        self.assertIn('assert_nat_state "$initial_snat_port"', SCRIPT)
        self.assertIn('assert_nat_state "$rebound_snat_port"', SCRIPT)
        self.assertIn('replace_snat_rule "$rebound_snat_port"', SCRIPT)
        self.assertLess(
            SCRIPT.index('replace_snat_rule "$rebound_snat_port"'),
            SCRIPT.index('run "$ns_router" conntrack -F'),
        )
        self.assertIn("observed NAT source port replaced configured dial target", SCRIPT)
        self.assertIn("source_port_rebind=%s->%s", SCRIPT)
        self.assertIn("configured_port_preserved=pass", SCRIPT)
        self.assertIn('set wgb fwmark 0x52241', SCRIPT)
        self.assertIn("wait_forward_syn_advance", SCRIPT)
        self.assertIn("reverse_dial_reconnect=pass", SCRIPT)
        self.assertIn("reverse_dial_syns=%s->%s", SCRIPT)
        self.assertIn("old_accepted_carrier=%s", SCRIPT)
        self.assertNotIn("old translated TCP carrier remained established", SCRIPT)

    def test_keepalive_and_bidirectional_traffic_are_runtime_assertions(self) -> None:
        self.assertIn("persistent-keepalive 2", SCRIPT)
        self.assertIn("wait_keepalive_advance", SCRIPT)
        self.assertIn('wait_ping "$ns_client" wga "$server_tunnel_address"', SCRIPT)
        self.assertIn('wait_ping "$ns_server" wgb "$client_tunnel_address"', SCRIPT)
        self.assertIn("persistent_keepalive=pass", SCRIPT)
        self.assertIn("bidirectional_traffic=pass", SCRIPT)

    def test_initial_acquisition_has_one_bounded_deadline_and_churn_telemetry(self) -> None:
        self.assertIn("initial_acquisition_timeout_seconds=90", SCRIPT)
        self.assertEqual(SCRIPT.count("initial_acquisition_deadline=$("), 1)
        self.assertIn(
            'wait_ping "$ns_client" wga "$server_tunnel_address" \\\n\t"$initial_acquisition_deadline"',
            SCRIPT,
        )
        self.assertIn(
            'wait_ping "$ns_server" wgb "$client_tunnel_address" \\\n\t"$initial_acquisition_deadline"',
            SCRIPT,
        )
        self.assertIn(
            'assert_nat_state "$initial_snat_port" "$initial_acquisition_deadline"',
            SCRIPT,
        )
        self.assertLess(
            SCRIPT.index("initial_snat_packets_before=$("),
            SCRIPT.index('set wga peer "$server_pub"'),
        )
        self.assertLess(
            SCRIPT.index('assert_nat_state "$initial_snat_port"'),
            SCRIPT.index("initial_acquisition_seconds=$("),
        )
        self.assertIn("initial_snat_rule_packets=%s->%s", SCRIPT)
        self.assertIn("initial_dnat_rule_packets=%s->%s", SCRIPT)
        self.assertIn(
            '$initial_snat_packets_after -gt $initial_snat_packets_before', SCRIPT
        )
        self.assertIn(
            '$initial_dnat_packets_after -gt $initial_dnat_packets_before', SCRIPT
        )
        rebound = SCRIPT.index('replace_snat_rule "$rebound_snat_port"')
        self.assertIn(
            'wait_ping "$ns_client" wga "$server_tunnel_address"',
            SCRIPT[rebound:],
        )
        self.assertNotIn("initial_acquisition_deadline", SCRIPT[rebound:])


if __name__ == "__main__":
    unittest.main()

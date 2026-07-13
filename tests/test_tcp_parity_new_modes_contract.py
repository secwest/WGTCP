"""Contract guards for the focused TCP parity runtime modes."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tests" / "tcp-parity-netns.sh").read_text(encoding="utf-8")
GUEST = (ROOT / "tests" / "hyperv" / "guest-node.sh").read_text(encoding="utf-8")
RUNNER = (ROOT / "tests" / "hyperv" / "regression.py").read_text(encoding="utf-8")


class TcpParityNewModesContract(unittest.TestCase):
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
        self.assertIn('"[fe80::b]" "$port_b"', SCRIPT)
        self.assertIn('"[fe80::a]%$p0a:"', SCRIPT)
        self.assertIn('"[fe80::a]" "$port_a"', SCRIPT)
        self.assertIn('"[fe80::b]%$p0b:"', SCRIPT)
        self.assertIn("scoped_endpoints=pass", SCRIPT)
        self.assertIn("link_local_carrier=pass", SCRIPT)

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


if __name__ == "__main__":
    unittest.main()

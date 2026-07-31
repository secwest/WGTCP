"""Contract guards for the focused TCP roaming runtime scenarios."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "tests" / "tcp-roaming-netns.sh").read_text(encoding="utf-8")
GUEST = (ROOT / "tests" / "hyperv" / "guest-node.sh").read_text(encoding="utf-8")
RUNNER = (ROOT / "tests" / "hyperv" / "regression.py").read_text(
    encoding="utf-8"
)
SOCKET = (ROOT / "kernel" / "wg_tcp.c").read_text(encoding="utf-8")


def integer_assignment(text: str, name: str) -> int:
    match = re.search(rf"^{re.escape(name)}=(\d+)$", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing integer assignment: {name}")
    return int(match.group(1))


def integer_define(text: str, name: str) -> int:
    match = re.search(rf"^#define {re.escape(name)} (\d+)$", text, re.MULTILINE)
    if not match:
        raise AssertionError(f"missing integer define: {name}")
    return int(match.group(1))


class TcpRoamingRuntimeContract(unittest.TestCase):
    def assert_ordered(self, text: str, *needles: str) -> None:
        position = -1
        for needle in needles:
            next_position = text.find(needle, position + 1)
            self.assertNotEqual(next_position, -1, f"missing ordered source: {needle}")
            self.assertGreater(next_position, position, f"out-of-order source: {needle}")
            position = next_position

    def test_modes_are_registered_with_bounded_hyperv_timeouts(self) -> None:
        self.assertIn("dual-router | half-open", SCRIPT)
        self.assertIn("tcp-roaming-netns)", GUEST)
        self.assertIn("$mode == dual-router || $mode == half-open", GUEST)
        self.assertIn("def tcp_roaming_netns_case", RUNNER)
        self.assertIn('timeout=max(self.args.timeout, 600)', RUNNER)
        self.assertNotIn('"tcp-nat44-dual-router-address-roam"', RUNNER)
        self.assertIn('"tcp-nat44-single-private-address-roam"', RUNNER)
        self.assertIn('"tcp-nat44-half-open-recovery"', RUNNER)
        self.assertIn('self.tcp_roaming_netns_case("half-open")', RUNNER)
        self.assertIn(
            "could not order static keys for the half-open client-initiator setup",
            SCRIPT,
        )

    def test_owned_resources_are_recorded_before_creation(self) -> None:
        self.assertIn("trap cleanup EXIT", SCRIPT)
        self.assertLess(
            SCRIPT.index('record_owned netns "$namespace"'),
            SCRIPT.index('ip netns add "$namespace"'),
        )
        self.assertLess(
            SCRIPT.index('record_link_names \\\n'),
            SCRIPT.index('ip link add "$client_old_if"'),
        )
        self.assertIn('ip netns del "$namespace"', SCRIPT)
        self.assertIn('ip link del dev "$iface"', SCRIPT)

    def test_runtime_tag_and_snmp_field_are_unambiguous(self) -> None:
        self.assertIn("printf -v tag '%05d' \"$(( suffix % 100000 ))\"", SCRIPT)
        self.assertNotIn("tag=${suffix: -5}", SCRIPT)
        self.assertIn('tcp_snmp_value "$ns_client" RetransSegs', SCRIPT)
        self.assertNotIn("TcpRetransSegs", SCRIPT)

    def test_dual_router_proves_same_identity_two_stream_roaming(self) -> None:
        dual_start = SCRIPT.index(
            'wait_tcp_tuple "$ns_server" "$server_address:$server_listen_port" '
            '\\\n\t"$old_public_address:$old_snat_port"'
        )
        dual = SCRIPT[dual_start:]
        dual_outer_policy = SCRIPT[
            SCRIPT.index("# Install both outer paths") : SCRIPT.index(
                "# Preplumb both inner routes"
            )
        ]
        dual_preplumb = SCRIPT[
            SCRIPT.index("# Preplumb both inner routes") : dual_start
        ]

        self.assertIn("old_snat_port=41001", SCRIPT)
        self.assertIn("new_snat_port=41002", SCRIPT)
        self.assertIn("stale_delay_seconds=110", SCRIPT)
        self.assertIn("stale_enqueue_timeout_seconds=8", SCRIPT)
        self.assertIn("pre_stage_carrier_quiet_seconds=12", SCRIPT)
        self.assertIn("pre_stage_carrier_timeout_seconds=30", SCRIPT)
        self.assertIn("route_notifier_minimum_settle_seconds=1", SCRIPT)
        self.assertIn("carrier_auth_quiet_seconds=12", SCRIPT)
        self.assertIn("carrier_auth_acquisition_timeout_seconds=60", SCRIPT)
        carrier_auth_ms = integer_assignment(
            SCRIPT, "carrier_auth_quiet_seconds"
        ) * 1000
        pre_auth_idle_ms = integer_define(
            SOCKET, "WG_TCP_AUTH_IDLE_TIMEOUT_MS"
        )
        cleanup_cadence_ms = integer_define(
            SOCKET, "WG_TCP_CLEANUP_INTERVAL_MS"
        )
        self.assertGreaterEqual(
            carrier_auth_ms, 2 * pre_auth_idle_ms + cleanup_cadence_ms
        )
        self.assertIn("quiet_window_seconds=16", SCRIPT)
        self.assertIn("quiet_acquisition_timeout_seconds=35", SCRIPT)
        self.assertIn("pre_fwmark_acquisition_timeout_seconds=45", SCRIPT)
        self.assertIn("old_key_stage_max_age_seconds=90", SCRIPT)
        self.assertLess(90, 120)
        self.assertIn("reject_after_time_seconds=180", SCRIPT)
        self.assertIn("new_client_listen_port=52222", SCRIPT)
        self.assertIn("new_nat_listen_port=$new_client_listen_port", SCRIPT)
        self.assertIn(
            'counter dnat to "$private_address:$target_listen_port"', SCRIPT
        )
        self.assert_ordered(
            dual_outer_policy,
            "net.ipv4.conf.all.src_valid_mark=1",
            "net.ipv4.conf.all.rp_filter=0",
            'ip route add table "$old_client_route_table"',
            'ip route add table "$new_client_route_table"',
            'ip rule add priority 100',
            'ip rule add priority 101',
            'route get "$server_address"',
        )
        self.assert_ordered(
            dual_preplumb,
            'ip link add wga type wireguard',
            'ip link add wgc type wireguard',
            '"$WG_FORK" set wgc \\\n',
            'listen-port "$new_client_listen_port" fwmark "$new_client_fwmark"',
            'ip link set wgc up',
            'ip route add "$new_server_tunnel_address/32" dev wgc \\\n'
            '\t\tsrc "$new_client_tunnel_address"',
            "install_server_inner_probe_counter",
            'ip route add "$server_tunnel_address/32" dev wga \\\n'
            '\t\tsrc "$client_tunnel_address"',
            'ip route add "$client_tunnel_address/32" dev wgb \\\n'
            '\t\tsrc "$server_tunnel_address"',
            'ip route add "$new_client_tunnel_address/32" dev wgb \\\n'
            '\t\tsrc "$new_server_tunnel_address"',
            'sleep "$route_notifier_minimum_settle_seconds"',
            'set wgb peer "$client_pub"',
            'allowed-ips "$client_tunnel_address/32,$new_client_tunnel_address/32"',
            'set wga peer "$server_pub"',
        )
        self.assertNotIn('set wgc private-key "$tmpdir/client.key"', dual_preplumb)
        self.assertNotIn('set wgc peer "$server_pub"', dual_preplumb)
        self.assertNotIn('ip link set wgc down', dual_preplumb)
        self.assert_ordered(
            dual,
            "wgc_flags_before_stale=",
            'ip -4 route get \\\n\t"$new_server_tunnel_address" oif wgc',
            'show wgc peers',
            'persistent-keepalive 0',
            'wait_ping "$ns_client" wga "$server_tunnel_address"',
            'wait_ping "$ns_server" wgb "$client_tunnel_address"',
            "pre_stage_carrier_deadline=",
            "pre_stage_carrier_started=-1",
            "pre_stage_carrier_candidate=",
            "pre_stage_carrier_signature=",
            "pre_stage_carrier_quiet_seconds",
            "IFS='|' read -r staged_old_server_remote old_client_outer_local",
            'tcp_tuple_has_fwmark "$ns_client" "$old_client_outer_local"',
            'tc qdisc add dev "$server_fabric_if" root handle 1:',
            'match ip src "$old_public_address/32"',
            'tcp_tuple_present "$ns_client" "$old_client_outer_local"',
            "post_netem_old_carrier_revalidated=1",
            "wga_tx_before_stale=",
            "qdisc_backlog_before_stale=",
            "old_inner_echo_before_stale=",
            "pre_stage_old_handshake=",
            "pre_stage_server_handshake=",
            "pre_stage_old_key_age_seconds=",
            "pre_stage_old_key_age_seconds < old_key_stage_max_age_seconds",
            "pre_stage_old_key_age_seconds + stale_enqueue_timeout_seconds +",
            "stale_delay_seconds +",
            "stale_monitor_margin_seconds < reject_after_time_seconds",
            "stale_enqueue_before_at=",
            "stale_enqueue_packets=1",
            'ping -4 -I wga -c 1 -W 1',
            "stale_enqueue_deadline=",
            "stale_enqueue_polls=0",
            "wga_tx_after_stale=",
            "qdisc_backlog_after_stale=",
            "stale_enqueue_after_at=",
            'ip link set wga down',
            'wait_tcp_established_tuple_absent "$ns_client" "$old_client_outer_local"',
            "old_client_cutoff_at=",
            "stale_release_earliest_at=",
            "stale_release_latest_at=",
            'tcp_tuple_present "$ns_server" "$staged_old_server_local"',
            "initial_bootstrap_endpoint_before=",
            "initial_bootstrap_server_rx_before=",
            "initial_bootstrap_backlog_before=",
            'set wgc private-key "$tmpdir/client.key"',
            'set wgc peer "$server_pub"',
            'moved_endpoint="$new_public_address:$forwarded_port"',
            'wait_peer_endpoint "$ns_server" wgb "$client_pub" "$moved_endpoint"',
            "new_reverse_syns_first_advance=$(wait_nat_counter_advance",
            'new_client_inbound_local="$client_new_address:$new_client_listen_port"',
            "new_client_stream_model=independent-outbound-pair",
            'retired wga TCP tuple returned to ESTABLISHED after new-path activation',
            'old accepted carrier retired before the staged rollback probe',
            "initial_bootstrap_acquisition=$(acquire_dual_quiet_window",
            "initial_bootstrap_wgc_handshake > 0",
            "initial_bootstrap_server_rx > initial_bootstrap_server_rx_before",
            "initial_bootstrap_backlog_after=",
            "wgc_handshake_before=$initial_bootstrap_wgc_handshake",
            'wait_ping "$ns_client" wgc "$new_server_tunnel_address"',
            'wait_ping "$ns_server" wgb "$new_client_tunnel_address"',
            "wgc_handshake_after=",
            "quiet_acquisition=$(acquire_dual_quiet_window pre-release",
            "quiet_barrier_duration quiet_signature",
            "minimum_stale_age_at_baseline_seconds=",
            "baseline_lead_seconds=$(( stale_release_earliest_at - SECONDS ))",
            "old_syn_snapshot_at=$(( stale_release_earliest_at - 1 ))",
            'exact old accepted tuple was absent immediately before release',
            'old_reverse_syns_before_release=',
            'new_reverse_syns_before_release=',
            'old_inner_echo_before_release=',
            'monitor_deadline=$(( stale_release_latest_at + stale_monitor_margin_seconds ))',
            "observed_inner_echo=",
            "observed_wgc_tx=",
            'old_inner_echo_after_release > old_inner_echo_before_release',
            "wgc_tx_after_release=",
            'old_reverse_syns_after_release=',
            "pre_fwmark_acquisition=$(acquire_dual_quiet_window pre-fwmark",
            "pre_fwmark_settle_duration pre_fwmark_signature",
            "pre_fwmark_new_syns pre_fwmark_inner_echo",
            "forced_reconnect_old_local=$pre_fwmark_new_server_local",
            'set wgb fwmark "$forced_server_fwmark"',
            'new_reverse_syns_after_forced=',
            'forced_reconnect_new_tuple=',
            'tcp_tuple_has_fwmark "$ns_server" "$forced_reconnect_new_local"',
            'pre-FwMark server outbound tuple remained ESTABLISHED',
            "forced_reconnect_old_client_inbound_remote=",
            'wait_tcp_tuple "$ns_client" "$new_client_inbound_local"',
            'wait_tcp_established_tuple_absent "$ns_client" "$new_client_inbound_local"',
            "carrier_auth_acquisition=$(acquire_dual_quiet_window post-fwmark-bootstrap",
            'carrier_auth_new_server_local == "$forced_reconnect_new_local"',
            'carrier_auth_new_client_outbound_local == "$pre_fwmark_new_client_outbound_local"',
            'carrier_auth_new_client_inbound_remote == "$forced_reconnect_new_local"',
            'carrier_auth_new_dnat == "$new_reverse_syns_after_forced"',
            "carrier_auth_server_tx > pre_fwmark_server_tx",
            "carrier_auth_wgc_rx > pre_fwmark_wgc_rx",
            "carrier_auth_duration >= carrier_auth_quiet_seconds",
            '# Exercise the tunnel only after replacement',
            'wait_ping "$ns_client" wgc "$new_server_tunnel_address"',
        )
        self.assertNotIn("ip route replace", dual)
        self.assertIn("test_scope=same_identity_two_carrier_surrogate", dual)
        self.assertIn("same_device_movement_owner=policy-churn", dual)
        self.assertIn("same_private_key_two_devices=pass", dual)
        self.assertIn(
            "outer_policy_preinstalled_before_peer_activation=pass", dual
        )
        self.assertIn(
            "inner_route_preinstalled_before_peer_activation=pass", dual
        )
        self.assertIn(
            "new_identity_peer_activated_after_stale_queue=pass", dual
        )
        self.assertIn("old_device_deactivated_after_stale_queue=pass", dual)
        self.assertIn(
            "old_client_established_socket_retired_before_new_activation=pass",
            dual,
        )
        self.assertIn("pre_stage_bidirectional_key_refresh=pass", dual)
        self.assertIn("wgc_keyless_before_stale_queue=pass", dual)
        self.assertIn("wgc_admin_up_before_stale_queue=pass", dual)
        self.assertIn("wgc_keyless_route_preplumb=persistent-up", dual)
        self.assertIn("inner_route_preferred_sources=path-specific", dual)
        self.assertIn("shared_public_forwarded_port", dual)
        self.assertIn("base64.b64decode(sys.argv[1], validate=True)", SCRIPT)
        self.assertIn('mv "$tmpdir/server.key" "$tmpdir/client.key"', SCRIPT)
        self.assertIn("simultaneous_noise_key_order=server-lower-than-client", dual)
        self.assertIn(
            "simultaneous_noise_branch_runtime_observed=not-instrumented", dual
        )
        self.assertIn("tcp_stream_model=%s", dual)
        self.assertIn("new_client_outbound_tuple=%s<->%s:%s", dual)
        self.assertIn("new_client_inbound_tuple=%s<->%s", dual)
        self.assertIn("new_server_outbound_tuple=%s<->%s", dual)
        self.assertNotIn("collision_selected_direction", dual)
        self.assertNotIn("dual_stream_settle_deadline", dual)
        self.assertNotIn(
            "the correlated TCP stream pair did not settle with exact marked tuples",
            dual,
        )
        self.assertIn(
            "shared_peer_allowed_ips=%s/32,%s/32", dual
        )
        self.assertIn("exact_client_socket_marks=pass", dual)
        self.assertIn("pre_stage_carrier_quiet_required_seconds", dual)
        self.assertIn("pre_peer_route_notifier_minimum_settle_seconds", dual)
        self.assertIn("pre_stage_carrier_quiet_seconds", dual)
        self.assertIn("pre_stage_carrier_quiet_resets", dual)
        self.assertIn("pre_stage_carrier_valid_samples", dual)
        self.assertIn("post_netem_old_carrier_revalidated", dual)
        self.assertNotIn(
            "wgc was not handshake- and transfer-clean before activation traffic",
            dual,
        )
        self.assertIn("initial_carrier_bootstrap_authentication=pass", dual)
        self.assertIn(
            "initial_carrier_bootstrap_no_explicit_tunnel_traffic=pass", dual
        )
        self.assertIn("initial_carrier_bootstrap_quiet_required_seconds", dual)
        self.assertIn("initial_carrier_bootstrap_quiet_seconds", dual)
        self.assertIn("initial_carrier_bootstrap_server_receive_bytes", dual)
        self.assertIn("initial_carrier_bootstrap_server_transmit_bytes", dual)
        self.assertIn("initial_carrier_bootstrap_new_dnat", dual)
        self.assertIn("initial_carrier_bootstrap_delayed_backlog", dual)
        self.assertIn(
            "initial_bootstrap_backlog_after -ge $initial_bootstrap_backlog_before",
            dual,
        )
        self.assertNotIn(
            'initial_bootstrap_backlog_after == "$initial_bootstrap_backlog_before"',
            dual,
        )
        self.assertIn("initial_bootstrap_new_client_outbound_local", dual)
        self.assertIn("initial_bootstrap_new_client_inbound_remote", dual)
        self.assertIn("quiet_new_client_outbound_local", dual)
        self.assertIn("quiet_new_client_inbound_remote", dual)
        self.assertIn("pre_fwmark_new_client_outbound_local", dual)
        self.assertIn("pre_fwmark_new_client_inbound_remote", dual)
        self.assertIn("carrier_auth_new_client_outbound_local", dual)
        self.assertIn("carrier_auth_new_client_inbound_remote", dual)
        self.assertIn("explicit_bidirectional_transfer_after_bootstrap=pass", dual)
        self.assertIn("new_client_tx_during_release", dual)
        self.assertIn("pre_release_quiet_handshakes_and_counters=pass", dual)
        self.assertIn("first-valid=$first_valid", SCRIPT)
        self.assertIn("previous-valid=$previous_valid", SCRIPT)
        self.assertIn("last-invalid=$last_invalid", SCRIPT)
        self.assertIn("delayed_rx_source_isolation=pass", dual)
        self.assertIn("observed_rx_recheck=", dual)
        self.assertIn("observed_rx_recheck > observed_rx", dual)
        self.assertIn("delayed_inner_echo_request=pass", dual)
        self.assertIn("minimum_stale_age_at_baseline_seconds", dual)
        staging = dual[
            dual.index("stale_enqueue_before_at=") : dual.index(
                "stale_enqueue_after_at="
            )
        ]
        self.assertEqual(staging.count('ping -4 -I wga -c 1 -W 1'), 1)
        refresh_end = dual.index(
            'wait_ping "$ns_server" wgb "$client_tunnel_address"'
        )
        tuple_reacquired = dual.index(
            "IFS='|' read -r staged_old_server_remote old_client_outer_local"
        )
        netem_installed = dual.index(
            'tc qdisc add dev "$server_fabric_if" root handle 1:'
        )
        stale_ping = dual.index('ping -4 -I wga -c 1 -W 1', netem_installed)
        self.assertLess(refresh_end, tuple_reacquired)
        self.assertLess(tuple_reacquired, netem_installed)
        self.assertLess(
            dual.index("post_netem_old_carrier_revalidated=1"), stale_ping
        )
        quiet_loop = dual[
            dual.index("pre_stage_carrier_deadline=") : tuple_reacquired
        ]
        self.assertIn("pre_stage_carrier_started=-1", quiet_loop)
        self.assertIn("pre_stage_carrier_candidate=", quiet_loop)
        self.assertIn("pre_stage_carrier_resets", quiet_loop)
        self.assertIn("SECONDS - pre_stage_carrier_started", quiet_loop)
        self.assertIn("pre_stage_carrier_quiet_seconds", quiet_loop)
        self.assertIn("stale_enqueue_packets=%s", dual)
        self.assertIn("stale_enqueue_polls=%s", dual)
        self.assertIn("old_client_cutoff_at=%s", dual)
        self.assertIn(
            "minimum_stale_age_at_earliest_release_seconds", dual
        )
        self.assertIn("pre_stage_client_key_age_seconds", dual)
        self.assertIn("pre_stage_server_key_age_seconds", dual)
        self.assertIn("exact_old_tuple_immediately_before_release=pass", dual)
        self.assertIn("pre_fwmark_syn_sent=0", dual)
        self.assertIn("pre_fwmark_quiet_counters_and_handshakes=pass", dual)
        self.assertIn('endpoint "$old_public_address:$forwarded_port"', SCRIPT)
        self.assertIn(
            'moved_endpoint="$new_public_address:$forwarded_port"', dual
        )
        self.assertIn("stale_old_carrier_rollback=blocked", dual)
        self.assertIn("transient_rollback_syn_guard=pass", dual)
        self.assertIn("configured_port_preserved=pass", dual)
        self.assertIn("forced_reconnect_reverse_syn_new_dnat", dual)
        self.assertIn("forced_reconnect_old_established_retired=pass", dual)
        self.assertIn("forced_reconnect_old_residual_tcp_state=%s", dual)
        self.assertIn("trap report_error ERR", SCRIPT)
        self.assertNotIn('{ print $(i + 1); exit }', SCRIPT)
        self.assertIn("forced_reconnect_new_socket_mark", dual)
        self.assertIn("carrier_bootstrap_authentication=pass", dual)
        self.assertIn(
            "carrier_bootstrap_no_explicit_tunnel_traffic=pass", dual
        )
        self.assertIn("carrier_bootstrap_server_tx_before=%s", dual)
        self.assertIn("carrier_bootstrap_server_tx_after=%s", dual)
        self.assertIn("carrier_bootstrap_server_tx_delta=%s", dual)
        self.assertIn("carrier_bootstrap_wgc_rx_before=%s", dual)
        self.assertIn("carrier_bootstrap_wgc_rx_after=%s", dual)
        self.assertIn("carrier_bootstrap_wgc_rx_delta=%s", dual)
        self.assertIn("carrier_bootstrap_counter_delta=pass", dual)
        self.assertIn("carrier_bootstrap_counter_stability=pass", dual)
        self.assertIn("carrier_bootstrap_quiet_required_seconds", dual)
        self.assertIn("carrier_bootstrap_quiet_seconds", dual)
        peer_configuration = dual.index('set wgc peer "$server_pub"')
        initial_carrier_gate = dual.index(
            "initial_bootstrap_acquisition=$(acquire_dual_quiet_window",
            peer_configuration,
        )
        initial_explicit_ping = dual.index(
            'wait_ping "$ns_client" wgc "$new_server_tunnel_address"',
            initial_carrier_gate,
        )
        self.assertNotIn("wait_ping", dual[peer_configuration:initial_carrier_gate])
        self.assertNotIn("ping -4", dual[peer_configuration:initial_carrier_gate])
        self.assertLess(initial_carrier_gate, initial_explicit_ping)
        forced_change = dual.index(
            'set wgb fwmark "$forced_server_fwmark"'
        )
        carrier_gate = dual.index(
            "carrier_auth_acquisition=$(acquire_dual_quiet_window",
            forced_change,
        )
        recovery_ping = dual.index(
            'wait_ping "$ns_client" wgc "$new_server_tunnel_address"',
            carrier_gate,
        )
        self.assertNotIn("wait_ping", dual[forced_change:carrier_gate])
        self.assertNotIn("ping -4", dual[forced_change:carrier_gate])
        self.assertLess(carrier_gate, recovery_ping)

        qdisc_reader = SCRIPT[
            SCRIPT.index("qdisc_backlog_packets()") : SCRIPT.index(
                "nat_rule_packets()"
            )
        ]
        self.assertIn("END { if (found) print packets + 0 }", qdisc_reader)
        self.assertNotIn("\n\t\t\texit\n", qdisc_reader)

    def test_dual_quiet_signature_resets_and_covers_all_state(self) -> None:
        signature = SCRIPT[
            SCRIPT.index("dual_quiet_state_signature()") : SCRIPT.index(
                "dual_quiet_signature_valid()"
            )
        ]
        validator = SCRIPT[
            SCRIPT.index("dual_quiet_signature_valid()") : SCRIPT.index(
                "acquire_dual_quiet_window()"
            )
        ]
        acquisition = SCRIPT[
            SCRIPT.index("acquire_dual_quiet_window()") : SCRIPT.index(
                "sanitize_tcp_info()"
            )
        ]
        inner_counter = SCRIPT[
            SCRIPT.index("install_server_inner_probe_counter()") : SCRIPT.index(
                "wait_nat_counter_advance()"
            )
        ]

        for needle in (
            'peer_endpoint "$ns_server" wgb "$client_pub"',
            'tcp_tuple_present "$ns_server" "$staged_old_server_local"',
            'tcp_locals_for_remote "$ns_server"',
            '"$new_public_address:$forwarded_port"',
            "new_client_outbound_locals=$(tcp_locals_for_remote_address",
            "new_client_inbound_remotes=$(tcp_remotes_for_local",
            'tcp_tuple_has_fwmark "$ns_client" "$new_client_outbound_local"',
            'tcp_tuple_has_fwmark "$ns_client" "$new_client_inbound_local"',
            'if ! tcp_tuple_present "$ns_client" "$old_client_outer_local"',
            '"$new_client_fwmark"',
            'tcp_state_count "$ns_client" syn-sent',
            'tcp_state_count "$ns_server" syn-sent',
            'nat_rule_packets "$ns_old_router"',
            'nat_rule_packets "$ns_new_router"',
            "server_old_echo_packets",
            'latest_handshake "$ns_client" wga',
            'latest_handshake "$ns_client" wgc',
            'latest_handshake "$ns_server" wgb',
            'received_bytes "$ns_client" wga',
            'sent_bytes "$ns_client" wga',
            'received_bytes "$ns_client" wgc',
            'sent_bytes "$ns_client" wgc',
            'received_bytes "$ns_server" wgb',
            'sent_bytes "$ns_server" wgb',
        ):
            self.assertIn(needle, signature)
        self.assertIn("new_client_outbound_local new_client_inbound_remote", validator)
        self.assertIn("-n $new_client_outbound_local", validator)
        self.assertIn("-n $new_client_inbound_remote", validator)
        self.assertIn("$new_mark == 1", validator)
        self.assertNotIn("$new_mark =~ ^[01]$", validator)
        self.assertIn("deadline=$(( SECONDS + timeout_seconds ))", acquisition)
        self.assertIn('[[ $signature != "$candidate" ]]', acquisition)
        self.assertIn("stable_started=$SECONDS", acquisition)
        self.assertIn("stable_started=-1", acquisition)
        self.assertIn("duration >= required_seconds", acquisition)
        self.assertEqual(
            SCRIPT.count("acquire_dual_quiet_window pre-"),
            2,
        )
        self.assertIn("iifname wgb", inner_counter)
        self.assertIn('ip saddr "$client_tunnel_address"', inner_counter)
        self.assertIn('ip daddr "$server_tunnel_address"', inner_counter)
        self.assertIn("icmp type echo-request counter", inner_counter)
        self.assertNotIn("quiet_barrier_deadline=", SCRIPT)
        self.assertNotIn("pre_fwmark_settle_deadline=", SCRIPT)
        self.assertNotIn("dual_pre_release_quiet_state", SCRIPT)

    def test_half_open_requires_exact_loss_and_replacement_evidence(self) -> None:
        half_open_start = SCRIPT.index("quiet_window_seconds=4")
        half_open = SCRIPT[
            half_open_start : SCRIPT.index("\texit 0\nfi", half_open_start)
        ]
        blackhole = SCRIPT[
            SCRIPT.index("install_half_open_blackhole()") : SCRIPT.index(
                "half_open_syn_packets()"
            )
        ]

        self.assertIn("net.ipv4.tcp_retries2=5", SCRIPT)
        self.assertIn("net.ipv4.tcp_syn_retries=3", SCRIPT)
        self.assertIn("counter drop", blackhole)
        self.assertNotIn("reject", blackhole)
        self.assert_ordered(
            half_open,
            "pre_blackhole_server_remotes=$quiet_server_remotes",
            'tcp_info_for_tuple "$ns_client" "$old_client_local"',
            'old_bytes_retrans_before old_retrans_total_before',
            "install_half_open_blackhole",
            "old_bytes_retrans_now > old_bytes_retrans_before",
            "old_carrier_retrans_metric_advanced=true",
            "tcp_retrans_after > tcp_retrans_before",
            "nft delete table ip wgtcp_halfopen",
            "recovered_pair=$(wait_correlated_recovery_pair",
            "conntrack_server_remote_for_client_local",
            'wait_tcp_tuple_absent "$ns_client" "$old_client_local"',
            'persistent-keepalive 0',
            "server_rx_after_client_ping > server_rx_before_client_ping",
            "client_rx_after_server_ping > client_rx_before_server_ping",
        )
        self.assertIn("new_tuples_outside_pre_blackhole_sets=pass", half_open)
        self.assertIn("old_client_outbound_absent=pass", half_open)
        self.assertIn("old_client_carrier_tcp_info_loss=pass", half_open)
        self.assertIn("old_client_carrier_retrans_metric=pass", half_open)
        self.assertIn("recovery_carrier_direction=%s", half_open)
        self.assertIn("reverse-dnat-tuple", half_open)
        self.assertNotIn("unacked:", half_open)
        self.assertIn("blackhole_drop_only=true", half_open)
        self.assertIn("production_timing_proof=false", half_open)
        self.assertIn(
            "timing_scope=namespace-accelerated-not-production-default",
            half_open,
        )


if __name__ == "__main__":
    unittest.main()

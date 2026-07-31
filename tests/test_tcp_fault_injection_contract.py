#!/usr/bin/env python3
"""Source-level guards for DEBUG-only TCP stream fault injection."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end)]


class TcpFaultInjectionContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.socket = (ROOT / "kernel" / "socket.c").read_text(encoding="utf-8")
        cls.guest_build = (ROOT / "tests" / "hyperv" / "guest-build.sh").read_text(
            encoding="utf-8"
        )
        cls.guest_module = (
            ROOT / "tests" / "hyperv" / "guest-module.sh"
        ).read_text(encoding="utf-8")
        cls.guest_node = (ROOT / "tests" / "hyperv" / "guest-node.sh").read_text(
            encoding="utf-8"
        )

    def test_controls_and_counters_exist_only_in_debug_builds(self) -> None:
        controls = section(
            self.socket,
            "#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)\n"
            "#define WG_TCP_TEST_MAX_GARBAGE_PREFIX",
            "#define WG_TCP_MAX_PENDING_CONNECTIONS",
        )
        debug, production = controls.split("#else", maxsplit=1)

        for name in (
            "tcp_test_max_send_bytes",
            "tcp_test_garbage_prefix_bytes",
            "tcp_test_queue_limit",
            "tcp_test_write_delay_ms",
        ):
            self.assertIn(f"module_param_named({name}", debug)
            self.assertIn("uint, 0600", debug[debug.index(name) :])
            self.assertNotIn(name, production)
        for name in (
            "tcp_test_short_writes",
            "tcp_test_injected_prefixes",
            "tcp_test_resyncs",
            "tcp_test_queue_drops",
        ):
            self.assertIn(f"module_param_cb({name}", debug)
            self.assertNotIn(name, production)

    def test_fault_controls_use_a_separate_module_variant(self) -> None:
        self.assertIn("wireguard-fork-fault.ko", self.guest_build)
        self.assertIn("EXTRA_CFLAGS=-DWG_TCP_FAULT_INJECTION", self.guest_build)
        self.assertIn("fork|fork-debug|fork-fault)", self.guest_module)
        self.assertIn("FORK_FAULT_MODULE", self.guest_module)
        self.assertIn('wireguard-fork-fault.params', self.guest_build)
        self.assertIn("modinfo -p", self.guest_build)
        self.assertIn("$variant.params", self.guest_build)
        self.assertIn("if grep -q '^tcp_test_'", self.guest_build)
        self.assertIn('die "fault parameters leaked into $variant"', self.guest_build)
        self.assertIn('die "fault module is missing tcp_test_$parameter"', self.guest_build)
        self.assertIn("verify_module_metadata", self.guest_build)
        self.assertIn('cmp -s "$actual_root/$variant.params" "$module.params"', self.guest_build)
        self.assertIn('"$ARTIFACT_ROOT/manifest.json"', self.guest_build)
        self.assertIn('manifest.get("kernel_release")', self.guest_build)

    def test_guest_owns_fault_module_load_and_restore_in_one_command(self) -> None:
        self.assertIn("restore_fault_module()", self.guest_node)
        self.assertIn("trap restore_fault_module EXIT", self.guest_node)
        self.assertIn("trap 'exit 129' HUP", self.guest_node)
        self.assertIn('"$module_helper" fork-fault', self.guest_node)
        self.assertIn('"$module_helper" fork >/dev/null', self.guest_node)
        self.assertIn("restored_kernel_variant=fork", self.guest_node)

    def test_send_cap_forces_real_suffix_writes(self) -> None:
        sender = section(
            self.socket,
            "static int wg_tcp_send_frame(",
            "static void wg_tcp_arm_write_space(",
        )

        self.assertIn("send_len = wg_tcp_test_send_len(frame->len)", sender)
        self.assertIn(".iov_len = send_len", sender)
        self.assertIn("kernel_sendmsg(sock, &msg, &vec, 1, send_len)", sender)
        self.assertIn("atomic64_inc(&wg_tcp_test_short_writes)", sender)

    def test_garbage_prefix_preserves_the_authenticated_record_length(self) -> None:
        builder = section(
            self.socket,
            "static struct sk_buff *wg_tcp_build_frame(",
            "static void wg_tcp_schedule_write_locked(",
        )

        record_length = builder.index("total_len = header_len + payload->len;")
        allocate = builder.index("alloc_skb(prefix_len + total_len")
        prefix = builder.index("memset(skb_put(frame, prefix_len), 0xa5")
        header = builder.index("skb_put_data(frame, &encap_header")
        self.assertLess(record_length, allocate)
        self.assertLess(allocate, prefix)
        self.assertLess(prefix, header)
        self.assertIn("WG_TCP_TEST_MAX_GARBAGE_PREFIX", self.socket)
        self.assertIn("high byte\n\t\t * of its network-order length", builder)
        self.assertIn("atomic64_inc(&wg_tcp_test_injected_prefixes)", builder)

    def test_queue_pressure_uses_a_debug_limit_and_observable_drop_counter(self) -> None:
        enqueue = section(
            self.socket,
            "static int wg_tcp_enqueue_frame(",
            "int wg_socket_send_skb_to_peer(",
        )

        self.assertIn("queue_limit = wg_tcp_test_effective_queue_limit()", enqueue)
        self.assertIn("skb_queue_len(&peer->send_queue) >= queue_limit", enqueue)
        self.assertIn("ret = -ENOBUFS", enqueue)
        self.assertIn("atomic64_inc(&wg_tcp_test_queue_drops)", enqueue)

    def test_writer_delay_is_bounded_and_runs_outside_queue_lock(self) -> None:
        controls = section(
            self.socket,
            "static unsigned int wg_tcp_test_take_write_delay_ms(void)",
            "#define WG_TCP_MAX_PENDING_CONNECTIONS",
        )
        writer = section(
            self.socket,
            "void wg_tcp_write_worker(",
            "void wg_peer_discard_partial_read(",
        )

        self.assertIn("WG_TCP_TEST_MAX_WRITE_DELAY_MS", controls)
        self.assertIn("xchg(&wg_tcp_test_write_delay_ms, 0U)", controls)
        self.assertIn("wg_tcp_test_take_write_delay_ms()", writer)
        delay = writer.index("msleep(write_delay_ms)")
        recheck_lock = writer.index("spin_lock_bh(&peer->tcp_lock)", delay)
        recheck_unlock = writer.index(
            "spin_unlock_bh(&peer->tcp_lock)", recheck_lock
        )
        cleanup_guard = writer.index(
            "!READ_ONCE(peer->device->tcp_cleanup_scheduled)", recheck_lock
        )
        dequeue = writer.index("__skb_dequeue(&peer->send_queue)", recheck_unlock)
        send = writer.index("wg_tcp_send_frame(socket, skb)", dequeue)
        self.assertLess(delay, recheck_lock)
        self.assertLess(recheck_lock, cleanup_guard)
        self.assertLess(cleanup_guard, recheck_unlock)
        self.assertLess(recheck_lock, recheck_unlock)
        self.assertLess(recheck_unlock, dequeue)
        self.assertLess(dequeue, send)
        self.assertEqual(writer.count("msleep(write_delay_ms)"), 1)

    def test_successful_parser_recovery_is_counted(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )
        resync = reader.index("if (!wg_sync_header(peer, socket))")
        count = reader.index("atomic64_inc(&wg_tcp_test_resyncs)", resync)
        revalidate = reader.index(
            "wg_check_potential_header_validity(", count
        )

        self.assertLess(resync, count)
        self.assertLess(count, revalidate)


if __name__ == "__main__":
    unittest.main()

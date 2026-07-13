#!/usr/bin/env python3
"""Source-level guards for TCP provisional and connect-failure lifetimes."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    return text[start_index : text.index(end, start_index + len(start))]


def final_section(text: str, start: str, end: str) -> str:
    start_index = text.rindex(start)
    return text[start_index : text.index(end, start_index + len(start))]


class TcpLifecycleContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.socket = source("kernel/socket.c")
        cls.peer = source("kernel/peer.c")
        cls.peer_header = source("kernel/peer.h")
        cls.device_header = source("kernel/device.h")

    def test_pending_connections_have_a_locked_hard_cap(self) -> None:
        add = final_section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_touch_tcp_connection(",
        )

        self.assertIn("#define WG_TCP_MAX_PENDING_CONNECTIONS 128", self.socket)
        self.assertIn("unsigned int tcp_pending_connections;", self.device_header)
        lock = "spin_lock_bh(&wg->tcp_connection_list_lock);"
        cap = "wg->tcp_pending_connections >= WG_TCP_MAX_PENDING_CONNECTIONS"
        insert = "list_add_tail_rcu(&entry->tcp_connection_ll"
        increment = "++wg->tcp_pending_connections;"
        unlock = "spin_unlock_bh(&wg->tcp_connection_list_lock);"
        for operation in (lock, cap, insert, increment, unlock):
            self.assertIn(operation, add)
        self.assertLess(add.index(lock), add.index(cap))
        self.assertLess(add.index(cap), add.index(insert))
        self.assertLess(add.index(insert), add.index(increment))
        self.assertLess(add.index(increment), add.rindex(unlock))

    def test_live_temp_connections_age_out_and_keep_the_sweeper_armed(self) -> None:
        add = final_section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_touch_tcp_connection(",
        )
        touch = section(
            self.socket,
            "static void wg_touch_tcp_connection(struct wg_peer *peer)\n{",
            "static struct wg_tcp_socket_list_entry *",
        )
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,",
            "static void wg_destroy_temp_peer(",
        )
        cleanup = section(
            self.socket,
            "void wg_tcp_cleanup_worker(struct work_struct *work)",
            "struct wg_peer *wg_temp_peer_create(",
        )
        data_ready = section(
            self.socket,
            "void wg_tcp_data_ready(struct sock *sk)",
            "void wg_tcp_write_space(struct sock *sk)",
        )

        self.assertIn("#define WG_TCP_AUTH_IDLE_TIMEOUT_MS 5000", self.socket)
        self.assertIn("#define WG_TCP_AUTH_MAX_LIFETIME_MS 30000", self.socket)
        self.assertIn("entry->created_at = ktime_get();", add)
        self.assertIn("entry->timestamp = entry->created_at;", add)
        self.assertIn("entry->timestamp = ktime_get();", touch)
        self.assertIn("wg_touch_tcp_connection(peer);", data_ready)
        self.assertIn("ktime_ms_delta(now, entry->timestamp)", claim)
        self.assertIn("WG_TCP_AUTH_IDLE_TIMEOUT_MS", claim)
        self.assertIn("ktime_ms_delta(now, entry->created_at)", claim)
        self.assertIn("WG_TCP_AUTH_MAX_LIFETIME_MS", claim)
        self.assertIn("mod_delayed_work(system_wq, &wg->tcp_cleanup_work, 0);", add)
        self.assertIn("pending = !list_empty(&wg->tcp_connection_list);", cleanup)
        self.assertIn("WG_TCP_CLEANUP_INTERVAL_MS", cleanup)

    def test_claimed_entry_remains_the_only_destruction_owner(self) -> None:
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,",
            "static void wg_destroy_temp_peer(",
        )
        destroy = section(
            self.socket,
            "wg_destroy_tcp_connection_entry(struct wg_device *wg,",
            "void wg_remove_from_tcp_connection_list(",
        )
        remove = section(
            self.socket,
            "void wg_remove_from_tcp_connection_list(",
            "void wg_tcp_outbound_remove_worker(",
        )

        self.assertEqual(claim.count("list_del_rcu("), 1)
        self.assertIn("synchronize_rcu();", claim)
        self.assertNotIn("list_del", destroy)
        self.assertIn("entry = wg_claim_tcp_connection", remove)
        self.assertIn("wg_destroy_tcp_connection_entry(wg, entry);", remove)
        self.assertIn("--wg->tcp_pending_connections;", destroy)

    def test_connect_errors_use_one_complete_unwind(self) -> None:
        unwind = section(
            self.socket,
            "static void wg_tcp_connect_unwind(",
            "// Attempt to establish a TCP connection",
        )
        connect = section(
            self.socket,
            "int wg_tcp_connect(struct wg_peer *peer)\n{",
            "/* FIX: -Wunused-function",
        )

        self.assertIn("struct socket *socket = NULL;", connect)
        self.assertIn("&socket);", connect)
        self.assertNotIn("&peer->peer_socket);", connect)
        self.assertGreaterEqual(connect.count("goto fail;"), 5)
        self.assertEqual(connect.count("wg_tcp_connect_unwind(peer, socket);"), 1)
        self.assertNotIn("sock_release(", connect)

        detach = "sk->sk_user_data = NULL;"
        peer_alias = "peer->peer_socket = NULL;"
        outbound_alias = "peer->outbound_socket = NULL;"
        release = "sock_release(socket);"
        for operation in (detach, peer_alias, outbound_alias, release):
            self.assertIn(operation, unwind)
        self.assertLess(unwind.index(detach), unwind.index(release))
        self.assertLess(unwind.index(peer_alias), unwind.index(release))
        self.assertLess(unwind.index(outbound_alias), unwind.index(release))
        for state in (
            "peer->tcp_connecting = false;",
            "peer->tcp_pending = false;",
            "peer->tcp_established = false;",
            "peer->outbound_connected = false;",
            "peer->tcp_outbound_callbacks_set = false;",
        ):
            self.assertIn(state, unwind)

    def test_synchronous_connect_failure_cannot_delegate_socket_ownership(self) -> None:
        state_change = section(
            self.socket,
            "void wg_tcp_state_change(struct sock *sk)",
            "void log_wireguard_endpoint(",
        )

        self.assertIn("bool tcp_connecting;", self.peer_header)
        self.assertIn("peer->tcp_connecting = false;", self.peer)
        self.assertIn("if (peer->tcp_connecting) {", state_change)
        suppress = section(
            state_change,
            "if (peer->tcp_connecting) {",
            "peer->tcp_reconnect_requested = true;",
        )
        self.assertNotIn("queue_outbound_remove = true", suppress)

    def test_peer_removal_quiesces_callbacks_and_workers_before_death(self) -> None:
        remove = section(
            self.peer,
            "void wg_peer_remove(struct wg_peer *peer)",
            "void wg_peer_remove_all(struct wg_device *wg)",
        )
        remove_all = section(
            self.peer,
            "void wg_peer_remove_all(struct wg_device *wg)",
            "static void rcu_release(",
        )
        stop = section(
            self.socket,
            "void wg_tcp_peer_stop(struct wg_peer *peer)",
            "struct wg_peer *wg_temp_peer_create(",
        )

        self.assertLess(
            remove.index("wg_tcp_peer_stop(peer);"),
            remove.index("peer_make_dead(peer);"),
        )
        self.assertNotIn("wg_clean_peer_socket(peer", remove)
        self.assertIn("wg_tcp_peer_stop(peer);", remove_all)
        self.assertLess(
            stop.index("peer->tcp_outbound_remove_scheduled = true;"),
            stop.index("cancel_work_sync(&peer->tcp_write_work);"),
        )
        self.assertLess(
            stop.index("cancel_work_sync(&peer->tcp_write_work);"),
            stop.index("wg_reset_tcp_socket_callbacks(peer, false);"),
        )
        self.assertLess(
            stop.index("wg_reset_tcp_socket_callbacks(peer, false);"),
            stop.index("wg_clean_peer_socket(peer, true, false, false);"),
        )

    def test_retry_timeout_delegates_socket_release_to_removal_owner(self) -> None:
        retry = section(
            self.socket,
            "void wg_tcp_retry_worker(struct work_struct *work)",
            "int wg_add_tcp_socket_to_list(",
        )

        self.assertIn("peer->tcp_outbound_remove_scheduled = true;", retry)
        self.assertIn("peer->tcp_reconnect_requested = true;", retry)
        self.assertIn(
            "mod_delayed_work(system_wq, &peer->tcp_outbound_remove_work, 0);",
            retry,
        )
        self.assertNotIn("sock_release(", retry)
        self.assertNotIn("wg_reset_tcp_socket_callbacks(", retry)


if __name__ == "__main__":
    unittest.main()

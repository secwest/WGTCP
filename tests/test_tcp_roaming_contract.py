#!/usr/bin/env python3
"""Source-level guards for authenticated TCP endpoint mobility state."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    return text[start_index : text.index(end, start_index + len(start))]


class TcpRoamingContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        receive = source("kernel/receive.c")
        cls.socket = source("kernel/wg_tcp.c")
        cls.peer_header = source("kernel/peer.h")
        cls.queueing = source("kernel/queueing.h")
        cls.netlink = source("kernel/netlink.c")
        cls.noise = source("kernel/noise.c")
        cls.handshake = section(
            receive,
            "static void wg_receive_handshake_packet(",
            "static void keep_key_fresh(",
        )
        cls.data_done = section(
            receive,
            "static void wg_packet_consume_data_done(",
            "int wg_packet_rx_poll(",
        )
        cls.authenticated_update = section(
            cls.socket,
            "void wg_socket_set_peer_endpoint_authenticated(",
            "void wg_socket_set_peer_endpoint_authenticated_from_skb(",
        )
        cls.configured_update = section(
            cls.socket,
            "static void wg_socket_set_peer_endpoint_internal(",
            "void wg_socket_set_peer_endpoint(",
        )
        cls.listener = section(
            cls.socket,
            "int wg_tcp_listener_worker(",
            "int wg_setup_tcp_listen4(",
        )
        cls.connect = section(
            cls.socket,
            "int wg_tcp_connect(struct wg_peer *peer)",
            "void wg_extract_endpoint_from_sock(",
        )

    def test_handshake_receive_does_not_own_provisional_entries(self) -> None:
        for forbidden in (
            "tcp_connection_list",
            "list_del_rcu",
            "synchronize_rcu",
            "kfree(socket_iter)",
            "kfree(socket_iter->temp_peer)",
        ):
            self.assertNotIn(forbidden, self.handshake)

    def test_tcp_does_not_use_udp_endpoint_learning(self) -> None:
        guarded_updates = re.findall(
            r"if \((?:wg|peer->device)->transport == WG_TRANSPORT_UDP\)\s*"
            r"(?:\{\s*)?wg_socket_set_peer_endpoint_from_skb\(peer, skb\);",
            self.handshake,
        )
        self.assertEqual(len(guarded_updates), 2)

        authenticated_updates = re.findall(
            r"PACKET_CB\(skb\)->outer_ipproto == IPPROTO_TCP\)\s*"
            r"(?:\{\s*)?wg_socket_set_peer_endpoint_authenticated_from_skb"
            r"\(peer, skb\);",
            self.handshake,
        )
        self.assertEqual(len(authenticated_updates), 2)

    def test_async_receive_records_carrier_provenance(self) -> None:
        receive_dispatch = section(
            self.socket,
            "static int wg_receive(",
            "static int wg_set_socket_timeouts(",
        )
        self.assertIn("u8 outer_ipproto;", self.queueing)
        self.assertIn("u64 tcp_connection_id;", self.queueing)
        self.assertIn(
            "PACKET_CB(skb)->outer_ipproto = sk->sk_protocol;",
            receive_dispatch,
        )
        self.assertIn(
            "PACKET_CB(skb)->tcp_connection_id =",
            receive_dispatch,
        )
        self.assertIn(
            "PACKET_CB(skb)->tcp_connection_id);",
            self.data_done,
        )

    def test_authentication_marks_the_exact_tcp_carrier(self) -> None:
        add_start = self.socket.rindex(
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,"
        )
        add = self.socket[
            add_start : self.socket.index("static void wg_touch_tcp_connection(", add_start)
        ]
        mark = section(
            self.socket,
            "static void wg_tcp_mark_connection_authenticated(",
            "void wg_tcp_set_device_mark(",
        )

        self.assertIn("atomic64_inc_return(", add)
        self.assertIn("temp_peer->tcp_connection_id = entry->connection_id;", add)
        self.assertIn("if (!wg || !connection_id)", mark)
        self.assertIn("entry->connection_id != connection_id", mark)

    def test_configured_listen_port_is_not_observed_source_port(self) -> None:
        self.assertIn("__be16 tcp_peer_listen_port;", self.peer_header)
        self.assertIn(
            "peer->tcp_peer_listen_port =",
            self.configured_update,
        )
        self.assertIn(
            "target.addr4.sin_port = peer->tcp_peer_listen_port;",
            self.authenticated_update,
        )
        self.assertIn(
            "target.addr6.sin6_port = peer->tcp_peer_listen_port;",
            self.authenticated_update,
        )
        self.assertNotIn("tcp_peer_listen_port =", self.authenticated_update)
        self.assertNotIn("wg_tcp_connect(", self.authenticated_update)
        self.assertIn("if (!peer->peer_endpoint_set || !connection_id ||", self.authenticated_update)
        self.assertIn(
            "connection_id <= peer->tcp_roaming_connection_id",
            self.authenticated_update,
        )
        self.assertIn(
            "peer->tcp_roaming_connection_id = connection_id;",
            self.authenticated_update,
        )
        self.assertIn("target_changed = true;", self.authenticated_update)
        self.assertIn(
            "wg_tcp_peer_request_reconnect_after(peer,",
            self.authenticated_update,
        )
        self.assertIn("u64 tcp_roaming_connection_id;", self.peer_header)
        self.assertIn("new_temp_peer->peer_endpoint_set = false;", self.listener)
        self.assertNotRegex(
            self.listener,
            r"new_temp_peer->peer_endpoint.*incoming_port",
        )

    def test_tcp_dump_reports_dial_target_not_ephemeral_tuple(self) -> None:
        get_peer = section(
            self.netlink,
            "static int get_peer(",
            "static int wg_get_device_start(",
        )
        self.assertIn(
            "peer->device->transport == WG_TRANSPORT_TCP &&",
            get_peer,
        )
        self.assertIn("&peer->peer_endpoint.addr4", get_peer)
        self.assertIn("&peer->peer_endpoint.addr6", get_peer)

    def test_accepted_socket_tuple_uses_kernel_address_helpers(self) -> None:
        copy = section(
            self.socket,
            "static int copy_sock_addresses(struct socket *tcp_socket,",
            "static struct wg_peer *wg_find_peer_by_endpoints(",
        )

        self.assertIn("kernel_getsockname(tcp_socket", copy)
        self.assertIn("kernel_getpeername(tcp_socket", copy)
        self.assertIn("wg_sockaddr_length_valid", copy)
        self.assertNotIn("sk->sk_v6_daddr", copy)
        self.assertNotIn("sin6_scope_id =", copy)

    def test_connect_uses_one_locked_target_snapshot(self) -> None:
        self.assertIn("read_lock_bh(&peer->endpoint_lock);", self.connect)
        self.assertIn("target = peer->peer_endpoint;", self.connect)
        self.assertIn("read_unlock_bh(&peer->endpoint_lock);", self.connect)
        self.assertEqual(self.connect.count("peer->peer_endpoint"), 2)
        self.assertIn("addr6->sin6_scope_id = target.addr6.sin6_scope_id;", self.connect)
        self.assertIn("dest6->sin6_addr = socket->sk->sk_v6_daddr;", self.connect)
        self.assertNotIn("dest6->sin6_addr = peer->endpoint", self.connect)

    def test_authenticated_update_does_not_promote_raw_skb_socket(self) -> None:
        self.assertNotIn("peer->peer_socket = skb->sk->sk_socket", self.handshake)
        self.assertNotIn("peer->inbound_socket = skb->sk->sk_socket", self.handshake)

    def test_inbound_removal_claim_rejects_a_replacement_socket(self) -> None:
        state_change = section(
            self.socket,
            "void wg_tcp_state_change(struct sock *sk)",
            "void log_wireguard_endpoint(",
        )
        inbound_worker = section(
            self.socket,
            "void wg_tcp_inbound_remove_worker(struct work_struct *work)",
            "void wg_destruct_tcp_connection_list(",
        )

        self.assertIn(
            "struct socket *tcp_inbound_remove_socket;", self.peer_header
        )
        claim = state_change.index("peer->tcp_inbound_remove_scheduled = true;")
        capture = state_change.index(
            "peer->tcp_inbound_remove_socket =", claim
        )
        queue = state_change.index("&peer->tcp_inbound_remove_work, 0);", capture)
        self.assertLess(claim, capture)
        self.assertLess(capture, queue)
        recheck = state_change.index(
            "peer->tcp_inbound_remove_socket ==", capture
        )
        replacement = state_change.index("peer->inbound_socket", recheck)
        self.assertLess(capture, recheck)
        self.assertLess(recheck, replacement)
        self.assertLess(replacement, queue)

        snapshot = inbound_worker.index(
            "socket = peer->tcp_inbound_remove_socket;"
        )
        exact = inbound_worker.index(
            "peer->inbound_socket == socket", snapshot
        )
        detach = inbound_worker.index(
            "wg_reset_exact_tcp_socket_callbacks(peer, socket);", exact
        )
        guarded_detach = inbound_worker.rindex(
            "if (clean_claim && socket) {", exact, detach
        )
        self.assertLess(snapshot, exact)
        self.assertLess(exact, guarded_detach)
        self.assertLess(guarded_detach, detach)
        self.assertNotIn("socket = peer->inbound_socket;", inbound_worker)

    def test_simultaneous_handshake_decision_and_commit_share_lock(self) -> None:
        consume = section(
            self.noise,
            "wg_noise_handshake_consume_initiation(",
            "wg_noise_handshake_create_response(",
        )
        commit = section(
            consume,
            "/* Success! Copy everything to peer */",
            "memcpy(handshake->remote_ephemeral",
        )
        self.assertLess(
            commit.index("down_write(&handshake->lock);"),
            commit.index("handshake->state == HANDSHAKE_CREATED_INITIATION"),
        )
        self.assertIn("if (cmp < 0)", commit)
        self.assertIn("up_write(&handshake->lock);", commit)


if __name__ == "__main__":
    unittest.main()

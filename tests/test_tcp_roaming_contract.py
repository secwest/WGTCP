#!/usr/bin/env python3
"""Source-level guards for the deliberately disabled TCP promotion path."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end)]


class TcpRoamingContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        receive = source("kernel/receive.c")
        cls.handshake = section(
            receive,
            "static void wg_receive_handshake_packet(",
            "static void keep_key_fresh(",
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

    def test_tcp_activity_requires_an_owned_socket(self) -> None:
        response = section(
            self.handshake,
            "case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):",
            "default:",
        )
        self.assertIn(
            "skb->sk->sk_socket == peer->inbound_socket", response
        )
        self.assertIn(
            "skb->sk->sk_socket == peer->outbound_socket", response
        )
        self.assertNotIn("peer->peer_socket = skb->sk->sk_socket", response)

    def test_exact_pending_stream_is_marked_only_after_authentication(self) -> None:
        initiation = section(
            self.handshake,
            "case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):",
            "case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):",
        )
        response = section(
            self.handshake,
            "case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):",
            "default:",
        )
        marker = "wg_tcp_mark_pending_authenticated("
        self.assertEqual(self.handshake.count(marker), 2)
        self.assertLess(
            initiation.index("wg_noise_handshake_consume_initiation"),
            initiation.index(marker),
        )
        self.assertLess(
            response.index("wg_noise_handshake_consume_response"),
            response.index(marker),
        )


if __name__ == "__main__":
    unittest.main()

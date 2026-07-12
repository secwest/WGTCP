#!/usr/bin/env python3
"""Source-level guards for TCP stream framing and receive bounds."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end)]


class TcpStreamContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.socket = source("kernel/socket.c")

    def test_only_the_serial_write_worker_writes_tcp_stream_bytes(self) -> None:
        send_to_peer = section(
            self.socket,
            "int wg_socket_send_skb_to_peer(",
            "int wg_socket_send_buffer_to_peer(",
        )
        write_worker = section(
            self.socket,
            "void wg_tcp_write_worker(",
            "void wg_peer_discard_partial_read(",
        )

        self.assertEqual(self.socket.count("sent = kernel_sendmsg("), 1)
        self.assertNotIn("kernel_sendmsg(", send_to_peer)
        self.assertIn("wg_tcp_build_frame(skb)", send_to_peer)
        self.assertIn("wg_tcp_enqueue_frame(peer, frame)", send_to_peer)
        self.assertIn("wg_tcp_send_frame(socket, skb)", write_worker)

    def test_frames_include_fragment_bytes_before_they_are_queued(self) -> None:
        build = section(
            self.socket,
            "static struct sk_buff *wg_tcp_build_frame(",
            "static int wg_tcp_enqueue_frame(",
        )

        self.assertIn("encap_header.flags = WG_TCP_FRAG_FLAG;", build)
        self.assertIn("frag_header.id = PACKET_CB(payload)->frag_id;", build)
        self.assertIn("frag_header.frag_off = PACKET_CB(payload)->frag_off;", build)
        encap = "skb_put_data(frame, &encap_header, WG_TCP_ENCAP_HDR_LEN);"
        fragment = "skb_put_data(frame, &frag_header, WG_TCP_FRAG_HDR_LEN);"
        payload = "skb_copy_bits(payload, 0, skb_put(frame, payload->len),"
        self.assertLess(build.index(encap), build.index(fragment))
        self.assertLess(build.index(fragment), build.index(payload))

    def test_short_writes_resume_the_exact_unconsumed_suffix(self) -> None:
        worker = section(
            self.socket,
            "void wg_tcp_write_worker(",
            "void wg_peer_discard_partial_read(",
        )

        send = "sent = wg_tcp_send_frame(socket, skb);"
        advance = "skb_pull(skb, sent);"
        requeue = "__skb_queue_head(&peer->send_queue, skb);"
        self.assertLess(worker.index(send), worker.index(advance))
        self.assertLess(worker.index(advance), worker.index(requeue))
        self.assertNotIn("wg_tcp_build_frame", worker)
        self.assertNotIn("struct wg_tcp_encap_header", worker)

    def test_writer_claim_and_teardown_share_the_socket_lifetime_lock(self) -> None:
        schedule = section(
            self.socket,
            "static void wg_tcp_schedule_write(",
            "static int wg_tcp_enqueue_frame(",
        )
        enqueue = section(
            self.socket,
            "static int wg_tcp_enqueue_frame(",
            "int wg_socket_send_skb_to_peer(",
        )
        worker = section(
            self.socket,
            "void wg_tcp_write_worker(",
            "void wg_peer_discard_partial_read(",
        )

        claim_lock = "spin_lock_bh(&peer->tcp_lock);"
        queue = "queue_work(peer->tcp_write_wq, &peer->tcp_write_work);"
        self.assertLess(schedule.index(claim_lock), schedule.index(queue))
        self.assertLess(
            schedule.index(queue),
            schedule.index("spin_unlock_bh(&peer->tcp_lock);"),
        )
        self.assertIn("wg_tcp_schedule_write(peer);", enqueue)
        self.assertNotIn("peer->peer_socket->sk", enqueue)
        self.assertIn("struct socket *socket = NULL;", worker)
        self.assertIn("socket = peer->peer_socket;", worker)
        self.assertIn("peer->peer_socket == socket", worker)
        self.assertIn("wg_tcp_send_frame(socket, skb)", worker)

    def test_queue_pressure_drops_new_frames_not_the_stream_head(self) -> None:
        enqueue = section(
            self.socket,
            "static int wg_tcp_enqueue_frame(",
            "int wg_socket_send_skb_to_peer(",
        )

        self.assertIn("MAX_QUEUED_PACKETS", enqueue)
        self.assertIn("ret = -ENOBUFS;", enqueue)
        self.assertIn("__skb_queue_tail(&peer->send_queue, frame);", enqueue)
        self.assertNotIn("__skb_dequeue", enqueue)
        self.assertNotIn("__skb_queue_head", enqueue)

    def test_header_validation_requires_checksum_and_bounded_body(self) -> None:
        validity = section(
            self.socket,
            "bool wg_check_potential_header_validity(",
            "static int wg_tcp_build_fake_headers(",
        )

        self.assertIn("wg_validate_header_checksum(&candidate)", validity)
        self.assertIn("candidate.type != WG_TCP_RECORD_DATA", validity)
        self.assertIn("candidate.flags & ~WG_TCP_FRAG_FLAG", validity)
        self.assertIn(
            "WG_TCP_ENCAP_HDR_LEN + MESSAGE_MINIMUM_LENGTH", validity
        )
        self.assertIn("minimum_len += WG_TCP_FRAG_HDR_LEN;", validity)
        self.assertIn("total_len >= minimum_len", validity)
        self.assertIn("total_len <= WG_MAX_PACKET_SIZE", validity)

    def test_resynchronization_uses_the_full_header_validator(self) -> None:
        sync = section(
            self.socket,
            "bool wg_sync_header(struct wg_peer *peer)\n{",
            "bool wg_check_potential_header_validity(",
        )

        self.assertGreaterEqual(
            sync.count("wg_check_potential_header_validity("), 2
        )
        self.assertNotIn("wg_validate_header_checksum(potential_hdr)", sync)
        self.assertIn("WG_MAX_PACKET_SIZE +", sync)
        self.assertIn("WG_TCP_RESERVED_HEADER_SIZE + NET_IP_ALIGN", sync)

    def test_reader_rebinds_and_revalidates_after_resynchronization(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )
        resync = reader.index("if (!wg_sync_header(peer))")
        rebind = reader.index("memcpy(&header, peer->partial_skb->data", resync)
        revalidate = reader.index(
            "wg_check_potential_header_validity(", rebind
        )
        resize = reader.index("skb_copy_expand(peer->partial_skb", revalidate)

        self.assertLess(resync, rebind)
        self.assertLess(rebind, revalidate)
        self.assertLess(revalidate, resize)
        self.assertIn("needed = peer->expected_len - peer->received_len", reader)
        self.assertIn("skb_headroom(peer->partial_skb)", reader)


if __name__ == "__main__":
    unittest.main()

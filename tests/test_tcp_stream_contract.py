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
        schedule_locked = section(
            self.socket,
            "static void wg_tcp_schedule_write_locked(",
            "static void wg_tcp_schedule_write(",
        )
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
        self.assertIn("lockdep_assert_held(&peer->tcp_lock);", schedule_locked)
        self.assertIn(queue, schedule_locked)
        self.assertLess(
            schedule.index(claim_lock),
            schedule.index("wg_tcp_schedule_write_locked(peer);"),
        )
        self.assertLess(
            schedule.index("wg_tcp_schedule_write_locked(peer);"),
            schedule.index("spin_unlock_bh(&peer->tcp_lock);"),
        )
        enqueue_lock = enqueue.index(claim_lock)
        enqueue_tail = enqueue.index("__skb_queue_tail(&peer->send_queue, frame);")
        enqueue_schedule = enqueue.index("wg_tcp_schedule_write_locked(peer);")
        enqueue_unlock = enqueue.index("spin_unlock_bh(&peer->tcp_lock);")
        self.assertLess(enqueue_lock, enqueue_tail)
        self.assertLess(enqueue_tail, enqueue_schedule)
        self.assertLess(enqueue_schedule, enqueue_unlock)
        self.assertIn("peer->tcp_stopping", enqueue)
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
            "bool wg_sync_header(struct wg_peer *peer, struct socket *socket)\n{",
            "bool wg_check_potential_header_validity(",
        )

        self.assertGreaterEqual(
            sync.count("wg_check_potential_header_validity("), 2
        )
        self.assertNotIn("wg_validate_header_checksum(potential_hdr)", sync)
        self.assertIn("WG_MAX_PACKET_SIZE +", sync)
        self.assertIn("WG_TCP_RESERVED_HEADER_SIZE + NET_IP_ALIGN", sync)
        self.assertIn("skb_put(read_skb, read_bytes);", sync)
        self.assertNotIn("skb_trim(read_skb, read_bytes)", sync)
        self.assertIn("WG_TCP_ENCAP_HDR_LEN - 1", sync)
        self.assertIn("peer->received_len = keep;", sync)
        self.assertIn("kernel_recvmsg(socket,", sync)

    def test_reader_rebinds_and_revalidates_after_resynchronization(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )
        resync = reader.index("if (!wg_sync_header(peer, socket))")
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

    def test_reader_drains_buffered_records_before_receiving_more(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )

        ready = reader.index("record_ready = peer->expected_len ?")
        receive_guard = reader.index("if (!record_ready)", ready)
        receive = reader.index("kernel_recvmsg(", receive_guard)
        self.assertLess(ready, receive_guard)
        self.assertLess(receive_guard, receive)
        self.assertIn("if (++packets_processed >= 64)", reader)
        self.assertIn("budget_exhausted = true;", reader)
        self.assertIn(
            "budget_exhausted && peer->partial_skb", reader
        )
        self.assertIn(
            "peer->received_len >= WG_TCP_ENCAP_HDR_LEN", reader
        )

    def test_reader_pins_one_socket_through_parse_and_delivery(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )

        claim = reader.index("spin_lock_bh(&peer->tcp_lock);")
        pin = reader.index("socket = peer->peer_socket;", claim)
        unlock = reader.index("spin_unlock_bh(&peer->tcp_lock);", pin)
        receive = reader.index("kernel_recvmsg(socket,", unlock)
        resync = reader.index("wg_sync_header(peer, socket)", receive)
        synthesize = reader.index(
            "wg_tcp_build_fake_headers(peer->partial_skb, peer,", resync
        )
        deliver = reader.index("wg_receive(sk, peer->partial_skb)", synthesize)

        self.assertLess(claim, pin)
        self.assertLess(pin, unlock)
        self.assertLess(unlock, receive)
        self.assertLess(receive, resync)
        self.assertLess(resync, synthesize)
        self.assertLess(synthesize, deliver)
        self.assertIn("peer->peer_socket == socket", reader)

    def test_coalesced_leftover_buffer_is_right_sized(self) -> None:
        reader = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )

        allocation = section(
            reader,
            "leftover_skb = alloc_skb(",
            "if (!leftover_skb)",
        )
        self.assertIn("leftover_len +", allocation)
        self.assertIn("WG_TCP_RESERVED_HEADER_SIZE +", allocation)
        self.assertNotIn("WG_TCP_SKB_READ_ALLOC_SIZE", allocation)

    def test_outbound_headers_use_the_connected_socket_tuple(self) -> None:
        headers = section(
            self.socket,
            "static int wg_tcp_build_fake_headers(",
            "void wg_tcp_read_worker(",
        )

        self.assertIn("struct socket *socket", headers)
        self.assertIn("outbound_source.sin_port = inet->inet_sport;", headers)
        self.assertIn("outbound_dest.sin_port = inet->inet_dport;", headers)
        self.assertIn("outbound_dest6.sin6_addr = sk->sk_v6_daddr;", headers)
        self.assertNotIn("peer->outbound_source", headers)
        self.assertNotIn("peer->outbound_dest", headers)

    def test_outbound_tuple_is_cached_after_connect_selects_it(self) -> None:
        connect = section(
            self.socket,
            "int wg_tcp_connect(struct wg_peer *peer)",
            "static void __maybe_unused wg_release_peer_tcp_connection(",
        )

        call = connect.index("ret = kernel_connect(socket, addr,")
        accepted = connect.index("if (ret != -EINPROGRESS && ret != 0)", call)
        cache = connect.index("memset(&peer->outbound_source", accepted)
        self.assertLess(call, accepted)
        self.assertLess(accepted, cache)
        self.assertIn("source->sin_port = inet->inet_sport;", connect[cache:])
        self.assertIn("dest->sin_port = inet->inet_dport;", connect[cache:])


if __name__ == "__main__":
    unittest.main()

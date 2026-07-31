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
        cls.socket = source("kernel/wg_tcp.c")
        cls.peer = source("kernel/peer.c")
        cls.peer_header = source("kernel/peer.h")
        cls.device = source("kernel/device.c")
        cls.device_header = source("kernel/device.h")

    def test_pending_connections_have_a_locked_hard_cap(self) -> None:
        add = final_section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_touch_tcp_connection(",
        )

        self.assertIn("#define WG_TCP_MAX_PENDING_CONNECTIONS 128", self.socket)
        self.assertIn("#define WG_TCP_MAX_TRACKED_CONNECTIONS 1024", self.socket)
        self.assertIn("unsigned int tcp_pending_connections;", self.device_header)
        self.assertIn("unsigned int tcp_tracked_connections;", self.device_header)
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

    def test_unauthenticated_accepts_have_source_and_rate_limits(self) -> None:
        listener = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )
        add = final_section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_touch_tcp_connection(",
        )

        self.assertIn("#define WG_TCP_MAX_PENDING_PER_SOURCE 8", self.socket)
        self.assertIn("#define WG_TCP_ACCEPT_BURST 32", self.socket)
        self.assertIn("struct wg_tcp_accept_source", self.device_header)
        rate = listener.index("wg_tcp_accept_rate_allow(wg, &new_endpoint.addr)")
        capacity = listener.index("wg_tcp_source_at_capacity(wg, &new_endpoint.addr)")
        allocate = listener.index("new_temp_peer = wg_temp_peer_create(wg);")
        self.assertLess(rate, allocate)
        self.assertLess(capacity, allocate)
        self.assertIn("wg_tcp_pending_from_source_locked(", add)
        self.assertIn("WG_TCP_MAX_PENDING_PER_SOURCE", add)

    def test_authenticated_streams_outlive_pre_auth_deadline(self) -> None:
        mark = section(
            self.socket,
            "static void wg_tcp_mark_connection_authenticated(",
            "void wg_free_peer_socket_data(",
        )
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,",
            "static bool wg_tcp_promote_authenticated_carrier(",
        )

        self.assertIn("entry->authenticated = true;", mark)
        self.assertIn("entry->authenticated ||", claim)
        self.assertIn("WG_TCP_AUTH_MAX_LIFETIME_MS", claim)
        self.assertIn("wg_tcp_release_admission_locked(wg, entry);", mark)

    def test_authenticated_promotion_preserves_the_accepted_tuple(self) -> None:
        promotion = final_section(
            self.socket,
            "static bool wg_tcp_promote_authenticated_carrier(struct wg_peer *peer,",
            "static void wg_destroy_temp_peer(",
        )
        source = "peer->inbound_source = temp->inbound_source;"
        dest = "peer->inbound_dest = temp->inbound_dest;"
        publish = "peer->peer_socket = socket;"
        self.assertIn(source, promotion)
        self.assertIn(dest, promotion)
        self.assertLess(promotion.index(source), promotion.index(publish))
        self.assertLess(promotion.index(dest), promotion.index(publish))

    def test_stale_authenticated_candidate_is_not_a_kernel_warning(self) -> None:
        promotion = final_section(
            self.socket,
            "static bool wg_tcp_promote_authenticated_carrier(struct wg_peer *peer,",
            "static void wg_destroy_temp_peer(",
        )
        self.assertIn("if (ret != -ESTALE && ret != -ESHUTDOWN)", promotion)
        self.assertLess(
            promotion.index("if (ret != -ESTALE && ret != -ESHUTDOWN)"),
            promotion.index("WARN_ON_ONCE(ret)"),
        )

    def test_authenticated_promotion_is_deferred_with_no_lost_wakeup(self) -> None:
        update = section(
            self.socket,
            "void wg_socket_set_peer_endpoint_authenticated(struct wg_peer *peer,",
            "void wg_socket_set_peer_endpoint_authenticated_from_skb(",
        )
        worker = section(
            self.socket,
            "void wg_tcp_promotion_worker(struct work_struct *work)",
            "static void wg_destroy_temp_peer(",
        )
        stop = section(
            self.socket,
            "void wg_tcp_peer_stop(struct wg_peer *peer)",
            "struct wg_peer *wg_temp_peer_create(",
        )

        self.assertIn("bool tcp_promotion_worker_scheduled;", self.peer_header)
        self.assertIn("wg_tcp_mark_connection_authenticated(", update)
        self.assertIn("if (!peer->tcp_promotion_worker_scheduled)", update)
        self.assertIn("peer->tcp_promotion_worker_scheduled = true;", update)
        self.assertIn("queue_work(system_wq, &peer->tcp_promotion_work);", update)
        self.assertNotIn("wg_tcp_promote_authenticated_carrier(", update)
        self.assertIn("peer->tcp_promotion_worker_scheduled = false;", worker)
        self.assertIn(
            "wg_tcp_promote_authenticated_carrier(peer, connection_id);", worker
        )
        self.assertIn("cancel_work_sync(&peer->tcp_promotion_work);", stop)

    def test_authenticated_streams_release_pre_auth_capacity_once(self) -> None:
        pending_from_source = section(
            self.socket,
            "wg_tcp_pending_from_source_locked(struct wg_device *wg,",
            "static bool wg_tcp_source_at_capacity(",
        )
        mark = section(
            self.socket,
            "static void wg_tcp_mark_connection_authenticated(",
            "void wg_free_peer_socket_data(",
        )
        release = section(
            self.socket,
            "wg_tcp_release_admission_locked(struct wg_device *wg,",
            "static void wg_tcp_mark_connection_authenticated(",
        )
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,",
            "static void wg_destroy_temp_peer(",
        )
        destroy = final_section(
            self.socket,
            "wg_destroy_tcp_connection_entry(struct wg_device *wg,",
            "void wg_remove_from_tcp_connection_list(",
        )

        self.assertIn("entry->admission_counted &&", pending_from_source)
        self.assertIn("lockdep_assert_held", release)
        self.assertIn("if (!entry->admission_counted)", release)
        self.assertIn("entry->admission_counted = false;", release)
        self.assertEqual(release.count("--wg->tcp_pending_connections;"), 1)
        self.assertIn("entry->connection_id != connection_id", mark)
        self.assertIn("wg_tcp_release_admission_locked(wg, entry);", mark)
        self.assertIn("wg_tcp_release_admission_locked(wg, entry);", claim)
        self.assertIn("--wg->tcp_tracked_connections;", claim)
        self.assertNotIn("tcp_pending_connections", destroy)
        self.assertNotIn("tcp_tracked_connections", destroy)

    def test_real_peers_initialize_both_scheduler_locks(self) -> None:
        create = section(
            self.peer,
            "struct wg_peer *wg_peer_create(struct wg_device *wg,",
            "struct wg_peer *wg_peer_get_maybe_zero(",
        )

        self.assertIn("spin_lock_init(&peer->tcp_read_lock);", create)
        self.assertIn("spin_lock_init(&peer->tcp_write_lock);", create)
        self.assertLess(
            create.index("spin_lock_init(&peer->tcp_read_lock);"),
            create.index("INIT_WORK(&peer->tcp_read_work"),
        )
        self.assertLess(
            create.index("spin_lock_init(&peer->tcp_write_lock);"),
            create.index("INIT_WORK(&peer->tcp_write_work"),
        )

    def test_listener_handoff_blocks_provisional_cleanup(self) -> None:
        listener = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )
        add = final_section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_finish_tcp_connection_init(",
        )
        finish = final_section(
            self.socket,
            "static void wg_finish_tcp_connection_init(struct wg_device *wg,",
            "static void wg_touch_tcp_connection(",
        )
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,",
            "static void wg_destroy_temp_peer(",
        )

        publish = add.index("list_add_tail_rcu(&entry->tcp_connection_ll")
        self.assertLess(add.index("entry->initializing = true;"), publish)
        callbacks = listener.index("err = wg_setup_tcp_socket_callbacks(")
        handoff = listener.index("wg_finish_tcp_connection_init(wg,", callbacks)
        self.assertLess(callbacks, handoff)
        self.assertIn("entry->initializing = false;", finish)
        self.assertIn("socket->sk->sk_state) != TCP_ESTABLISHED", finish)
        self.assertIn("READ_ONCE(entry->temp_peer->is_dead)", finish)
        self.assertIn(
            "mod_delayed_work(system_wq, &wg->tcp_cleanup_work, 0);", finish
        )
        self.assertIn("if (cleanup_only && entry->initializing)", claim)

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
            "static bool wg_tcp_promote_authenticated_carrier(",
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
            "static bool wg_tcp_promote_authenticated_carrier(",
        )
        destroy = final_section(
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
        self.assertIn("wg_tcp_release_admission_locked(wg, entry);", claim)
        self.assertNotIn("tcp_pending_connections", destroy)

    def test_connect_errors_use_one_complete_unwind(self) -> None:
        unwind = section(
            self.socket,
            "static void wg_tcp_connect_unwind(",
            "int wg_tcp_connect(struct wg_peer *peer)",
        )
        connect = section(
            self.socket,
            "int wg_tcp_connect(struct wg_peer *peer)\n{",
            "static void __maybe_unused wg_release_peer_tcp_connection(",
        )

        self.assertIn("struct socket *socket = NULL;", connect)
        self.assertIn("&socket);", connect)
        self.assertNotIn("&peer->peer_socket);", connect)
        self.assertGreaterEqual(connect.count("goto fail;"), 5)
        self.assertEqual(connect.count("wg_tcp_connect_unwind(peer, socket);"), 1)
        self.assertNotIn("sock_release(", connect)

        detach = "wg_reset_exact_tcp_socket_callbacks(peer, socket);"
        release_owned = "wg_release_peer_socket_locked(peer, socket);"
        release_unowned = "sock_release(socket);"
        for operation in (detach, release_owned, release_unowned):
            self.assertIn(operation, unwind)
        self.assertLess(unwind.index(detach), unwind.index(release_owned))
        self.assertLess(unwind.index(release_owned), unwind.index(release_unowned))
        for state in (
            "peer->tcp_connecting = false;",
            "peer->tcp_pending = false;",
            "peer->tcp_established = false;",
            "peer->outbound_connected = false;",
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
        reset = stop.index(
            "wg_reset_exact_tcp_socket_callbacks(peer, outbound);"
        )
        release = stop.index(
            "wg_release_peer_socket_locked(peer, outbound);"
        )
        self.assertLess(stop.index("cancel_work_sync(&peer->tcp_write_work);"), reset)
        self.assertLess(reset, release)

    def test_peer_stop_drains_removal_owners_before_socket_snapshot(self) -> None:
        stop = section(
            self.socket,
            "void wg_tcp_peer_stop(struct wg_peer *peer)",
            "struct wg_peer *wg_temp_peer_create(",
        )

        barrier = stop.index("peer->tcp_stopping = true;")
        snapshot = stop.index("outbound = peer->outbound_socket;")
        for cancellation in (
            "cancel_delayed_work_sync(&peer->tcp_retry_work);",
            "cancel_delayed_work_sync(&peer->tcp_outbound_remove_work);",
            "cancel_delayed_work_sync(&peer->tcp_inbound_remove_work);",
        ):
            index = stop.index(cancellation)
            self.assertLess(barrier, index)
            self.assertLess(index, snapshot)
        reassert = stop.index(
            "peer->tcp_outbound_remove_scheduled = true;", barrier + 1
        )
        self.assertLess(reassert, snapshot)
        self.assertLess(snapshot, stop.index("outbound_sk = outbound ?"))
        self.assertIn("__skb_queue_purge(&peer->send_queue);", stop)
        final_state = stop[stop.rindex("spin_lock_bh(&peer->tcp_lock);") :]
        self.assertIn("peer->tcp_connecting = false;", final_state)
        self.assertIn("peer->tcp_reconnect_requested = false;", final_state)

    def test_late_retry_and_remove_queues_recheck_the_stop_barrier(self) -> None:
        send = section(
            self.socket,
            "int wg_socket_send_skb_to_peer(",
            "static bool wg_tcp_dial_target_eq(",
        )
        state_change = section(
            self.socket,
            "void wg_tcp_state_change(struct sock *sk)",
            "void log_wireguard_endpoint(",
        )

        retry_queue = send.index(
            "mod_delayed_work(system_wq, &peer->tcp_retry_work, 0);"
        )
        retry_lock = send.rindex(
            "spin_lock_bh(&peer->tcp_lock);", 0, retry_queue
        )
        retry_unlock = send.index(
            "spin_unlock_bh(&peer->tcp_lock);", retry_queue
        )
        self.assertLess(retry_lock, retry_queue)
        self.assertLess(retry_queue, retry_unlock)
        self.assertIn("!peer->tcp_stopping", send[retry_lock:retry_queue])

        for queue in (
            "&peer->tcp_inbound_remove_work, 0);",
            "&peer->tcp_outbound_remove_work, 0);",
        ):
            queue_index = state_change.index(queue)
            lock_index = state_change.rindex(
                "spin_lock_bh(&peer->tcp_lock);", 0, queue_index
            )
            unlock_index = state_change.index(
                "spin_unlock_bh(&peer->tcp_lock);", queue_index
            )
            self.assertLess(lock_index, queue_index)
            self.assertLess(queue_index, unlock_index)
            self.assertIn(
                "!peer->tcp_stopping", state_change[lock_index:queue_index]
            )

    def test_connect_rechecks_stop_before_socket_and_work_publication(self) -> None:
        connect = section(
            self.socket,
            "int wg_tcp_connect(struct wg_peer *peer)\n{",
            "static void __maybe_unused wg_release_peer_tcp_connection(",
        )

        self.assertGreaterEqual(
            connect.count("!READ_ONCE(peer->device->tcp_cleanup_scheduled)"), 3
        )
        self.assertNotIn("wg_tcp_listener_socket_init(", connect)
        publication = connect.index("peer->peer_socket = socket;")
        publication_lock = connect.rindex(
            "spin_lock_bh(&peer->tcp_lock);", 0, publication
        )
        self.assertIn(
            "peer->tcp_stopping", connect[publication_lock:publication]
        )
        retry_queue = connect.index(
            "mod_delayed_work(system_wq, &peer->tcp_retry_work,"
        )
        retry_unlock = connect.index(
            "spin_unlock_bh(&peer->tcp_lock);", retry_queue
        )
        self.assertLess(retry_queue, retry_unlock)

    def test_device_teardown_stops_peers_before_shared_listeners(self) -> None:
        stop = section(
            self.device,
            "static int wg_stop(struct net_device *dev)",
            "static netdev_tx_t wg_xmit(",
        )
        destruct = section(
            self.device,
            "static void wg_destruct(struct net_device *dev)",
            "static const struct device_type device_type",
        )
        cancel = "cancel_delayed_work_sync(&wg->tcp_cleanup_work);"
        provisional = "wg_destruct_tcp_connection_list(wg);"

        for teardown in (stop, destruct):
            self.assertLess(
                teardown.index("wg_tcp_peer_stop(peer);"),
                teardown.index("wg_tcp_listener_socket_release(wg);"),
            )
            self.assertGreaterEqual(teardown.count(cancel), 2)
            self.assertLess(teardown.index(cancel), teardown.index(provisional))
            self.assertLess(teardown.index(provisional), teardown.rindex(cancel))

    def test_retry_timeout_delegates_socket_release_to_removal_owner(self) -> None:
        retry = section(
            self.socket,
            "void wg_tcp_retry_worker(struct work_struct *work)",
            "int wg_add_tcp_socket_to_list(",
        )

        self.assertIn("peer->tcp_outbound_remove_scheduled = true;", retry)
        self.assertIn(
            "peer->tcp_outbound_remove_socket = peer->outbound_socket;", retry
        )
        self.assertIn("peer->tcp_reconnect_requested = true;", retry)
        self.assertIn(
            "mod_delayed_work(system_wq, &peer->tcp_outbound_remove_work, 0);",
            retry,
        )
        self.assertNotIn("sock_release(", retry)
        self.assertNotIn("wg_reset_tcp_socket_callbacks(", retry)

    def test_reconnect_owner_is_stopped_and_bound_to_one_socket(self) -> None:
        request = section(
            self.socket,
            "static void wg_tcp_peer_request_reconnect_after(",
            "static void wg_socket_set_peer_endpoint_internal(",
        )
        unwind = section(
            self.socket,
            "static void wg_tcp_connect_unwind(",
            "int wg_tcp_connect(struct wg_peer *peer)",
        )
        worker = section(
            self.socket,
            "void wg_tcp_outbound_remove_worker(struct work_struct *work)",
            "void wg_tcp_inbound_remove_worker(struct work_struct *work)",
        )
        stop = section(
            self.socket,
            "void wg_tcp_peer_stop(struct wg_peer *peer)",
            "struct wg_peer *wg_temp_peer_create(",
        )

        self.assertIn("bool tcp_stopping;", self.peer_header)
        self.assertIn("struct socket *tcp_outbound_remove_socket;", self.peer_header)
        self.assertIn("peer->tcp_stopping = true;", stop)
        self.assertIn("peer->tcp_stopping", request)
        self.assertNotIn("kernel_sock_shutdown(", request)
        self.assertIn("peer->tcp_outbound_remove_socket = socket;", unwind)
        self.assertIn("peer->tcp_reconnect_requested && !peer->tcp_stopping", unwind)
        self.assertNotIn("peer->tcp_reconnect_requested = false;", unwind)
        self.assertIn("socket = peer->tcp_outbound_remove_socket;", worker)
        self.assertIn("peer->outbound_socket == socket", worker)

    def test_removal_workers_publish_their_own_completion(self) -> None:
        cleanup = section(
            self.socket,
            "void wg_clean_peer_socket(struct wg_peer *peer, bool release, bool destroy, bool inbound)",
            "void wg_tcp_peer_stop(struct wg_peer *peer)",
        )
        state_change = section(
            self.socket,
            "void wg_tcp_state_change(struct sock *sk)",
            "void log_wireguard_endpoint(",
        )
        outbound = section(
            self.socket,
            "void wg_tcp_outbound_remove_worker(struct work_struct *work)",
            "void wg_tcp_inbound_remove_worker(struct work_struct *work)",
        )
        inbound = section(
            self.socket,
            "void wg_tcp_inbound_remove_worker(struct work_struct *work)",
            "void wg_destruct_tcp_connection_list(struct wg_device *wg)",
        )

        self.assertNotIn("tcp_outbound_remove_scheduled", cleanup)
        self.assertNotIn("tcp_inbound_remove_scheduled", cleanup)
        self.assertNotIn("cancel_delayed_work(remove_work)", cleanup)
        established = section(
            state_change,
            "case TCP_ESTABLISHED:",
            "case TCP_CLOSE:",
        )
        self.assertNotIn("tcp_outbound_remove_scheduled = false", established)

        for worker, direction in (
            (outbound, "outbound"),
            (inbound, "inbound"),
        ):
            clean = "wg_reset_exact_tcp_socket_callbacks(peer, socket);"
            lock = "spin_lock_bh(&peer->tcp_lock);"
            publish = f"peer->tcp_{direction}_remove_scheduled = false;"
            clean_index = worker.index(clean)
            completion_lock = worker.index(lock, clean_index)
            self.assertLess(clean_index, completion_lock)
            self.assertLess(completion_lock, worker.index(publish))
            publish_index = worker.index(publish)
            self.assertLess(
                publish_index,
                worker.index("spin_unlock_bh(&peer->tcp_lock);", publish_index),
            )


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Source-level guards for the TCP listener lifecycle contract."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    return text[start_index : text.index(end, start_index + len(start))]


class TcpListenerContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.socket = source("kernel/wg_tcp.c")
        cls.header = source("kernel/wg_tcp.h")
        cls.device = source("kernel/device.c")
        cls.netlink = source("kernel/netlink.c")
        cls.peer = source("kernel/peer.c")

    def test_each_family_has_an_independent_accept_worker(self) -> None:
        worker = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )
        listener_init = section(
            self.socket,
            "int wg_tcp_listener_socket_init(",
            "static void wg_tcp_connect_unwind(",
        )

        self.assertNotIn("listener_active", worker)
        self.assertNotIn("dev_v4", listener_init)
        self.assertNotIn("dev_v6", listener_init)
        self.assertIn("if (wg->tcp_listen_socket4)", listener_init)
        self.assertIn("if (wg->tcp_listen_socket6)", listener_init)

    def test_listener_shutdown_precedes_thread_stop(self) -> None:
        release = section(
            self.socket,
            "void wg_tcp_listener_socket_release(",
            "int wg_setup_tcp_listen4(",
        )

        for family in ("4", "6"):
            shutdown = (
                f"kernel_sock_shutdown(wg->tcp_listen_socket{family}, SHUT_RDWR)"
            )
            stop = f"kthread_stop(wg->tcp_listener{family}_thread)"
            self.assertIn(shutdown, release)
            self.assertIn(stop, release)
            self.assertLess(release.index(shutdown), release.index(stop))

    def test_setup_returns_errno_and_ipv6_is_v6_only(self) -> None:
        listen4 = section(
            self.socket,
            "int wg_setup_tcp_listen4(",
            "int wg_setup_tcp_listen6(",
        )
        listen6 = section(
            self.socket,
            "int wg_setup_tcp_listen6(",
            "int wg_tcp_listener_socket_init(",
        )

        self.assertIn("struct socket **listen_socket", self.header)
        for setup in (listen4, listen6):
            self.assertIn("*listen_socket = NULL", setup)
            self.assertIn("return ret;", setup)
            self.assertIn("sock_release(socket);", setup)
        self.assertLess(
            listen6.index("ip6_sock_set_v6only(socket->sk)"),
            listen6.index("kernel_bind(socket"),
        )

    def test_thread_errors_roll_back_published_listeners(self) -> None:
        listener_init = section(
            self.socket,
            "int wg_tcp_listener_socket_init(",
            "static void wg_tcp_connect_unwind(",
        )

        self.assertEqual(listener_init.count("PTR_ERR("), 2)
        self.assertEqual(listener_init.count("goto error_listeners;"), 2)
        self.assertIn("error_listeners:", listener_init)
        self.assertIn("wg_tcp_listener_socket_release(wg);", listener_init)
        self.assertIn("error_sockets:", listener_init)
        self.assertIn("return ret;", listener_init)

    def test_tcp_connect_waits_for_a_configured_endpoint(self) -> None:
        create = section(
            self.peer,
            "struct wg_peer *wg_peer_create(",
            "struct wg_peer *wg_peer_get_maybe_zero(",
        )
        endpoint_update = section(
            self.socket,
            "static void wg_socket_set_peer_endpoint_internal(",
            "void wg_socket_set_peer_endpoint(",
        )
        learned_update = section(
            self.socket,
            "void wg_socket_set_peer_endpoint(",
            "void wg_socket_set_peer_endpoint_configured(",
        )
        configured_update = section(
            self.socket,
            "void wg_socket_set_peer_endpoint_configured(",
            "void wg_socket_set_peer_endpoint_from_skb(",
        )

        self.assertNotIn("wg_tcp_connect(peer);", create)
        self.assertIn(
            "wg_socket_set_peer_endpoint_internal(peer, endpoint, false);",
            learned_update,
        )
        self.assertIn(
            "wg_socket_set_peer_endpoint_internal(peer, endpoint, true);",
            configured_update,
        )
        self.assertIn("wg_socket_set_peer_endpoint_configured", self.header)
        self.assertEqual(
            self.netlink.count("wg_socket_set_peer_endpoint_configured(peer, &endpoint);"),
            2,
        )
        self.assertLess(
            endpoint_update.index("peer->peer_endpoint = peer->endpoint;"),
            endpoint_update.index("wg_tcp_connect(peer);"),
        )

    def test_configured_endpoint_change_uses_close_retry_lifecycle(self) -> None:
        endpoint_update = section(
            self.socket,
            "static void wg_socket_set_peer_endpoint_internal(",
            "void wg_socket_set_peer_endpoint(",
        )
        reconnect = section(
            self.socket,
            "static void wg_tcp_peer_request_reconnect_after(",
            "static void wg_socket_set_peer_endpoint_internal(",
        )
        remove_worker = section(
            self.socket,
            "void wg_tcp_outbound_remove_worker(",
            "void wg_tcp_inbound_remove_worker(",
        )

        self.assertIn("tcp_target_changed = peer->peer_endpoint_set", endpoint_update)
        self.assertIn("wg_tcp_peer_request_reconnect(peer);", endpoint_update)
        self.assertNotIn("kernel_sock_shutdown(", reconnect)
        self.assertIn("peer->tcp_reconnect_requested = true;", reconnect)
        self.assertIn(
            "peer->tcp_outbound_remove_socket = peer->outbound_socket;",
            reconnect,
        )
        queue = reconnect.index("mod_delayed_work(")
        self.assertLess(queue, reconnect.index("spin_unlock_bh(&peer->tcp_lock);", queue))
        self.assertIn("peer->tcp_reconnect_requested = false;", remove_worker)
        self.assertLess(
            remove_worker.index("wg_clean_peer_socket(peer, true, false, false);"),
            remove_worker.index("ret = wg_tcp_connect(peer);"),
        )
        self.assertIn(
            "!READ_ONCE(peer->device->tcp_cleanup_scheduled)", remove_worker
        )
        self.assertNotIn("sock_release(outbound_socket)", endpoint_update)
        self.assertNotIn("kfree(outbound_socket", endpoint_update)

    def test_tcp_receive_resolves_the_device_wrapper(self) -> None:
        receive = section(
            self.socket,
            "static int wg_receive(",
            "static int wg_set_socket_timeouts(",
        )

        self.assertIn("sk->sk_protocol == IPPROTO_TCP", receive)
        self.assertIn("struct wg_socket_data *socket_data", receive)
        self.assertIn("wg = socket_data->device;", receive)
        self.assertNotIn("skb->sk = sk", receive)

    def test_listeners_and_accepted_streams_keep_the_device_mark(self) -> None:
        listener = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )
        setup = section(
            self.socket,
            "int wg_setup_tcp_listen4(",
            "int wg_tcp_listener_socket_init(",
        )
        refresh = section(
            self.socket,
            "void wg_tcp_set_device_mark(",
            "void wg_free_peer_socket_data(",
        )
        fwmark = section(
            self.netlink,
            "if (info->attrs[WGDEVICE_A_FWMARK]) {",
            "if (info->attrs[WGDEVICE_A_LISTEN_PORT]) {",
        )
        add = section(
            self.socket,
            "int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,",
            "static void wg_touch_tcp_connection(",
        )

        self.assertIn(
            "WRITE_ONCE(new_peer_connection->sk->sk_mark, wg->fwmark);",
            listener,
        )
        self.assertEqual(
            setup.count("WRITE_ONCE(socket->sk->sk_mark, wg->fwmark);"), 2
        )
        self.assertIn("wg->tcp_listen_socket4->sk->sk_mark", refresh)
        self.assertIn("wg->tcp_listen_socket6->sk->sk_mark", refresh)
        self.assertIn("entry->tcp_socket->sk->sk_mark", refresh)
        self.assertIn("wg_tcp_set_device_mark(wg, fwmark);", fwmark)
        list_lock = "spin_lock_bh(&wg->tcp_connection_list_lock);"
        publish_mark = "WRITE_ONCE(receive_socket->sk->sk_mark, wg->fwmark);"
        publish = "list_add_tail_rcu(&entry->tcp_connection_ll"
        self.assertLess(add.index(list_lock), add.index(publish_mark))
        self.assertLess(add.index(publish_mark), add.index(publish))
        self.assertLess(
            add.index(publish),
            add.index("spin_unlock_bh(&wg->tcp_connection_list_lock);", add.index(publish)),
        )

    def test_tcp_read_worker_closes_the_lost_wakeup_window(self) -> None:
        read_worker = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )

        clear = "peer->tcp_read_worker_scheduled = false;"
        pending = "!skb_queue_empty(&socket->sk->sk_receive_queue)"
        requeue = "queue_work(peer->tcp_read_wq, &peer->tcp_read_work);"
        self.assertIn(clear, read_worker)
        self.assertIn(pending, read_worker)
        self.assertIn(requeue, read_worker)
        self.assertLess(read_worker.rindex(clear), read_worker.index(pending))
        self.assertLess(read_worker.index(pending), read_worker.index(requeue))

    def test_tcp_read_scheduling_is_serialized_with_socket_removal(self) -> None:
        read_worker = section(
            self.socket,
            "void wg_tcp_read_worker(",
            "void wg_tcp_data_ready(",
        )
        read_worker_exit = read_worker[read_worker.rindex("out:") :]
        data_ready = section(
            self.socket,
            "void wg_tcp_data_ready(",
            "void wg_tcp_write_space(",
        )

        for scheduler in (read_worker_exit, data_ready):
            lifetime_lock = "spin_lock_bh(&peer->tcp_lock);"
            scheduler_lock = "spin_lock(&peer->tcp_read_lock);"
            stopping_guard = "!peer->tcp_stopping"
            cleanup_guard = "READ_ONCE(peer->device->tcp_cleanup_scheduled)"
            outbound_guard = "!peer->tcp_outbound_remove_scheduled"
            inbound_guard = "!peer->tcp_inbound_remove_scheduled"
            queue = "queue_work(peer->tcp_read_wq, &peer->tcp_read_work);"
            scheduler_unlock = "spin_unlock(&peer->tcp_read_lock);"
            lifetime_unlock = "spin_unlock_bh(&peer->tcp_lock);"

            for operation in (
                lifetime_lock,
                scheduler_lock,
                stopping_guard,
                cleanup_guard,
                outbound_guard,
                inbound_guard,
                queue,
                scheduler_unlock,
                lifetime_unlock,
            ):
                self.assertIn(operation, scheduler)
            self.assertLess(scheduler.index(lifetime_lock), scheduler.index(scheduler_lock))
            self.assertLess(scheduler.index(scheduler_lock), scheduler.index(stopping_guard))
            self.assertLess(scheduler.index(stopping_guard), scheduler.index(cleanup_guard))
            self.assertLess(scheduler.index(cleanup_guard), scheduler.index(outbound_guard))
            self.assertLess(scheduler.index(outbound_guard), scheduler.index(inbound_guard))
            self.assertLess(scheduler.index(inbound_guard), scheduler.index(queue))
            self.assertLess(scheduler.index(queue), scheduler.index(scheduler_unlock))
            self.assertLess(scheduler.index(scheduler_unlock), scheduler.index(lifetime_unlock))

    def test_disconnected_tcp_send_queues_on_demand_retry(self) -> None:
        send = section(
            self.socket,
            "int wg_socket_send_skb_to_peer(",
            "static bool wg_tcp_dial_target_eq(",
        )

        self.assertIn("ret = -ENOTCONN;", send)
        self.assertIn("peer->tcp_retry_scheduled = true;", send)
        self.assertIn("mod_delayed_work(system_wq, &peer->tcp_retry_work, 0);", send)
        self.assertIn("peer->tcp_outbound_remove_scheduled", send)

    def test_temp_peer_owns_only_tcp_stream_resources(self) -> None:
        marker = "struct wg_peer *wg_temp_peer_create(struct wg_device *wg)\n{"
        temp_create = self.socket[self.socket.rindex(marker) :]

        for unused_generic_resource in (
            "dst_cache_init(",
            "wg_timers_init(",
            "wg_prev_queue_init(",
            "kref_init(",
            "staged_packet_queue",
            "netif_napi_add(",
            "napi_enable(",
        ):
            self.assertNotIn(unused_generic_resource, temp_create)
        self.assertIn("skb_queue_head_init(&peer->send_queue);", temp_create)
        self.assertIn("peer->tcp_read_wq = wg->tcp_auth_wq;", temp_create)
        self.assertIn("peer->tcp_write_wq = wg->tcp_auth_wq;", temp_create)
        self.assertNotIn("alloc_workqueue", temp_create)

    def test_temp_destroy_quiesces_workers_before_socket_wrapper(self) -> None:
        destroy = section(
            self.socket,
            "static void wg_destroy_temp_peer(struct wg_peer *peer)\n{",
            "static void\nwg_destroy_tcp_connection_entry(",
        )

        dead = "WRITE_ONCE(peer->is_dead, true);"
        cancel = "cancel_work_sync(&peer->tcp_read_work);"
        reset = "wg_reset_tcp_socket_callbacks(peer, true);"
        release = "sock_release(socket);"
        for operation in (dead, cancel, reset, release):
            self.assertIn(operation, destroy)
        self.assertLess(destroy.index(dead), destroy.index(cancel))
        self.assertLess(destroy.index(cancel), destroy.index(reset))
        self.assertLess(destroy.index(reset), destroy.index(release))

    def test_pending_connection_cleanup_has_one_owner(self) -> None:
        claim = section(
            self.socket,
            "wg_claim_tcp_connection(",
            "static void wg_destroy_temp_peer(struct wg_peer *peer)\n{",
        )
        cleanup = section(
            self.socket,
            "void wg_tcp_cleanup_worker(",
            "struct wg_peer *wg_temp_peer_create(struct wg_device *wg)\n{",
        )

        lock = "spin_lock_bh(&wg->tcp_connection_list_lock);"
        delete = "list_del_rcu(&entry->tcp_connection_ll);"
        unlock = "spin_unlock_bh(&wg->tcp_connection_list_lock);"
        grace = "synchronize_rcu();"
        self.assertLess(claim.index(lock), claim.index(delete))
        self.assertLess(claim.index(delete), claim.index(unlock))
        self.assertLess(claim.index(unlock), claim.index(grace))
        self.assertIn("wg_claim_tcp_connection(wg, NULL, true)", cleanup)
        self.assertNotIn("schedule_delayed_work", cleanup)

    def test_device_drains_temp_peers_before_shared_resources(self) -> None:
        stop = section(self.device, "static int wg_stop(", "static netdev_tx_t wg_xmit(")
        destruct = section(
            self.device,
            "static void wg_destruct(",
            "static const struct device_type device_type",
        )

        self.assertLess(
            stop.index("wg_tcp_listener_socket_release(wg);"),
            stop.index("wg_destruct_tcp_connection_list(wg);"),
        )
        drain = destruct.index("wg_destruct_tcp_connection_list(wg);")
        auth_queue = destruct.index("destroy_workqueue(wg->tcp_auth_wq);")
        self.assertLess(drain, auth_queue)
        self.assertLess(drain, destruct.index("wg_peer_remove_all(wg);"))
        self.assertLess(drain, destruct.index("destroy_workqueue(wg->handshake_receive_wq);"))
        self.assertLess(drain, destruct.index("kvfree(wg->peer_hashtable);"))

    def test_device_restart_quiesces_and_reconnects_real_tcp_peers(self) -> None:
        stop = section(self.device, "static int wg_stop(", "static netdev_tx_t wg_xmit(")
        open_device = section(
            self.device, "static int wg_open(", "static int wg_pm_notification("
        )
        peer_stop = section(
            self.socket,
            "void wg_tcp_peer_stop(",
            "struct wg_peer *wg_temp_peer_create(",
        )

        self.assertIn("wg_tcp_peer_stop(peer);", stop)
        self.assertIn(
            "mod_delayed_work(system_wq, &peer->tcp_retry_work, 0);", open_device
        )
        self.assertIn("cancel_delayed_work_sync(&peer->tcp_retry_work);", peer_stop)
        self.assertLess(
            peer_stop.index("cancel_work_sync(&peer->tcp_read_work);"),
            peer_stop.index("wg_reset_tcp_socket_callbacks(peer, false);"),
        )
        self.assertIn("wg_tcp_peer_stop", self.header)


if __name__ == "__main__":
    unittest.main()

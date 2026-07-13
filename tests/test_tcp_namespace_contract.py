#!/usr/bin/env python3
"""Source-level guards for TCP address identity and network namespaces."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    start_index = text.index(start)
    return text[start_index : text.index(end, start_index + len(start))]


class TcpNamespaceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.socket = source("kernel/socket.c")
        cls.device = source("kernel/device.c")
        cls.main = source("kernel/main.c")

    def test_accepted_remote_address_is_initialized_and_validated(self) -> None:
        worker = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )

        clear = "memset(&new_endpoint, 0, sizeof(new_endpoint));"
        getname = "err = new_peer_connection->ops->getname("
        validate = "!wg_sockaddr_length_valid(&new_endpoint.addr, err)"
        release = "sock_release(new_peer_connection);"
        for operation in (clear, getname, validate, release):
            self.assertIn(operation, worker)
        self.assertLess(worker.index(clear), worker.index(getname))
        self.assertLess(worker.index(getname), worker.index(validate))
        self.assertLess(worker.index(validate), worker.index(release))

    def test_provisional_replacement_compares_only_remote_sockaddr(self) -> None:
        compare = section(
            self.socket,
            "static bool wg_sockaddrs_match(",
            "static bool wg_sockaddr_length_valid(",
        )
        worker = section(
            self.socket,
            "int wg_tcp_listener_worker(",
            "int wg_tcp_listener4_thread(",
        )

        for remote_field in (
            "sin_port",
            "sin_addr.s_addr",
            "sin6_port",
            "sin6_addr",
            "sin6_scope_id",
        ):
            self.assertIn(remote_field, compare)
        for local_field in ("src4", "src6", "src_if4"):
            self.assertNotIn(local_field, compare)
        self.assertIn("wg_sockaddrs_match(", worker)
        self.assertIn("(const struct sockaddr *)&socket_iter->src_addr", worker)
        self.assertNotIn("endpoint_eq(&new_endpoint", worker)

    def test_listener_does_not_probe_a_global_default_route(self) -> None:
        listener = section(
            self.socket,
            "int wg_tcp_listener_socket_init(",
            "static void wg_tcp_connect_unwind(",
        )

        self.assertIn("rcu_dereference(wg->creating_net)", listener)
        self.assertIn("net = net ? maybe_get_net(net) : NULL;", listener)
        self.assertIn("wg_setup_tcp_listen4(wg, net, port", listener)
        self.assertIn("if (ipv6_mod_enabled())", listener)
        self.assertNotIn("lookup_default_interface", listener)
        self.assertNotIn("default_iface_info", self.socket)
        self.assertNotIn("lookup_default_interface", self.main)
        self.assertNotIn("&init_net", self.main)

    def test_outbound_socket_uses_creation_namespace_and_device_mark(self) -> None:
        connect = section(
            self.socket,
            "int wg_tcp_connect(struct wg_peer *peer)\n{",
            "/* FIX: -Wunused-function",
        )

        acquire = "net = rcu_dereference(peer->device->creating_net);"
        create = "ret = sock_create_kern(net, peer->peer_endpoint.addr.sa_family,"
        release = "put_net(net);"
        mark = "WRITE_ONCE(socket->sk->sk_mark, peer->device->fwmark);"
        initiate = "ret = kernel_connect(socket, addr,"
        for operation in (acquire, create, release, mark, initiate):
            self.assertIn(operation, connect)
        self.assertLess(connect.index(acquire), connect.index(create))
        self.assertLess(connect.index(create), connect.index(release))
        self.assertLess(connect.index(release), connect.index(mark))
        self.assertLess(connect.index(mark), connect.index(initiate))
        self.assertNotIn("sock_create_kern(&init_net", connect)

    def test_creation_namespace_exit_quiesces_tcp_before_pointer_clear(self) -> None:
        pre_exit = section(
            self.device,
            "static void wg_netns_pre_exit(struct net *net)",
            "static struct pernet_operations pernet_ops",
        )

        disable = "WRITE_ONCE(wg->tcp_cleanup_scheduled, false);"
        listener = "wg_tcp_listener_socket_release(wg);"
        cancel = "cancel_delayed_work_sync(&wg->tcp_cleanup_work);"
        provisional = "wg_destruct_tcp_connection_list(wg);"
        peer = "wg_tcp_peer_stop(peer);"
        clear = "rcu_assign_pointer(wg->creating_net, NULL);"
        udp = "wg_socket_reinit(wg, NULL, NULL);"
        for operation in (
            disable,
            listener,
            cancel,
            provisional,
            peer,
            clear,
            udp,
        ):
            self.assertIn(operation, pre_exit)
        self.assertLess(pre_exit.index(disable), pre_exit.index(listener))
        self.assertLess(pre_exit.index(listener), pre_exit.index(cancel))
        self.assertLess(pre_exit.index(cancel), pre_exit.index(provisional))
        self.assertLess(pre_exit.index(provisional), pre_exit.index(peer))
        self.assertLess(pre_exit.index(peer), pre_exit.index(clear))
        self.assertLess(pre_exit.index(clear), pre_exit.index(udp))


if __name__ == "__main__":
    unittest.main()

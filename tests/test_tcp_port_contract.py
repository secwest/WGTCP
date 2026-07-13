#!/usr/bin/env python3
"""Source-level guards for TCP listen-port selection and updates."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


def section(text: str, start: str, end: str) -> str:
    return text[text.index(start) : text.index(end)]


class TcpPortContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.device = source("kernel/device.c")
        cls.netlink = source("kernel/netlink.c")
        cls.socket = source("kernel/socket.c")

    def test_tcp_open_uses_udp_selected_port(self) -> None:
        open_device = section(
            self.device, "static int wg_open(", "static int wg_pm_notification("
        )
        udp_init = "ret = wg_socket_init(wg, wg->incoming_port);"
        tcp_init = "ret = wg_tcp_listener_socket_init(wg, wg->incoming_port);"

        self.assertIn("u16 requested_port = wg->incoming_port;", open_device)
        self.assertLess(open_device.index(udp_init), open_device.index(tcp_init))

    def test_tcp_listener_failure_rolls_back_udp_and_requested_port(self) -> None:
        open_device = section(
            self.device, "static int wg_open(", "static int wg_pm_notification("
        )
        tcp_failure = section(
            open_device,
            "ret = wg_tcp_listener_socket_init(wg, wg->incoming_port);",
            "mutex_lock(&wg->device_update_lock);",
        )

        self.assertIn("wg_socket_reinit(wg, NULL, NULL);", tcp_failure)
        self.assertIn("wg->incoming_port = requested_port;", tcp_failure)
        self.assertLess(
            tcp_failure.index("wg_socket_reinit(wg, NULL, NULL);"),
            tcp_failure.index("wg->incoming_port = requested_port;"),
        )

    def test_live_tcp_port_change_is_rejected_before_mutation(self) -> None:
        set_port = section(
            self.netlink, "static int set_port(", "static int set_allowedip("
        )
        reject = (
            "if (wg->transport == WG_TRANSPORT_TCP && netif_running(wg->dev))\n"
            "\t\treturn -EBUSY;"
        )

        self.assertIn(reject, set_port)
        self.assertLess(set_port.index(reject), set_port.index("list_for_each_entry"))
        self.assertNotIn("wg_tcp_listener_socket_release", set_port)
        self.assertNotIn("wg_tcp_listener_socket_init", set_port)

    def test_link_down_endpoint_update_does_not_open_tcp_sockets(self) -> None:
        endpoint_update = section(
            self.socket,
            "static void wg_socket_set_peer_endpoint_internal(",
            "void wg_socket_set_peer_endpoint(",
        )
        guarded_connect = (
            "else if (netif_running(peer->device->dev) &&\n"
            "\t\t   !peer->tcp_established)"
        )

        self.assertIn(guarded_connect, endpoint_update)
        self.assertLess(
            endpoint_update.index(guarded_connect),
            endpoint_update.index("wg_tcp_connect(peer);"),
        )


if __name__ == "__main__":
    unittest.main()

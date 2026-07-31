#!/usr/bin/env python3
"""Source-level guards for the UDP compatibility contract."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def source(relative_path: str) -> str:
    return (ROOT / relative_path).read_text(encoding="utf-8")


class UdpCompatibilityContract(unittest.TestCase):
    def test_udp_remains_zero_and_default_port_is_not_forced(self) -> None:
        uapi = source("include/uapi/linux/wireguard.h")
        device = source("kernel/device.c") + source("kernel/device.h")
        self.assertIn("#define WG_TRANSPORT_UDP 0", uapi)
        self.assertNotIn("WG_INCOMING_PORT", device)
        self.assertNotRegex(device, r"incoming_port\s*=\s*51820")

    def test_udp_device_creation_does_not_allocate_tcp_workqueues(self) -> None:
        device = source("kernel/device.c")
        newlink = device[
            device.index("static int wg_newlink(") : device.index(
                "static struct rtnl_link_ops"
            )
        ]
        open_device = device[
            device.index("static int wg_open(") : device.index(
                "static int wg_pm_notification("
            )
        ]

        self.assertNotIn('alloc_workqueue("wg-tcp-auth-%s"', newlink)
        tcp_gate = open_device.index(
            "if (wg->transport == WG_TRANSPORT_TCP) {"
        )
        allocation = open_device.index(
            'alloc_workqueue("wg-tcp-auth-%s"', tcp_gate
        )
        self.assertLess(tcp_gate, allocation)

    def test_cookie_truth_table_challenges_uncookied_load(self) -> None:
        cookie = source("kernel/cookie.h")
        receive = source("kernel/receive.c")
        main = source("kernel/main.c")
        selftest = source("kernel/selftest/cookie.c")
        self.assertRegex(
            cookie,
            r"under_load\s*&&\s*mac_state\s*==\s*"
            r"VALID_MAC_BUT_NO_COOKIE\)\s*\n\s*return WG_COOKIE_CHALLENGE",
        )
        self.assertIn(
            "{ true, VALID_MAC_BUT_NO_COOKIE, WG_COOKIE_CHALLENGE }",
            selftest,
        )
        expected_cases = (
            "{ false, INVALID_MAC, WG_COOKIE_DROP }",
            "{ false, VALID_MAC_BUT_NO_COOKIE, WG_COOKIE_ACCEPT }",
            "{ false, VALID_MAC_WITH_COOKIE_BUT_RATELIMITED, WG_COOKIE_DROP }",
            "{ false, VALID_MAC_WITH_COOKIE, WG_COOKIE_DROP }",
            "{ true, INVALID_MAC, WG_COOKIE_DROP }",
            "{ true, VALID_MAC_BUT_NO_COOKIE, WG_COOKIE_CHALLENGE }",
            "{ true, VALID_MAC_WITH_COOKIE_BUT_RATELIMITED, WG_COOKIE_DROP }",
            "{ true, VALID_MAC_WITH_COOKIE, WG_COOKIE_ACCEPT }",
        )
        for case in expected_cases:
            self.assertIn(case, selftest)
        self.assertIn(
            "cookie_action = wg_cookie_validation_action(under_load, mac_state);",
            receive,
        )
        self.assertIn("wg_cookie_policy_selftest()", main)

    def test_udp_socket_uses_device_as_user_data(self) -> None:
        socket = source("kernel/socket.c")
        udp_init = socket[
            socket.index("int wg_socket_init(") : socket.index(
                "void wg_socket_reinit("
            )
        ]
        udp_reinit = socket[socket.index("void wg_socket_reinit(") :]
        self.assertIn(".sk_user_data = wg", udp_init)
        self.assertNotIn("socket_data", udp_init)
        self.assertIn("synchronize_rcu();", udp_reinit)
        self.assertIn("synchronize_net();", udp_reinit)

    def test_udp_send_rejects_self_routes(self) -> None:
        socket = source("kernel/socket.c")
        send4 = socket[
            socket.index("static int send4(") : socket.index("static int send6(")
        ]
        send6 = socket[
            socket.index("static int send6(") : socket.index(
                "int wg_socket_send_skb_to_endpoint("
            )
        ]
        self.assertIn("} else if (unlikely(rt->dst.dev == skb->dev)) {", send4)
        self.assertIn("ip_rt_put(rt);\n\t\t\tret = -ELOOP;", send4)
        self.assertIn("} else if (unlikely(dst->dev == skb->dev)) {", send6)
        self.assertIn("dst_release(dst);\n\t\t\tret = -ELOOP;", send6)

    def test_udp_send_without_endpoint_returns_address_family_error(self) -> None:
        tcp_socket = source("kernel/wg_tcp.c")
        udp_socket = source("kernel/socket.c")
        dispatch = tcp_socket[
            tcp_socket.index("int wg_socket_send_skb_to_peer(") : tcp_socket.index(
                "static bool wg_tcp_dial_target_eq("
            )
        ]
        endpoint_dispatch = udp_socket[
            udp_socket.index("int wg_socket_send_skb_to_endpoint(") :
            udp_socket.index("int wg_socket_send_buffer_to_peer(")
        ]
        self.assertIn("int ret = -EAFNOSUPPORT;", dispatch)
        self.assertIn("dev_kfree_skb(skb);", endpoint_dispatch)
        self.assertIn("return -EAFNOSUPPORT;", endpoint_dispatch)
        self.assertNotIn("return -EAGAIN;", dispatch)

    def test_tcp_endpoint_rewrite_is_gated_from_udp(self) -> None:
        socket = source("kernel/wg_tcp.c")
        endpoint_update = socket[
            socket.index("static void wg_socket_set_peer_endpoint_internal(") : socket.index(
                "void wg_socket_set_peer_endpoint("
            )
        ]
        gate = endpoint_update.index(
            "if (peer->device->transport == WG_TRANSPORT_TCP) {"
        )
        rewrite = endpoint_update.index("peer->tcp_reply_endpoint = peer->endpoint;")
        self.assertLess(gate, rewrite)
        self.assertNotIn("incoming_port", endpoint_update)

    def test_tcp_collision_policy_is_gated_from_udp(self) -> None:
        noise = source("kernel/noise.c")
        consume = noise[
            noise.index("wg_noise_handshake_consume_initiation(") : noise.index(
                "wg_noise_handshake_create_response("
            )
        ]
        self.assertIn("if (wg->transport == WG_TRANSPORT_TCP) {", consume)
        self.assertNotIn("pr_info(\"wireguard: create_", noise)

    def test_transport_set_is_validated_and_not_live_switched(self) -> None:
        netlink = source("kernel/netlink.c")
        setter = netlink[
            netlink.index("static int wg_set_device(") : netlink.index(
                "static const struct genl_ops"
            )
        ]
        self.assertIn("if (transport > WG_TRANSPORT_TCP)", setter)
        self.assertIn("if (netif_running(wg->dev) ||", setter)

    def test_stock_udp_tool_output_stays_stable(self) -> None:
        show = source("tools/show.c")
        showconf = source("tools/showconf.c")
        ipc = source("tools/ipc-linux.h")
        self.assertIn("if (device->transport == WG_TRANSPORT_TCP)", show)
        self.assertIn('printf("Transport = %s\\n"', showconf)
        self.assertNotIn('printf("TransportMode =', showconf)
        self.assertNotIn("print_netlink_message", ipc)
        self.assertNotIn("hex_dump", ipc)
        self.assertIn("if (!(current->flags & WGDEVICE_HAS_TRANSPORT))", ipc)
        self.assertIn("dev->flags &= ~WGDEVICE_HAS_TRANSPORT;", ipc)


if __name__ == "__main__":
    unittest.main()

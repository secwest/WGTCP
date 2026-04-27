// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "version.h"
#include "device.h"
#include "noise.h"
#include "queueing.h"
#include "ratelimiter.h"
#include "netlink.h"
#include "socket.h"

#include <uapi/linux/wireguard.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/genetlink.h>
#include <net/rtnetlink.h>

#include <linux/netdevice.h>  // Required for net_device
#include <linux/inetdevice.h> // Required for inetdev processing
#include "wg_tcp_debug.h"

// Global structure to hold default network interface information
struct default_interface_info {
	struct net_device *dev;   	// Default network interface
	__be32 ipv4_address;      	// IPv4 address of the default interface
	struct in6_addr ipv6_address;	// IPv6 address of the default interface
	bool ipv4_available;		// Flag indicating if IPv4 is available
	bool ipv6_available;		// Flag indicating if IPv6 is available
};

struct default_interface_info default_iface_info;

#include <net/route.h>			// Required for routing table access
#include <net/ip_fib.h>			// Required for FIB (Forwarding Information Base) access

void lookup_default_interface(void)
{
	// Use the initial network namespace
	struct net *net = &init_net;
	struct flowi4 fl4 = {
		// Using 8.8.8.8 as a dummy external destination
		.daddr = htonl(0x08080808),
	};
	struct rtable *rt = ip_route_output_key(net, &fl4);

	if (!rt) {
		printk(KERN_ERR "Failed to find the default route\n");
		return;
	}

	// Get the main interface used for routing
	struct net_device *main_dev = rt->dst.dev;

	if (!main_dev) {
		printk(KERN_ERR "Failed to find the main network interface\n");
		ip_rt_put(rt);
		return;
	}

	default_iface_info.dev = main_dev;

	// Retrieve the IPv4 address
	struct in_device *in_dev = __in_dev_get_rtnl(main_dev);
	struct in_ifaddr *ifa = NULL;

	if (in_dev) {
		for (ifa = in_dev->ifa_list; ifa; ifa = ifa->ifa_next) {
			if (ifa->ifa_scope == RT_SCOPE_UNIVERSE) {
				default_iface_info.ipv4_address = ifa->ifa_address;
				default_iface_info.ipv4_available = true;
				wg_dbg("Default IPv4 interface: %s, IP: %pI4\n",
				        main_dev->name, &ifa->ifa_address);
				break;
			}
		}
	}

	// Retrieve the IPv6 address
	struct inet6_dev *in6_dev = __in6_dev_get(main_dev);
	struct inet6_ifaddr *ifa6 = NULL;

	if (in6_dev) {
		list_for_each_entry(ifa6, &in6_dev->addr_list, if_list) {
			if (ifa6->scope == RT_SCOPE_UNIVERSE) {
				default_iface_info.ipv6_address = ifa6->addr;
				default_iface_info.ipv6_available = true;
				wg_dbg("Default IPv6 interface: %s, IP: %pI6\n",
				       main_dev->name, &ifa6->addr);
				break;
			}
		}
	}

	// Clean up routing table reference
	ip_rt_put(rt);
}

static int __init wg_mod_init(void)
{
	int ret;

	wg_dbg("Entering: wg_mod_init\n");

	ret = wg_allowedips_slab_init();
	wg_dbg("wg_mod_init: wg_allowedips_slab_init() = %d\n", ret);
	if (ret < 0)
		goto err_allowedips;

#ifdef DEBUG
	ret = -ENOTRECOVERABLE;
	if (!wg_allowedips_selftest() || !wg_packet_counter_selftest() || !wg_ratelimiter_selftest()) {
		wg_dbg("wg_mod_init: Self-test failed\n");
		goto err_peer;
	}
#endif
	wg_noise_init();
	wg_dbg("wg_mod_init: wg_noise_init() completed\n");

	ret = wg_peer_init();
	wg_dbg("wg_mod_init: wg_peer_init() = %d\n", ret);
	if (ret < 0)
		goto err_peer;

	ret = wg_device_init();
	wg_dbg("wg_mod_init: wg_device_init() = %d\n", ret);
	if (ret < 0)
		goto err_device;

	ret = wg_genetlink_init();
	wg_dbg("wg_mod_init: wg_genetlink_init() = %d\n", ret);
	if (ret < 0)
		goto err_netlink;

	wg_dbg("WireGuard " WIREGUARD_VERSION " loaded. See www.wireguard.com for information.\n");
	wg_dbg("Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.\n");
	wg_dbg("TCP Transport Mode - Copyright (C) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.\n");

	lookup_default_interface();
	
	wg_dbg("Exiting: wg_mod_init\n");
	return 0;

err_netlink:
	wg_device_uninit();
err_device:
	wg_peer_uninit();
err_peer:
	wg_allowedips_slab_uninit();
err_allowedips:
	wg_dbg("Exiting with error: wg_mod_init, ret = %d\n", ret);
	return ret;
}

static void __exit wg_mod_exit(void)
{
	wg_dbg("Entering: wg_mod_exit\n");

	wg_genetlink_uninit();
	wg_dbg("wg_mod_exit: wg_genetlink_uninit() completed\n");

	wg_device_uninit();
	wg_dbg("wg_mod_exit: wg_device_uninit() completed\n");

	wg_peer_uninit();
	wg_dbg("wg_mod_exit: wg_peer_uninit() completed\n");

	wg_allowedips_slab_uninit();
	wg_dbg("wg_mod_exit: wg_allowedips_slab_uninit() completed\n");

	wg_dbg("Exiting: wg_mod_exit\n");
}

module_init(wg_mod_init);
module_exit(wg_mod_exit);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("WireGuard secure network tunnel - with UDP/TCP");
MODULE_AUTHOR("Jason A. Donenfeld <Jason@zx2c4.com>");
MODULE_VERSION(WIREGUARD_VERSION);
MODULE_ALIAS_RTNL_LINK(KBUILD_MODNAME);
MODULE_ALIAS_GENL_FAMILY(WG_GENL_NAME);

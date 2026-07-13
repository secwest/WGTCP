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
#include "cookie.h"

#include <uapi/linux/wireguard.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/genetlink.h>
#include <net/rtnetlink.h>

#include "wg_tcp_debug.h"

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
	if (!wg_allowedips_selftest() || !wg_packet_counter_selftest() ||
	    !wg_ratelimiter_selftest() || !wg_cookie_policy_selftest()) {
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

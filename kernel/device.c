// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#include "queueing.h"
#include "socket.h"
#include "timers.h"
#include "device.h"
#include "ratelimiter.h"
#include "peer.h"
#include "messages.h"

#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/suspend.h>
#include <linux/spinlock.h>
#include <linux/wireguard.h>
#include <net/dst_metadata.h>
#include <net/gso.h>
#include <net/icmp.h>
#include <net/rtnetlink.h>
#include <net/ip_tunnels.h>
#include <net/addrconf.h>
#include <net/fib_notifier.h>
#include <net/netns/generic.h>
#include "wg_tcp_debug.h"

void wg_tcp_listener_socket_release(struct wg_device *wg);

static LIST_HEAD(device_list);
static unsigned int wg_net_id;

struct wg_net {
	struct net *net;
	struct notifier_block fib_notifier;
	struct delayed_work fib_dispatch_work;
	bool fib_registered;
};

static int wg_open(struct net_device *dev)
{
	struct in_device *dev_v4 = __in_dev_get_rtnl(dev);
	struct inet6_dev *dev_v6 = __in6_dev_get(dev);
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	u16 requested_port = wg->incoming_port;
	int ret = 0;

	wg_dbg("Entering wg_open: dev=%px\n", dev);
	WRITE_ONCE(wg->tcp_cleanup_scheduled,
		   wg->transport == WG_TRANSPORT_TCP);

	if (dev_v4) {
		/* At some point we might put this check near the ip_rt_send_
		 * redirect call of ip_forward in net/ipv4/ip_forward.c, similar
		 * to the current secpath check.
		 */
		IN_DEV_CONF_SET(dev_v4, SEND_REDIRECTS, false);
		IPV4_DEVCONF_ALL(dev_net(dev), SEND_REDIRECTS) = false;
	}
	if (dev_v6)
		dev_v6->cnf.addr_gen_mode = IN6_ADDR_GEN_MODE_NONE;

	
	wg->listener_active = false;
	/* Bind UDP first so port zero retains WireGuard's random-port semantics.
	 * TCP then uses the concrete port selected by the companion UDP socket.
	 */
	ret = wg_socket_init(wg, wg->incoming_port);
	if (ret < 0) {
		WRITE_ONCE(wg->tcp_cleanup_scheduled, false);
		return ret;
	}
	if (wg->transport == WG_TRANSPORT_TCP) {
		if (!wg->tcp_auth_wq) {
			wg->tcp_auth_wq = alloc_workqueue("wg-tcp-auth-%s",
						  WQ_UNBOUND | WQ_MEM_RECLAIM,
						  0, dev->name);
			if (!wg->tcp_auth_wq) {
				ret = -ENOMEM;
				goto err_tcp_open;
			}
		}
		ret = wg_tcp_listener_socket_init(wg, wg->incoming_port);
		if (ret < 0)
			goto err_tcp_open;
	}
	mutex_lock(&wg->device_update_lock);
	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		bool queue_tcp_retry = false;

		if (wg->transport == WG_TRANSPORT_TCP) {
			spin_lock_bh(&peer->tcp_lock);
			peer->tcp_stopping = false;
			if (peer->peer_endpoint_set &&
			    !peer->tcp_retry_scheduled &&
			    !peer->tcp_outbound_remove_scheduled) {
				peer->tcp_retry_scheduled = true;
				queue_tcp_retry = true;
			}
			if (queue_tcp_retry)
				mod_delayed_work(system_wq, &peer->tcp_retry_work, 0);
			spin_unlock_bh(&peer->tcp_lock);
		}
		wg_packet_send_staged_packets(peer);
		if (peer->persistent_keepalive_interval)
			wg_packet_send_keepalive(peer);
	}
	mutex_unlock(&wg->device_update_lock);
	wg_dbg("Exiting wg_open: dev=%px, ret=%d\n", dev, ret);
	return ret;

err_tcp_open:
	WRITE_ONCE(wg->tcp_cleanup_scheduled, false);
	wg_tcp_listener_socket_release(wg);
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);
	wg_destruct_tcp_connection_list(wg);
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);
	wg_socket_reinit(wg, NULL, NULL);
	wg->incoming_port = requested_port;
	return ret;
}

static int wg_pm_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct wg_device *wg;
	struct wg_peer *peer;

	wg_dbg("Entering wg_pm_notification: nb=%px, action=%lu, data=%px\n", nb, action, data);

	/* If the machine is constantly suspending and resuming, as part of
	 * its normal operation rather than as a somewhat rare event, then we
	 * don't actually want to clear keys.
	 */
	if (IS_ENABLED(CONFIG_PM_AUTOSLEEP) ||
	    IS_ENABLED(CONFIG_PM_USERSPACE_AUTOSLEEP)) {
		wg_dbg("Exiting wg_pm_notification (no action): nb=%px, action=%lu, data=%px\n", nb, action, data);
		return 0;
	}

	if (action != PM_HIBERNATION_PREPARE && action != PM_SUSPEND_PREPARE) {
		wg_dbg("Exiting wg_pm_notification (no action): nb=%px, action=%lu, data=%px\n", nb, action, data);
		return 0;
	}

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		mutex_lock(&wg->device_update_lock);
		list_for_each_entry(peer, &wg->peer_list, peer_list) {
			del_timer(&peer->timer_zero_key_material);
			wg_noise_handshake_clear(&peer->handshake);
			wg_noise_keypairs_clear(&peer->keypairs);
		}
		mutex_unlock(&wg->device_update_lock);
	}
	rtnl_unlock();
	rcu_barrier();
	wg_dbg("Exiting wg_pm_notification: nb=%px, action=%lu, data=%px\n", nb, action, data);
	return 0;
}

static struct notifier_block pm_notifier = { .notifier_call = wg_pm_notification };

static int wg_vm_notification(struct notifier_block *nb, unsigned long action, void *data)
{
	struct wg_device *wg;
	struct wg_peer *peer;

	wg_dbg("Entering wg_vm_notification: nb=%px, action=%lu, data=%px\n", nb, action, data);

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		mutex_lock(&wg->device_update_lock);
		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_noise_expire_current_peer_keypairs(peer);
		mutex_unlock(&wg->device_update_lock);
	}
	rtnl_unlock();
	wg_dbg("Exiting wg_vm_notification: nb=%px, action=%lu, data=%px\n", nb, action, data);
	return 0;
}

static struct notifier_block vm_notifier = { .notifier_call = wg_vm_notification };

static void wg_tcp_route_change_worker(struct work_struct *work)
{
	struct wg_device *wg = container_of(work, struct wg_device,
					    tcp_route_work.work);
	struct wg_peer *peer;

	mutex_lock(&wg->device_update_lock);
	if (wg->transport == WG_TRANSPORT_TCP &&
	    READ_ONCE(wg->tcp_cleanup_scheduled) && netif_running(wg->dev) &&
	    rcu_access_pointer(wg->creating_net)) {
		list_for_each_entry(peer, &wg->peer_list, peer_list) {
			wg_socket_clear_peer_endpoint_src(peer);
			wg_tcp_peer_request_reconnect(peer);
		}
	}
	mutex_unlock(&wg->device_update_lock);
}

static void wg_tcp_fib_dispatch_worker(struct work_struct *work)
{
	struct wg_net *wn = container_of(work, struct wg_net,
					 fib_dispatch_work.work);
	struct wg_device *wg;

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		if (rcu_access_pointer(wg->creating_net) != wn->net ||
		    wg->transport != WG_TRANSPORT_TCP ||
		    !READ_ONCE(wg->tcp_cleanup_scheduled) ||
		    !netif_running(wg->dev))
			continue;
		mod_delayed_work(system_wq, &wg->tcp_route_work,
				 msecs_to_jiffies(100));
	}
	rtnl_unlock();
}

static int wg_tcp_fib_notification(struct notifier_block *nb,
				   unsigned long action, void *data)
{
	struct wg_net *wn = container_of(nb, struct wg_net, fib_notifier);
	const struct fib_notifier_info *info = data;

	if (!READ_ONCE(wn->fib_registered) || !info ||
	    (info->family != AF_INET && info->family != AF_INET6))
		return NOTIFY_DONE;
	switch (action) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_APPEND:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
	case FIB_EVENT_RULE_ADD:
	case FIB_EVENT_RULE_DEL:
	case FIB_EVENT_NH_ADD:
	case FIB_EVENT_NH_DEL:
		mod_delayed_work(system_wq, &wn->fib_dispatch_work, 0);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

/* Address and link notifiers run under RTNL, which also protects device_list.
 * Queueing keeps socket shutdown and reconnect work out of notifier context and
 * coalesces the event bursts emitted by one administrative change.
 */
static void wg_tcp_schedule_route_change(struct net_device *changed_dev)
{
	struct wg_device *wg;

	if (!changed_dev)
		return;
	list_for_each_entry(wg, &device_list, device_list) {
		if (wg->dev == changed_dev ||
		    rcu_access_pointer(wg->creating_net) != dev_net(changed_dev) ||
		    wg->transport != WG_TRANSPORT_TCP)
			continue;
		mod_delayed_work(system_wq, &wg->tcp_route_work,
				 msecs_to_jiffies(100));
	}
}

static int wg_netdevice_notification(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct net_device *changed_dev = netdev_notifier_info_to_dev(data);

	switch (action) {
	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_CHANGE:
	case NETDEV_CHANGEADDR:
	case NETDEV_UNREGISTER:
		wg_tcp_schedule_route_change(changed_dev);
		break;
	default:
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block netdevice_notifier = {
	.notifier_call = wg_netdevice_notification
};

static int wg_inetaddr_notification(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	const struct in_ifaddr *ifa = data;

	if (ifa && ifa->ifa_dev)
		wg_tcp_schedule_route_change(ifa->ifa_dev->dev);
	return NOTIFY_DONE;
}

static struct notifier_block inetaddr_notifier = {
	.notifier_call = wg_inetaddr_notification
};

#if IS_ENABLED(CONFIG_IPV6)
static int wg_inet6addr_notification(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	const struct inet6_ifaddr *ifa = data;

	if (ifa && ifa->idev)
		wg_tcp_schedule_route_change(ifa->idev->dev);
	return NOTIFY_DONE;
}

static struct notifier_block inet6addr_notifier = {
	.notifier_call = wg_inet6addr_notification
};
#endif

static int wg_stop(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct wg_peer *peer;
	struct sk_buff *skb;

	wg_dbg("Entering wg_stop: dev=%px\n", dev);
	WRITE_ONCE(wg->tcp_cleanup_scheduled, false);
	cancel_delayed_work_sync(&wg->tcp_route_work);
	mutex_lock(&wg->device_update_lock);
	if (wg->transport == WG_TRANSPORT_TCP) {
		/* Quiesce every connect/removal owner before releasing the shared
		 * listeners. Otherwise an in-flight connect can republish listener or
		 * peer socket state after the device teardown pass.
		 */
		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_tcp_peer_stop(peer);
		wg_tcp_listener_socket_release(wg);
	}
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);
	wg_destruct_tcp_connection_list(wg);
	/* Destruction drains temp-peer callbacks that may have passed their
	 * cleanup flag check before shutdown. Catch any device work queued by
	 * such a callback after the first cancellation pass.
	 */
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);

	list_for_each_entry(peer, &wg->peer_list, peer_list) {
		wg_packet_purge_staged_packets(peer);
		wg_timers_stop(peer);
		wg_noise_handshake_clear(&peer->handshake);
		wg_noise_keypairs_clear(&peer->keypairs);
		wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	}
	mutex_unlock(&wg->device_update_lock);
	while ((skb = ptr_ring_consume(&wg->handshake_queue.ring)) != NULL)
		kfree_skb(skb);

	atomic_set(&wg->handshake_queue_len, 0);

	wg_socket_reinit(wg, NULL, NULL);

	wg_dbg("Exiting wg_stop: dev=%px\n", dev);
	return 0;
}

static netdev_tx_t wg_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	struct sk_buff_head packets;
	struct wg_peer *peer;
	struct sk_buff *next;
	sa_family_t family;
	u32 mtu;
	int ret;

	wg_dbg("Entering wg_xmit: skb=%px, dev=%px\n", skb, dev);

	if (unlikely(!wg_check_packet_protocol(skb))) {
		ret = -EPROTONOSUPPORT;
		net_dbg_ratelimited("%s: Invalid IP packet\n", dev->name);
		goto err;
	}

	peer = wg_allowedips_lookup_dst(&wg->peer_allowedips, skb);
	if (unlikely(!peer)) {
		ret = -ENOKEY;
		if (skb->protocol == htons(ETH_P_IP))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI4\n",
					    dev->name, &ip_hdr(skb)->daddr);
		else if (skb->protocol == htons(ETH_P_IPV6))
			net_dbg_ratelimited("%s: No peer has allowed IPs matching %pI6\n",
					    dev->name, &ipv6_hdr(skb)->daddr);
		goto err_icmp;
	}

	family = READ_ONCE(peer->endpoint.addr.sa_family);
	if (unlikely(family != AF_INET && family != AF_INET6)) {
		ret = -EDESTADDRREQ;
		net_dbg_ratelimited("%s: No valid endpoint has been configured or discovered for peer %llu\n",
				    dev->name, peer->internal_id);
		goto err_peer;
	}

	mtu = skb_valid_dst(skb) ? dst_mtu(skb_dst(skb)) : dev->mtu;

	__skb_queue_head_init(&packets);
	if (!skb_is_gso(skb)) {
		skb_mark_not_on_list(skb);
	} else {
		struct sk_buff *segs = skb_gso_segment(skb, 0);

		if (IS_ERR(segs)) {
			ret = PTR_ERR(segs);
			goto err_peer;
		}
		dev_kfree_skb(skb);
		skb = segs;
	}

	skb_list_walk_safe(skb, skb, next) {
		skb_mark_not_on_list(skb);

		skb = skb_share_check(skb, GFP_ATOMIC);
		if (unlikely(!skb))
			continue;

		/* We only need to keep the original dst around for icmp,
		 * so at this point we're in a position to drop it.
		 */
		skb_dst_drop(skb);

		PACKET_CB(skb)->mtu = mtu;

		__skb_queue_tail(&packets, skb);
	}

	spin_lock_bh(&peer->staged_packet_queue.lock);
	/* If the queue is getting too big, we start removing the oldest packets
	 * until it's small again. We do this before adding the new packet, so
	 * we don't remove GSO segments that are in excess.
	 */
	while (skb_queue_len(&peer->staged_packet_queue) > MAX_STAGED_PACKETS) {
		dev_kfree_skb(__skb_dequeue(&peer->staged_packet_queue));
		DEV_STATS_INC(dev, tx_dropped);
	}
	skb_queue_splice_tail(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	wg_packet_send_staged_packets(peer);

	wg_peer_put(peer);
	wg_dbg("Exiting wg_xmit: skb=%px, dev=%px\n", skb, dev);
	return NETDEV_TX_OK;

err_peer:
	wg_peer_put(peer);
err_icmp:
	if (skb->protocol == htons(ETH_P_IP))
		icmp_ndo_send(skb, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH, 0);
	else if (skb->protocol == htons(ETH_P_IPV6))
		icmpv6_ndo_send(skb, ICMPV6_DEST_UNREACH, ICMPV6_ADDR_UNREACH, 0);
err:
	DEV_STATS_INC(dev, tx_errors);
	kfree_skb(skb);
	wg_dbg("Exiting wg_xmit with error: skb=%px, dev=%px, ret=%d\n", skb, dev, ret);
	return ret;
}

static const struct net_device_ops netdev_ops = {
	.ndo_open		= wg_open,
	.ndo_stop		= wg_stop,
	.ndo_start_xmit		= wg_xmit,
	.ndo_get_stats64	= dev_get_tstats64
};

static void wg_destruct(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);

	wg_dbg("Entering wg_destruct: dev=%px\n", dev);

	rtnl_lock();
	list_del(&wg->device_list);
	rtnl_unlock();
	cancel_delayed_work_sync(&wg->tcp_route_work);
	mutex_lock(&wg->device_update_lock);
	WRITE_ONCE(wg->tcp_cleanup_scheduled, false);
	if (wg->transport == WG_TRANSPORT_TCP) {
		struct wg_peer *peer;

		list_for_each_entry(peer, &wg->peer_list, peer_list)
			wg_tcp_peer_stop(peer);
		wg_tcp_listener_socket_release(wg);
	}
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);
	wg_destruct_tcp_connection_list(wg);
	cancel_delayed_work_sync(&wg->tcp_cleanup_work);
	if (wg->tcp_auth_wq) {
		destroy_workqueue(wg->tcp_auth_wq);
		wg->tcp_auth_wq = NULL;
	}
	rcu_assign_pointer(wg->creating_net, NULL);
	wg->incoming_port = 0;
	wg_socket_reinit(wg, NULL, NULL);
	/* The final references are cleared in the below calls to destroy_workqueue. */
	wg_peer_remove_all(wg);
	destroy_workqueue(wg->handshake_receive_wq);
	destroy_workqueue(wg->handshake_send_wq);
	destroy_workqueue(wg->packet_crypt_wq);
	wg_packet_queue_free(&wg->handshake_queue, true);
	wg_packet_queue_free(&wg->decrypt_queue, false);
	wg_packet_queue_free(&wg->encrypt_queue, false);
	rcu_barrier(); /* Wait for all the peers to be actually freed. */
	wg_ratelimiter_uninit();
	memzero_explicit(&wg->static_identity, sizeof(wg->static_identity));
	free_percpu(dev->tstats);
	kvfree(wg->index_hashtable);
	kvfree(wg->peer_hashtable);
	mutex_unlock(&wg->device_update_lock);

	pr_debug("%s: Interface destroyed\n", dev->name);
	free_netdev(dev);

	wg_dbg("Exiting wg_destruct: dev=%px\n", dev);
}

static const struct device_type device_type = { .name = KBUILD_MODNAME };

static void wg_setup(struct net_device *dev)
{
	struct wg_device *wg = netdev_priv(dev);
	enum { WG_NETDEV_FEATURES = NETIF_F_HW_CSUM | NETIF_F_RXCSUM |
				    NETIF_F_SG | NETIF_F_GSO |
				    NETIF_F_GSO_SOFTWARE | NETIF_F_HIGHDMA };
	const int overhead = MESSAGE_MINIMUM_LENGTH + sizeof(struct udphdr) +
			     max(sizeof(struct ipv6hdr), sizeof(struct iphdr)) +
			     (wg->transport == WG_TRANSPORT_TCP ? WG_TCP_ENCAP_HDR_LEN : 0);

	wg_dbg("Entering wg_setup: dev=%px\n", dev);

	dev->netdev_ops = &netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->needed_headroom = DATA_PACKET_HEAD_ROOM + (wg->transport ? WG_TCP_ENCAP_HDR_LEN : 0);
	dev->needed_tailroom = noise_encrypted_len(MESSAGE_PADDING_MULTIPLE);
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_POINTOPOINT | IFF_NOARP;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->features |= NETIF_F_LLTX;
	dev->features |= WG_NETDEV_FEATURES;
	dev->hw_features |= WG_NETDEV_FEATURES;
	dev->hw_enc_features |= WG_NETDEV_FEATURES;
	dev->mtu = ETH_DATA_LEN - overhead;
	dev->max_mtu = round_down(INT_MAX, MESSAGE_PADDING_MULTIPLE) - overhead;

	SET_NETDEV_DEVTYPE(dev, &device_type);

	/* We need to keep the dst around in case of icmp replies. */
	netif_keep_dst(dev);

	memset(wg, 0, sizeof(*wg));
	wg->dev = dev;

	wg_dbg("Exiting wg_setup: dev=%px\n", dev);
}

static int wg_newlink(struct net *src_net, struct net_device *dev,
		      struct nlattr *tb[], struct nlattr *data[],
		      struct netlink_ext_ack *extack)
{
	struct wg_device *wg = netdev_priv(dev);
	int ret = -ENOMEM;

	wg_dbg("Entering wg_newlink: src_net=%px, dev=%px, tb=%px, data=%px, extack=%px\n", src_net, dev, tb, data, extack);

	rcu_assign_pointer(wg->creating_net, src_net);
	init_rwsem(&wg->static_identity.lock);
	mutex_init(&wg->socket_update_lock);
	mutex_init(&wg->device_update_lock);
	wg_allowedips_init(&wg->peer_allowedips);
	wg_cookie_checker_init(&wg->cookie_checker, wg);
	INIT_LIST_HEAD(&wg->peer_list);
	wg->device_update_gen = 1;
	// Initialize the tcp_cleanup_scheduled flag and spinlock
	wg->tcp_cleanup_scheduled = false;
	spin_lock_init(&wg->tcp_cleanup_lock);

	// Initialize the work for tcp_cleanup_worker
	INIT_DELAYED_WORK(&wg->tcp_cleanup_work, wg_tcp_cleanup_worker);
	INIT_DELAYED_WORK(&wg->tcp_route_work, wg_tcp_route_change_worker);

	wg->peer_hashtable = wg_pubkey_hashtable_alloc();
	if (!wg->peer_hashtable)
		return ret;

	wg->index_hashtable = wg_index_hashtable_alloc();
	if (!wg->index_hashtable)
		goto err_free_peer_hashtable;

	dev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);
	if (!dev->tstats)
		goto err_free_index_hashtable;

	wg->handshake_receive_wq = alloc_workqueue("wg-kex-%s",
			WQ_CPU_INTENSIVE | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_receive_wq)
		goto err_free_tstats;

	wg->handshake_send_wq = alloc_workqueue("wg-kex-%s",
			WQ_UNBOUND | WQ_FREEZABLE, 0, dev->name);
	if (!wg->handshake_send_wq)
		goto err_destroy_handshake_receive;

	wg->packet_crypt_wq = alloc_workqueue("wg-crypt-%s",
			WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 0, dev->name);
	if (!wg->packet_crypt_wq)
		goto err_destroy_handshake_send;

	ret = wg_packet_queue_init(&wg->encrypt_queue, wg_packet_encrypt_worker,
				   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_destroy_packet_crypt;

	ret = wg_packet_queue_init(&wg->decrypt_queue, wg_packet_decrypt_worker,
				   MAX_QUEUED_PACKETS);
	if (ret < 0)
		goto err_free_encrypt_queue;

	ret = wg_packet_queue_init(&wg->handshake_queue, wg_packet_handshake_receive_worker,
				   MAX_QUEUED_INCOMING_HANDSHAKES);
	if (ret < 0)
		goto err_free_decrypt_queue;

	ret = wg_ratelimiter_init();
	if (ret < 0)
		goto err_free_handshake_queue;

	ret = register_netdevice(dev);
	if (ret < 0)
		goto err_uninit_ratelimiter;

	list_add(&wg->device_list, &device_list);

	INIT_LIST_HEAD(&wg->tcp_connection_list);
	spin_lock_init(&wg->tcp_connection_list_lock);
	spin_lock_init(&wg->tcp_accept_lock);
	atomic64_set(&wg->tcp_connection_sequence, 0);
	wg->tcp_socket4_ready = false;
	wg->tcp_socket6_ready = false;

	/* We wait until the end to assign priv_destructor, so that
	 * register_netdevice doesn't call it for us if it fails.
	 */
	dev->priv_destructor = wg_destruct;

	pr_debug("%s: Interface created\n", dev->name);

	wg_dbg("Exiting wg_newlink: src_net=%px, dev=%px, ret=%d\n", src_net, dev, ret);
	return ret;
err_uninit_ratelimiter:
	wg_ratelimiter_uninit();
err_free_handshake_queue:
	wg_packet_queue_free(&wg->handshake_queue, false);
err_free_decrypt_queue:
	wg_packet_queue_free(&wg->decrypt_queue, false);
err_free_encrypt_queue:
	wg_packet_queue_free(&wg->encrypt_queue, false);
err_destroy_packet_crypt:
	destroy_workqueue(wg->packet_crypt_wq);
err_destroy_handshake_send:
	destroy_workqueue(wg->handshake_send_wq);
err_destroy_handshake_receive:
	destroy_workqueue(wg->handshake_receive_wq);
err_free_tstats:
	free_percpu(dev->tstats);
err_free_index_hashtable:
	kvfree(wg->index_hashtable);
err_free_peer_hashtable:
	kvfree(wg->peer_hashtable);
	wg_dbg("Exiting wg_newlink with error: src_net=%px, dev=%px, ret=%d\n", src_net, dev, ret);
	return ret;
}

static struct rtnl_link_ops link_ops __read_mostly = {
	.kind			= KBUILD_MODNAME,
	.priv_size		= sizeof(struct wg_device),
	.setup			= wg_setup,
	.newlink		= wg_newlink,
};

static int wg_netns_init(struct net *net)
{
	struct wg_net *wn = net_generic(net, wg_net_id);
	int ret;

	wn->net = net;
	wn->fib_notifier.notifier_call = wg_tcp_fib_notification;
	INIT_DELAYED_WORK(&wn->fib_dispatch_work,
			  wg_tcp_fib_dispatch_worker);
	ret = register_fib_notifier(net, &wn->fib_notifier, NULL, NULL);
	if (ret) {
		pr_warn("wireguard: TCP route notifications unavailable in netns %u: %d\n",
			net->ns.inum, ret);
		return 0;
	}
	WRITE_ONCE(wn->fib_registered, true);
	return 0;
}

static void wg_netns_pre_exit(struct net *net)
{
	struct wg_net *wn = net_generic(net, wg_net_id);
	struct wg_device *wg;
	struct wg_peer *peer;

	wg_dbg("Entering wg_netns_pre_exit: net=%px\n", net);
	if (READ_ONCE(wn->fib_registered)) {
		WRITE_ONCE(wn->fib_registered, false);
		unregister_fib_notifier(net, &wn->fib_notifier);
	}
	cancel_delayed_work_sync(&wn->fib_dispatch_work);

	rtnl_lock();
	list_for_each_entry(wg, &device_list, device_list) {
		if (rcu_access_pointer(wg->creating_net) == net) {
			pr_debug("%s: Creating namespace exiting\n", wg->dev->name);
			netif_carrier_off(wg->dev);
			cancel_delayed_work_sync(&wg->tcp_route_work);
			mutex_lock(&wg->device_update_lock);
			if (wg->transport == WG_TRANSPORT_TCP) {
				/* Stop every user of sockets created in this namespace
				 * before publishing that the namespace is gone.
				 */
				WRITE_ONCE(wg->tcp_cleanup_scheduled, false);
				list_for_each_entry(peer, &wg->peer_list, peer_list)
					wg_tcp_peer_stop(peer);
				wg_tcp_listener_socket_release(wg);
				cancel_delayed_work_sync(&wg->tcp_cleanup_work);
				wg_destruct_tcp_connection_list(wg);
				cancel_delayed_work_sync(&wg->tcp_cleanup_work);
			}
			rcu_assign_pointer(wg->creating_net, NULL);
			wg_socket_reinit(wg, NULL, NULL);
			list_for_each_entry(peer, &wg->peer_list, peer_list)
				wg_socket_clear_peer_endpoint_src(peer);
			mutex_unlock(&wg->device_update_lock);
		}
	}
	rtnl_unlock();

	wg_dbg("Exiting wg_netns_pre_exit: net=%px\n", net);
}

static struct pernet_operations pernet_ops = {
	.init = wg_netns_init,
	.pre_exit = wg_netns_pre_exit,
	.id = &wg_net_id,
	.size = sizeof(struct wg_net),
};

int __init wg_device_init(void)
{
	int ret;

	wg_dbg("Entering wg_device_init\n");

	ret = register_pm_notifier(&pm_notifier);
	if (ret)
		goto error;

	ret = register_random_vmfork_notifier(&vm_notifier);
	if (ret)
		goto error_pm;

	ret = register_pernet_device(&pernet_ops);
	if (ret)
		goto error_vm;

	ret = register_netdevice_notifier(&netdevice_notifier);
	if (ret)
		goto error_pernet;

	ret = register_inetaddr_notifier(&inetaddr_notifier);
	if (ret)
		goto error_netdevice;

#if IS_ENABLED(CONFIG_IPV6)
	ret = register_inet6addr_notifier(&inet6addr_notifier);
	if (ret)
		goto error_inetaddr;
#endif

	ret = rtnl_link_register(&link_ops);
	if (ret)
		goto error_inet6addr;

	wg_dbg("Exiting wg_device_init: ret=0\n");
	return 0;

error_inet6addr:
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&inet6addr_notifier);
error_inetaddr:
#endif
	unregister_inetaddr_notifier(&inetaddr_notifier);
error_netdevice:
	unregister_netdevice_notifier(&netdevice_notifier);
error_pernet:
	unregister_pernet_device(&pernet_ops);
error_vm:
	unregister_random_vmfork_notifier(&vm_notifier);
error_pm:
	unregister_pm_notifier(&pm_notifier);
error:
	wg_dbg("Exiting wg_device_init with error: ret=%d\n", ret);
	return ret;
}

void wg_device_uninit(void)
{
	wg_dbg("Entering wg_device_uninit\n");

	rtnl_link_unregister(&link_ops);
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&inet6addr_notifier);
#endif
	unregister_inetaddr_notifier(&inetaddr_notifier);
	unregister_netdevice_notifier(&netdevice_notifier);
	unregister_pernet_device(&pernet_ops);
	unregister_random_vmfork_notifier(&vm_notifier);
	unregister_pm_notifier(&pm_notifier);
	rcu_barrier();

	wg_dbg("Exiting wg_device_uninit\n");
}

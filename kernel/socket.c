// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024-2026 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */


#include "device.h"
#include "peer.h"
#include "socket.h"
#include "wg_tcp.h"
#include "queueing.h"
#include "messages.h"

#include <asm/byteorder.h> /* For ntohl */
#include <linux/ctype.h>
#include <linux/delay.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <linux/wireguard.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/socket.h>
#include <linux/in6.h>
#include <net/checksum.h>
#include <net/udp_tunnel.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <net/inet_common.h>
#include <net/tcp.h>
#include <linux/jiffies.h>
#include <net/inet_connection_sock.h>
#include <linux/version.h>
#include "wg_tcp_debug.h"

static int send4(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
	wg_dbg("Entering function send4\n");


	struct flowi4 fl = {
		.saddr = endpoint->src4.s_addr,
		.daddr = endpoint->addr4.sin_addr.s_addr,
		.fl4_dport = endpoint->addr4.sin_port,
		.flowi4_mark = wg->fwmark,
		.flowi4_proto = IPPROTO_UDP
	};
	struct rtable *rt = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock4);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl4_sport = inet_sk(sock)->inet_sport;

	if (cache)
		rt = dst_cache_get_ip4(cache, &fl.saddr);

	if (!rt) {
		security_sk_classify_flow(sock, flowi4_to_flowi_common(&fl));
		if (unlikely(!inet_confirm_addr(sock_net(sock), NULL, 0,
						fl.saddr, RT_SCOPE_HOST))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
		}
		rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		if (unlikely(endpoint->src_if4 && ((IS_ERR(rt) &&
			     PTR_ERR(rt) == -EINVAL) || (!IS_ERR(rt) &&
			     rt->dst.dev->ifindex != endpoint->src_if4)))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
			if (!IS_ERR(rt))
				ip_rt_put(rt);
			rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		}
		if (unlikely(IS_ERR(rt))) {
			ret = PTR_ERR(rt);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		} else if (unlikely(rt->dst.dev == skb->dev)) {
			ip_rt_put(rt);
			ret = -ELOOP;
			net_dbg_ratelimited("%s: Avoiding routing loop to %pISpfsc\n",
					    wg->dev->name, &endpoint->addr);
			goto err;
		}
		if (cache)
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
	}

	skb->ignore_df = 1;
	udp_tunnel_xmit_skb(rt, sock, skb, fl.saddr, fl.daddr, ds,
			    ip4_dst_hoplimit(&rt->dst), 0, fl.fl4_sport,
			    fl.fl4_dport, false, false);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	wg_dbg("Exiting function send4\n");
	return ret;
}

static int send6(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache)
{
	wg_dbg("Entering function send6\n");
#if IS_ENABLED(CONFIG_IPV6)


	struct flowi6 fl = {
		.saddr = endpoint->src6,
		.daddr = endpoint->addr6.sin6_addr,
		.fl6_dport = endpoint->addr6.sin6_port,
		.flowi6_mark = wg->fwmark,
		.flowi6_oif = endpoint->addr6.sin6_scope_id,
		.flowi6_proto = IPPROTO_UDP
		/* TODO: addr->sin6_flowinfo */
	};
	struct dst_entry *dst = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock6);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl6_sport = inet_sk(sock)->inet_sport;

	if (cache)
		dst = dst_cache_get_ip6(cache, &fl.saddr);

	if (!dst) {
		security_sk_classify_flow(sock, flowi6_to_flowi_common(&fl));
		if (unlikely(!ipv6_addr_any(&fl.saddr) &&
			     !ipv6_chk_addr(sock_net(sock), &fl.saddr, NULL, 0))) {
			endpoint->src6 = fl.saddr = in6addr_any;
			if (cache)
				dst_cache_reset(cache);
		}
		dst = ipv6_stub->ipv6_dst_lookup_flow(sock_net(sock), sock, &fl,
						      NULL);
		if (unlikely(IS_ERR(dst))) {
			ret = PTR_ERR(dst);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		} else if (unlikely(dst->dev == skb->dev)) {
			dst_release(dst);
			ret = -ELOOP;
			net_dbg_ratelimited("%s: Avoiding routing loop to %pISpfsc\n",
					    wg->dev->name, &endpoint->addr);
			goto err;
		}
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	skb->ignore_df = 1;
	udp_tunnel6_xmit_skb(dst, sock, skb, skb->dev, &fl.saddr, &fl.daddr, ds,
			     ip6_dst_hoplimit(dst), 0, fl.fl6_sport,
			     fl.fl6_dport, false);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	wg_dbg("Exiting function send6\n");
	return ret;
#else
	kfree_skb(skb);
	wg_dbg("Exiting function send6\n");
	return -EAFNOSUPPORT;
#endif
}

int wg_socket_send_skb_to_endpoint(struct wg_device *wg,
				   struct sk_buff *skb,
				   struct endpoint *endpoint, u8 ds,
				   struct dst_cache *cache)
{
	if (endpoint->addr.sa_family == AF_INET)
		return send4(wg, skb, endpoint, ds, cache);
	if (endpoint->addr.sa_family == AF_INET6)
		return send6(wg, skb, endpoint, ds, cache);

	dev_kfree_skb(skb);
	return -EAFNOSUPPORT;
}

int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *buffer,
				  size_t len, u8 ds)
{
	int ret;
	struct sk_buff *skb;

	wg_dbg("Entering function wg_socket_send_buffer_to_peer peer=%px\n", peer);

	/* BUG FIX: null check peer BEFORE dereferencing it */
	if (unlikely(!peer) || unlikely(IS_ERR(peer))) {
		ret = -EINVAL;
		goto out;
	}

	log_wireguard_endpoint(&peer->endpoint);
	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);

	wg_dbg("Sending buffer to peer - Length: %zu, Data: %*ph\n",
		len, (int)len, buffer);
	if (unlikely(!skb)){
		ret = -ENOMEM;
		goto out;
	}

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	skb_put_data(skb, buffer, len);
	ret = wg_socket_send_skb_to_peer(peer, skb, ds);

out:
	wg_dbg("Exiting function wg_socket_send_buffer_to_peer\n");
	return ret;
}

int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb, void *buffer,
					  size_t len)
{
	wg_dbg("Entering function wg_socket_send_buffer_as_reply_to_skb\n");
	int ret = 0;
	struct sk_buff *skb;
	struct endpoint endpoint;

	if (unlikely(!in_skb))
		return -EINVAL;
	ret = wg_socket_endpoint_from_skb(&endpoint, in_skb);
	if (unlikely(ret < 0))
		return ret;

	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	skb_put_data(skb, buffer, len);

	ret = wg_socket_send_skb_to_endpoint(wg, skb, &endpoint, 0, NULL);

	wg_dbg("Exiting function wg_socket_send_buffer_as_reply_to_skb\n");
	return ret;
}


int wg_socket_endpoint_from_skb(struct endpoint *endpoint, const struct sk_buff *skb)
{
	wg_dbg("Entering function wg_socket_endpoint_from_skb\n");

	wg_dbg("skb data: %*ph\n", min_t(int, skb->len, 128), skb->data);

	memset(endpoint, 0, sizeof(*endpoint));
	if (skb->protocol == htons(ETH_P_IP)) {
		endpoint->addr4.sin_family = AF_INET;
		endpoint->addr4.sin_port = udp_hdr(skb)->source;
		endpoint->addr4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		endpoint->src4.s_addr = ip_hdr(skb)->daddr;
		endpoint->src_if4 = skb->skb_iif;
		wg_dbg("wg_socket_endpoint_from_skb: Extracted IPv4 address %pI4:%d\n",
		       &endpoint->addr4.sin_addr, ntohs(endpoint->addr4.sin_port));
	} else if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6)) {
		endpoint->addr6.sin6_family = AF_INET6;
		endpoint->addr6.sin6_port = udp_hdr(skb)->source;
		endpoint->addr6.sin6_addr = ipv6_hdr(skb)->saddr;
		endpoint->addr6.sin6_scope_id = ipv6_iface_scope_id(&ipv6_hdr(skb)->saddr, skb->skb_iif);
		endpoint->src6 = ipv6_hdr(skb)->daddr;
		wg_dbg("wg_socket_endpoint_from_skb: Extracted IPv6 address %pI6c:%d\n",
		       &endpoint->addr6.sin6_addr, ntohs(endpoint->addr6.sin6_port));
	} else {
		return -EINVAL;
	}


	wg_dbg("Exiting function wg_socket_endpoint_from_skb\n");
	return 0;
}

bool endpoint_eq(const struct endpoint *a, const struct endpoint *b)
{
	wg_dbg("Entering function endpoint_eq\n");
	wg_dbg("Exiting function endpoint_eq\n");
	return (a->addr.sa_family == AF_INET && b->addr.sa_family == AF_INET &&
		a->addr4.sin_port == b->addr4.sin_port &&
		a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr &&
		a->src4.s_addr == b->src4.s_addr && a->src_if4 == b->src_if4) ||
	       (a->addr.sa_family == AF_INET6 &&
		b->addr.sa_family == AF_INET6 &&
		a->addr6.sin6_port == b->addr6.sin6_port &&
		ipv6_addr_equal(&a->addr6.sin6_addr, &b->addr6.sin6_addr) &&
		a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&
		ipv6_addr_equal(&a->src6, &b->src6)) ||
	       unlikely(!a->addr.sa_family && !b->addr.sa_family);
}
static void sock_free(struct sock *sock)
{
	wg_dbg("Entering function sock_free\n");
	if (unlikely(!sock))
		return;
	sk_clear_memalloc(sock);
	udp_tunnel_sock_release(sock->sk_socket);
	wg_dbg("Exiting function sock_free\n");
}

static void set_sock_opts(struct socket *sock)
{
	wg_dbg("Entering function set_sock_opts\n");
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
	wg_dbg("Exiting function set_sock_opts\n");
}

static int wg_udp_receive(struct sock *sk, struct sk_buff *skb)
{
	struct wg_device *wg;

	if (unlikely(!sk))
		goto err;
	wg = READ_ONCE(sk->sk_user_data);
	if (unlikely(!wg))
		goto err;
	skb_mark_not_on_list(skb);
	wg_packet_receive(wg, skb);
	return 0;

err:
	kfree_skb(skb);
	return 0;
}

int wg_socket_init(struct wg_device *wg, u16 port)
{
	wg_dbg("Entering function wg_socket_init\n");
	struct net *net;
	int ret;
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_udp_receive
	};
	struct socket *new4 = NULL, *new6 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(port),
		.use_udp_checksums = true
	};
#if IS_ENABLED(CONFIG_IPV6)
	int retries = 0;
	struct udp_port_cfg port6 = {
		.family = AF_INET6,
		.local_ip6 = IN6ADDR_ANY_INIT,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
		.ipv6_v6only = true
	};
#endif

	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net))
		return -ENONET;

#if IS_ENABLED(CONFIG_IPV6)
retry:
#endif

	ret = udp_sock_create(net, &port4, &new4);
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 socket\n", wg->dev->name);
		goto out;
	}
	set_sock_opts(new4);

	setup_udp_tunnel_sock(net, new4, &cfg);

#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6_mod_enabled()) {
		port6.local_udp_port = inet_sk(new4->sk)->inet_sport;
		ret = udp_sock_create(net, &port6, &new6);
		if (ret < 0) {
			udp_tunnel_sock_release(new4);
			if (ret == -EADDRINUSE && !port && retries++ < 100)
				goto retry;
			pr_err("%s: Could not create IPv6 socket\n",
			       wg->dev->name);
			goto out;
		}
		set_sock_opts(new6);

		/* Setup the IPv6 UDP tunnel socket with the same socket data */
		setup_udp_tunnel_sock(net, new6, &cfg);
	}
#endif

	wg_socket_reinit(wg, new4->sk, new6 ? new6->sk : NULL);
	ret = 0;
out:
	put_net(net);
	wg_dbg("Exiting function wg_socket_init\n");
	return ret;
}


void wg_socket_reinit(struct wg_device *wg, struct sock *new4,
		      struct sock *new6)
{
	wg_dbg("Entering function wg_socket_reinit\n");
	struct sock *old4, *old6;

	mutex_lock(&wg->socket_update_lock);
	old4 = rcu_dereference_protected(wg->sock4,
				lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6,
				lockdep_is_held(&wg->socket_update_lock));
	rcu_assign_pointer(wg->sock4, new4);
	rcu_assign_pointer(wg->sock6, new6);
	if (new4)
		wg->incoming_port = ntohs(inet_sk(new4)->inet_sport);
	mutex_unlock(&wg->socket_update_lock);
	synchronize_rcu();
	synchronize_net();
	sock_free(old4);
	sock_free(old6);
	wg_dbg("Exiting function wg_socket_reinit\n");
}

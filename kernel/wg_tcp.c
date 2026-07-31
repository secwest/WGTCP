// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2024-2026 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */
#include <linux/icmp.h>

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
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/ktime.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/syslog.h>
#include <linux/timer.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/lockdep.h>
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


#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)
#define WG_TCP_TEST_MAX_GARBAGE_PREFIX 64
#define WG_TCP_TEST_MAX_WRITE_DELAY_MS 1000

static unsigned int wg_tcp_test_max_send_bytes;
static unsigned int wg_tcp_test_garbage_prefix_bytes;
static unsigned int wg_tcp_test_queue_limit;
static unsigned int wg_tcp_test_write_delay_ms;
static atomic64_t wg_tcp_test_short_writes = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_test_injected_prefixes = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_test_resyncs = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_test_queue_drops = ATOMIC64_INIT(0);

module_param_named(tcp_test_max_send_bytes, wg_tcp_test_max_send_bytes,
		   uint, 0600);
MODULE_PARM_DESC(tcp_test_max_send_bytes,
		 "DEBUG only: cap each TCP sendmsg request to force short writes");
module_param_named(tcp_test_garbage_prefix_bytes,
		   wg_tcp_test_garbage_prefix_bytes, uint, 0600);
MODULE_PARM_DESC(tcp_test_garbage_prefix_bytes,
		 "DEBUG only: prepend bounded garbage to each TCP record");
module_param_named(tcp_test_queue_limit, wg_tcp_test_queue_limit, uint, 0600);
MODULE_PARM_DESC(tcp_test_queue_limit,
		 "DEBUG only: lower the per-peer TCP frame queue limit");
module_param_named(tcp_test_write_delay_ms, wg_tcp_test_write_delay_ms,
		   uint, 0600);
MODULE_PARM_DESC(tcp_test_write_delay_ms,
		 "DEBUG only: delay the next serial TCP writer to force queue pressure");

static int wg_tcp_test_counter_get(char *buffer,
				   const struct kernel_param *parameter)
{
	const atomic64_t *counter = parameter->arg;

	return scnprintf(buffer, PAGE_SIZE, "%lld\n",
			 (long long)atomic64_read(counter));
}

static const struct kernel_param_ops wg_tcp_test_counter_ops = {
	.get = wg_tcp_test_counter_get,
};

module_param_cb(tcp_test_short_writes, &wg_tcp_test_counter_ops,
		&wg_tcp_test_short_writes, 0400);
MODULE_PARM_DESC(tcp_test_short_writes,
		 "DEBUG only: number of observed partial TCP writes");
module_param_cb(tcp_test_injected_prefixes, &wg_tcp_test_counter_ops,
		&wg_tcp_test_injected_prefixes, 0400);
MODULE_PARM_DESC(tcp_test_injected_prefixes,
		 "DEBUG only: number of TCP records prefixed with test garbage");
module_param_cb(tcp_test_resyncs, &wg_tcp_test_counter_ops,
		&wg_tcp_test_resyncs, 0400);
MODULE_PARM_DESC(tcp_test_resyncs,
		 "DEBUG only: number of successful TCP parser resynchronizations");
module_param_cb(tcp_test_queue_drops, &wg_tcp_test_counter_ops,
		&wg_tcp_test_queue_drops, 0400);
MODULE_PARM_DESC(tcp_test_queue_drops,
		 "DEBUG only: number of frames rejected by TCP queue pressure");

static size_t wg_tcp_test_send_len(size_t frame_len)
{
	unsigned int configured = READ_ONCE(wg_tcp_test_max_send_bytes);

	return configured ? min_t(size_t, configured, frame_len) : frame_len;
}

static size_t wg_tcp_test_prefix_len(void)
{
	return min_t(size_t, READ_ONCE(wg_tcp_test_garbage_prefix_bytes),
		     WG_TCP_TEST_MAX_GARBAGE_PREFIX);
}

static unsigned int wg_tcp_test_effective_queue_limit(void)
{
	unsigned int configured = READ_ONCE(wg_tcp_test_queue_limit);

	return configured && configured < MAX_QUEUED_PACKETS ?
		configured : MAX_QUEUED_PACKETS;
}

static unsigned int wg_tcp_test_take_write_delay_ms(void)
{
	return min_t(unsigned int, xchg(&wg_tcp_test_write_delay_ms, 0U),
		     WG_TCP_TEST_MAX_WRITE_DELAY_MS);
}
#else
static size_t wg_tcp_test_send_len(size_t frame_len)
{
	return frame_len;
}

static size_t wg_tcp_test_prefix_len(void)
{
	return 0;
}

static unsigned int wg_tcp_test_effective_queue_limit(void)
{
	return MAX_QUEUED_PACKETS;
}

static unsigned int wg_tcp_test_take_write_delay_ms(void)
{
	return 0;
}
#endif

#define WG_TCP_MAX_PENDING_CONNECTIONS 128
#define WG_TCP_MAX_TRACKED_CONNECTIONS 1024
#define WG_TCP_AUTH_IDLE_TIMEOUT_MS 5000
#define WG_TCP_AUTH_MAX_LIFETIME_MS 30000
#define WG_TCP_CLEANUP_INTERVAL_MS 1000
#define WG_TCP_MAX_PENDING_PER_SOURCE 8
#define WG_TCP_ACCEPT_BURST 32
#define WG_TCP_ACCEPT_WINDOW HZ

static void wg_finish_tcp_connection_init(struct wg_device *wg,
					  struct socket *socket);
static void wg_destroy_temp_peer(struct wg_peer *peer);
static void wg_touch_tcp_connection(struct wg_peer *peer);

void wg_setup_tcp_socket_callbacks(struct wg_peer *peer, bool inbound);
void wg_reset_tcp_socket_callbacks(struct wg_peer *peer, bool inbound);
void wg_get_endpoint_from_socket(struct socket *epsocket, struct endpoint *ep);
static __be16 wg_header_checksum(const struct wg_tcp_encap_header *hdr);
static void wg_tcp_mark_connection_authenticated(struct wg_device *wg,
						 u64 connection_id);

static struct sk_buff *wg_tcp_build_frame(const struct sk_buff *payload)
{
	struct wg_tcp_encap_header encap_header = {
		.type = WG_TCP_RECORD_DATA,
		.flags = 0
	};
	struct wg_tcp_frag_header frag_header;
	struct sk_buff *frame;
	bool fragmented = PACKET_CB(payload)->frag_off != 0;
	size_t header_len = WG_TCP_ENCAP_HDR_LEN;
	size_t prefix_len = wg_tcp_test_prefix_len();
	size_t total_len;

	if (payload->len < MESSAGE_MINIMUM_LENGTH)
		return ERR_PTR(-EINVAL);
	if (fragmented) {
		encap_header.flags = WG_TCP_FRAG_FLAG;
		frag_header.id = PACKET_CB(payload)->frag_id;
		frag_header.frag_off = PACKET_CB(payload)->frag_off;
		header_len += WG_TCP_FRAG_HDR_LEN;
	}
	if (payload->len > WG_MAX_PACKET_SIZE - header_len)
		return ERR_PTR(-EMSGSIZE);

	total_len = header_len + payload->len;
	encap_header.length = htonl(total_len);
	encap_header.checksum = wg_header_checksum(&encap_header);
	frame = alloc_skb(prefix_len + total_len, GFP_ATOMIC);
	if (!frame)
		return ERR_PTR(-ENOMEM);

	if (prefix_len) {
		/* Any candidate beginning in this prefix has 0xa5 as the high byte
		 * of its network-order length, so it cannot pass the bounded header
		 * validator even when the candidate overlaps the real header.
		 */
		memset(skb_put(frame, prefix_len), 0xa5, prefix_len);
#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)
		atomic64_inc(&wg_tcp_test_injected_prefixes);
#endif
	}
	skb_put_data(frame, &encap_header, WG_TCP_ENCAP_HDR_LEN);
	if (fragmented)
		skb_put_data(frame, &frag_header, WG_TCP_FRAG_HDR_LEN);
	if (skb_copy_bits(payload, 0, skb_put(frame, payload->len),
			  payload->len)) {
		kfree_skb(frame);
		return ERR_PTR(-EINVAL);
	}
	return frame;
}

/* Queue the serial writer while holding the same lifetime lock used to claim
 * socket removal. queue_work() stays inside tcp_lock so teardown cannot set a
 * removal flag, finish cancel_work_sync(), and release the socket before the
 * newly claimed work is visible to the workqueue.
 */
static void wg_tcp_schedule_write_locked(struct wg_peer *peer)
{
	lockdep_assert_held(&peer->tcp_lock);
	spin_lock(&peer->tcp_write_lock);
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled && peer->peer_socket &&
	    peer->tcp_established && peer->tcp_write_wq &&
	    !peer->tcp_write_worker_scheduled) {
		peer->tcp_write_worker_scheduled = true;
		queue_work(peer->tcp_write_wq, &peer->tcp_write_work);
	}
	spin_unlock(&peer->tcp_write_lock);

}

static void wg_tcp_schedule_write(struct wg_peer *peer)
{
	if (!peer || IS_ERR(peer))
		return;

	spin_lock_bh(&peer->tcp_lock);
	wg_tcp_schedule_write_locked(peer);
	spin_unlock_bh(&peer->tcp_lock);
}

static int wg_tcp_enqueue_frame(struct wg_peer *peer, struct sk_buff *frame)
{
	unsigned int queue_limit = wg_tcp_test_effective_queue_limit();
	int ret = 0;

	/* The queue and writer claim share the peer lifetime lock. Once stop sets
	 * tcp_stopping, no producer can append a frame or queue work after the
	 * final cancellation pass.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP ||
	    !peer->peer_socket || !peer->tcp_established ||
	    peer->tcp_outbound_remove_scheduled ||
	    peer->tcp_inbound_remove_scheduled) {
		ret = -ENOTCONN;
		goto unlock_tcp;
	}

	spin_lock(&peer->send_queue_lock);
	/* Preserve stream order. In particular, the head can contain the
	 * unconsumed suffix of a frame whose prefix is already on the wire.
	 */
	if (skb_queue_len(&peer->send_queue) >= queue_limit) {
		ret = -ENOBUFS;
#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)
		atomic64_inc(&wg_tcp_test_queue_drops);
#endif
	} else {
		__skb_queue_tail(&peer->send_queue, frame);
	}
	spin_unlock(&peer->send_queue_lock);
	if (!ret)
		wg_tcp_schedule_write_locked(peer);

unlock_tcp:
	spin_unlock_bh(&peer->tcp_lock);

	if (ret) {
		kfree_skb(frame);
		return ret;
	}
	return 0;
}

int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds)
{
	wg_dbg("Entering function wg_socket_send_skb_to_peer\n");
	size_t skb_len;
	int ret = -EAFNOSUPPORT;
	bool tcp_connected = false;

	if (unlikely(!peer) || unlikely(IS_ERR(peer))){
		ret = -EINVAL;
		goto out;
	}
	if (unlikely(!skb)){
		ret = -ENOMEM;
		goto out;
	}
	skb_len = skb->len;

	print_peer_socket_info(peer);

	if (peer->device->transport == WG_TRANSPORT_TCP) {
		spin_lock_bh(&peer->tcp_lock);
		tcp_connected = !READ_ONCE(peer->is_dead) &&
			!peer->tcp_stopping &&
			READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
			peer->peer_socket && peer->tcp_established &&
			!peer->tcp_outbound_remove_scheduled &&
			!peer->tcp_inbound_remove_scheduled;
		spin_unlock_bh(&peer->tcp_lock);
		if (likely(tcp_connected)) {
			struct sk_buff *frame = wg_tcp_build_frame(skb);

			kfree_skb(skb);
			if (IS_ERR(frame))
				ret = PTR_ERR(frame);
			else
				ret = wg_tcp_enqueue_frame(peer, frame);
		} else {
			ret = -ENOTCONN;
			spin_lock_bh(&peer->tcp_lock);
			if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
			    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
			    peer->device->transport == WG_TRANSPORT_TCP &&
			    peer->peer_endpoint_set && !peer->tcp_retry_scheduled &&
			    !peer->tcp_outbound_remove_scheduled) {
				peer->tcp_retry_scheduled = true;
				mod_delayed_work(system_wq, &peer->tcp_retry_work, 0);
			}
			spin_unlock_bh(&peer->tcp_lock);
			net_dbg_ratelimited("%s: TCP peer %llu is reconnecting\n",
					    peer->device->dev->name,
					    peer->internal_id);
			kfree_skb(skb);
		}
	} else {
		read_lock_bh(&peer->endpoint_lock);
		ret = wg_socket_send_skb_to_endpoint(peer->device, skb,
						     &peer->endpoint, ds,
						     &peer->endpoint_cache);
		read_unlock_bh(&peer->endpoint_lock);
	}
	if (ret == 0)
		peer->tx_bytes += skb_len;
out:
	wg_dbg("Exiting function wg_socket_send_skb_to_peer\n");
	return ret;

}
static bool wg_tcp_dial_target_eq(const struct endpoint *a,
				  const struct endpoint *b)
{
	if (a->addr.sa_family != b->addr.sa_family)
		return false;
	if (a->addr.sa_family == AF_INET)
		return a->addr4.sin_port == b->addr4.sin_port &&
		       a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr;
#if IS_ENABLED(CONFIG_IPV6)
	if (a->addr.sa_family == AF_INET6)
		return a->addr6.sin6_port == b->addr6.sin6_port &&
		       ipv6_addr_equal(&a->addr6.sin6_addr,
				       &b->addr6.sin6_addr) &&
		       a->addr6.sin6_scope_id == b->addr6.sin6_scope_id;
#endif
	return false;
}

static void wg_release_peer_tcp_connection(struct wg_peer *peer);

static void wg_tcp_peer_request_reconnect_after(struct wg_peer *peer,
						 unsigned long delay)
{
	bool queue_outbound_remove = false;

	if (!peer || IS_ERR(peer) || !peer->device)
		return;

	/* This helper is callable from authenticated receive/NAPI context. Claim
	 * and queue the process-context removal owner without shutting down the
	 * socket inline. Queueing under tcp_lock closes the race with peer stop
	 * setting its barrier and draining this work item.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP ||
	    !netif_running(peer->device->dev) || !peer->peer_endpoint_set) {
		spin_unlock_bh(&peer->tcp_lock);
		return;
	}
	peer->tcp_reconnect_requested = true;
	if (!peer->tcp_connecting && !peer->tcp_outbound_remove_scheduled) {
		peer->tcp_outbound_remove_scheduled = true;
		peer->tcp_outbound_remove_socket = peer->outbound_socket;
		queue_outbound_remove = true;
	}
	if (queue_outbound_remove)
		mod_delayed_work(system_wq, &peer->tcp_outbound_remove_work,
				 delay);
	spin_unlock_bh(&peer->tcp_lock);
}

void wg_tcp_peer_request_reconnect(struct wg_peer *peer)
{
	wg_tcp_peer_request_reconnect_after(peer, 0);
}

static void wg_socket_set_peer_endpoint_internal(struct wg_peer *peer,
						 const struct endpoint *endpoint,
						 bool configured)
{
	bool tcp_target_changed = false;

	wg_dbg("Entering function wg_socket_set_peer_endpoint peer=%px\n", peer);
	if (unlikely(!peer) || unlikely(IS_ERR(peer))){
		goto out;
	}

	/* First we check unlocked, in order to optimize, since it's pretty rare
	 * that an endpoint will change. If we happen to be mid-write, and two
	 * CPUs wind up writing the same thing or something slightly different,
	 * it doesn't really matter much either.
	 */
	if (endpoint_eq(endpoint, &peer->endpoint) &&
	    (!configured || peer->device->transport != WG_TRANSPORT_TCP ||
	     (peer->peer_endpoint_set &&
	      endpoint_eq(endpoint, &peer->peer_endpoint)))) {
		wg_dbg("Exiting function wg_socket_set_peer_endpoint (no change in endpoint)\n");
		return;
	}

	print_peer_socket_info(peer);

	write_lock_bh(&peer->endpoint_lock);
	if (endpoint->addr.sa_family == AF_INET) {
		wg_dbg("Setting endpoint address: %pI4:%d\n",
		       &endpoint->addr4.sin_addr,
		       ntohs(endpoint->addr4.sin_port));
		peer->endpoint.addr4 = endpoint->addr4;
		peer->endpoint.src4 = endpoint->src4;
		peer->endpoint.src_if4 = endpoint->src_if4;
	} else if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6) {
		wg_dbg("Setting endpoint address: [%pI6]:%d\n",
		       &endpoint->addr6.sin6_addr,
		       ntohs(endpoint->addr6.sin6_port));
		peer->endpoint.addr6 = endpoint->addr6;
		peer->endpoint.src6 = endpoint->src6;
	} else {
		write_unlock_bh(&peer->endpoint_lock);
		goto out;
	}
	dst_cache_reset(&peer->endpoint_cache);
	if (peer->device->transport == WG_TRANSPORT_TCP) {
		peer->tcp_reply_endpoint = peer->endpoint;
		if (configured) {
			tcp_target_changed = peer->peer_endpoint_set &&
				!endpoint_eq(&peer->peer_endpoint, &peer->endpoint);
			peer->peer_endpoint = peer->endpoint;
			peer->tcp_peer_listen_port =
				peer->endpoint.addr.sa_family == AF_INET ?
				peer->endpoint.addr4.sin_port :
				peer->endpoint.addr6.sin6_port;
			peer->peer_endpoint_set = true;
		}
	}
	write_unlock_bh(&peer->endpoint_lock);
	if (peer->device->transport != WG_TRANSPORT_TCP || !configured)
		goto out;

	wg_dbg("Peer Endpoint:\n");
	log_wireguard_endpoint(&peer->endpoint);
	wg_dbg("TCP Reply Endpoint:\n");
	log_wireguard_endpoint(&peer->tcp_reply_endpoint);

	/* A configured target change owns the reconnect request. Mark removal
	 * before shutdown so the state callback cannot race us to queue a second
	 * owner for the same socket. The removal worker releases the old stream
	 * before it arms an immediate reconnect.
	 */
	if (tcp_target_changed) {
		wg_tcp_peer_request_reconnect(peer);
	} else if (netif_running(peer->device->dev) &&
		   !peer->tcp_established) {
		wg_tcp_connect(peer);
	}

out:
	wg_dbg("Exiting function wg_socket_set_peer_endpoint\n");
}

void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint)
{
	wg_socket_set_peer_endpoint_internal(peer, endpoint, false);
}

void wg_socket_set_peer_endpoint_configured(struct wg_peer *peer,
					    const struct endpoint *endpoint)
{
	wg_socket_set_peer_endpoint_internal(peer, endpoint, true);
}

void wg_socket_set_peer_endpoint_authenticated(struct wg_peer *peer,
					       const struct endpoint *endpoint,
					       u64 connection_id)
{
	struct endpoint target;
	bool target_changed = false;

	if (unlikely(!peer) || unlikely(IS_ERR(peer)) || unlikely(!endpoint))
		return;

	/* Keep the complete live tuple as observed state. For TCP, only the
	 * authenticated remote address may refresh the future dial target: an
	 * accepted socket's remote port is normally ephemeral and must never
	 * replace the operator-configured peer listen port.
	 */
	wg_socket_set_peer_endpoint(peer, endpoint);
	if (peer->device->transport != WG_TRANSPORT_TCP)
		return;
	wg_tcp_mark_connection_authenticated(peer->device, connection_id);

	write_lock_bh(&peer->endpoint_lock);
	/* Only authenticated accepted carriers have a nonzero, device-monotonic
	 * ID. Advancing the generation even when the address is unchanged keeps
	 * an older retained stream from reverting a later roaming observation.
	 */
	if (!peer->peer_endpoint_set || !connection_id ||
	    connection_id <= peer->tcp_roaming_connection_id)
		goto out;
	target = *endpoint;
	if (target.addr.sa_family == AF_INET) {
		target.addr4.sin_port = peer->tcp_peer_listen_port;
		target.src4.s_addr = 0;
		target.src_if4 = 0;
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   target.addr.sa_family == AF_INET6) {
		target.addr6.sin6_port = peer->tcp_peer_listen_port;
		memset(&target.src6, 0, sizeof(target.src6));
	} else {
		goto out;
	}
	peer->tcp_roaming_connection_id = connection_id;
	if (!wg_tcp_dial_target_eq(&peer->peer_endpoint, &target)) {
		peer->peer_endpoint = target;
		dst_cache_reset(&peer->endpoint_cache);
		target_changed = true;
	}
out:
	write_unlock_bh(&peer->endpoint_lock);
	if (target_changed && !peer->temp_peer)
		wg_tcp_peer_request_reconnect_after(peer,
					msecs_to_jiffies(100));
}

void wg_socket_set_peer_endpoint_authenticated_from_skb(
	struct wg_peer *peer, const struct sk_buff *skb)
{
	struct endpoint endpoint;

	if (likely(!wg_socket_endpoint_from_skb(&endpoint, skb)))
		wg_socket_set_peer_endpoint_authenticated(
			peer, &endpoint, PACKET_CB(skb)->tcp_connection_id);
}

void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb)
{
	wg_dbg("Entering function wg_socket_set_peer_endpoint_from_skb peer=%px\n", peer);
	struct endpoint endpoint;

	if (unlikely(!peer) || unlikely(IS_ERR(peer))){
		goto out;
	}

	if (!wg_socket_endpoint_from_skb(&endpoint, skb))
		wg_socket_set_peer_endpoint(peer, &endpoint);
	log_wireguard_endpoint(&peer->endpoint);
	print_peer_socket_info(peer);
out:
	wg_dbg("Exiting function wg_socket_set_peer_endpoint_from_skb\n");
}

void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer)
{
	wg_dbg("Entering function wg_socket_clear_peer_endpoint_src\n");
	write_lock_bh(&peer->endpoint_lock);
	memset(&peer->endpoint.src6, 0, sizeof(peer->endpoint.src6));
	dst_cache_reset_now(&peer->endpoint_cache);
	write_unlock_bh(&peer->endpoint_lock);
	wg_dbg("Exiting function wg_socket_clear_peer_endpoint_src\n");
}

static int wg_receive(struct sock *sk, struct sk_buff *skb)
{
	wg_dbg("Entering function wg_receive\n");
	struct wg_device *wg;
	struct wg_socket_data *socket_data = NULL;

	if (unlikely(!sk))
		goto err;
	if (sk->sk_protocol == IPPROTO_TCP) {
		socket_data = READ_ONCE(sk->sk_user_data);

		if (unlikely(!socket_data))
			goto err;
		wg = socket_data->device;
	} else {
		wg = READ_ONCE(sk->sk_user_data);
	}
	if (unlikely(!wg))
		goto err;
	PACKET_CB(skb)->outer_ipproto = sk->sk_protocol;
	PACKET_CB(skb)->tcp_connection_id =
		socket_data && socket_data->peer && socket_data->peer->temp_peer ?
			socket_data->peer->tcp_connection_id : 0;
	skb_mark_not_on_list(skb);
	wg_packet_receive(wg, skb);
	wg_dbg("Exiting function wg_receive\n");
	return 0;

err:
	kfree_skb(skb);
	wg_dbg("Exiting function wg_receive with error.\n");
	return 0;
}
static int wg_set_socket_timeouts(struct socket *sock, unsigned long snd_timeout,
				  unsigned long rcv_timeout)
{
	wg_dbg("Entering function wg_set_socket_timeouts\n");
	if (!sock || !sock->sk) {
		pr_err("Invalid socket or sock is NULL\n");
		return -EINVAL;
	}

	struct sock *sk = sock->sk;

	sk->sk_sndtimeo = snd_timeout*30;
	sk->sk_rcvtimeo = rcv_timeout*30;

	wg_dbg("Exiting function wg_set_socket_timeouts\n");
	return 0;
}

static bool wg_sockaddrs_match(const struct sockaddr *a,
			       const struct sockaddr *b)
{
	if (!a || !b || a->sa_family != b->sa_family)
		return false;

	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

		return a4->sin_port == b4->sin_port &&
		       a4->sin_addr.s_addr == b4->sin_addr.s_addr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
		const bool a_link_local =
			ipv6_addr_type(&a6->sin6_addr) & IPV6_ADDR_LINKLOCAL;
		const bool b_link_local =
			ipv6_addr_type(&b6->sin6_addr) & IPV6_ADDR_LINKLOCAL;

		return a6->sin6_port == b6->sin6_port &&
		       ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		       (!a_link_local || !b_link_local ||
			a6->sin6_scope_id == b6->sin6_scope_id);
	}
#endif
	return false;
}

static bool wg_sockaddrs_same_host(const struct sockaddr *a,
				   const struct sockaddr *b)
{
	if (!a || !b || a->sa_family != b->sa_family)
		return false;

	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

		return a4->sin_addr.s_addr == b4->sin_addr.s_addr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
		const bool link_local =
			ipv6_addr_type(&a6->sin6_addr) & IPV6_ADDR_LINKLOCAL;

		return ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		       (!link_local || a6->sin6_scope_id == b6->sin6_scope_id);
	}
#endif
	return false;
}

static bool wg_sockaddr_length_valid(const struct sockaddr *addr, int length)
{
	if (!addr)
		return false;
	if (addr->sa_family == AF_INET)
		return length >= sizeof(struct sockaddr_in);
#if IS_ENABLED(CONFIG_IPV6)
	if (addr->sa_family == AF_INET6)
		return length >= sizeof(struct sockaddr_in6);
#endif
	return false;
}

static bool wg_endpoints_match(const struct endpoint *a,
			       const struct endpoint *b)
{
	return a && b && wg_sockaddrs_match(&a->addr, &b->addr);
}

static bool wg_tcp_accept_source_matches(
	const struct wg_tcp_accept_source *source, const struct sockaddr *addr)
{
	if (!source || !addr || source->family != addr->sa_family)
		return false;
	if (addr->sa_family == AF_INET)
		return source->address.addr4 ==
		       ((const struct sockaddr_in *)addr)->sin_addr.s_addr;
#if IS_ENABLED(CONFIG_IPV6)
	if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 =
			(const struct sockaddr_in6 *)addr;
		const bool link_local =
			ipv6_addr_type(&addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL;

		return ipv6_addr_equal(&source->address.addr6,
				       &addr6->sin6_addr) &&
		       (!link_local || source->scope_id == addr6->sin6_scope_id);
	}
#endif
	return false;
}

static void wg_tcp_accept_source_set(struct wg_tcp_accept_source *source,
				     const struct sockaddr *addr,
				     unsigned long now)
{
	memset(source, 0, sizeof(*source));
	source->family = addr->sa_family;
	if (addr->sa_family == AF_INET) {
		source->address.addr4 =
			((const struct sockaddr_in *)addr)->sin_addr.s_addr;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *addr6 =
			(const struct sockaddr_in6 *)addr;

		source->address.addr6 = addr6->sin6_addr;
		if (ipv6_addr_type(&addr6->sin6_addr) & IPV6_ADDR_LINKLOCAL)
			source->scope_id = addr6->sin6_scope_id;
#endif
	}
	source->window_started = now;
	source->last_seen = now;
	source->accepts = 1;
}

/* Bound rapid provisional-peer creation without allocating attacker-owned
 * tracking state. The fixed table is deliberately lossy under a many-source
 * flood; the device-wide pending cap remains the final backstop.
 */
static bool wg_tcp_accept_rate_allow(struct wg_device *wg,
				     const struct sockaddr *addr)
{
	struct wg_tcp_accept_source *empty = NULL, *oldest = NULL, *source = NULL;
	const unsigned long now = jiffies;
	bool allowed = true;
	unsigned int i;

	if (!wg || !addr || (addr->sa_family != AF_INET &&
			       addr->sa_family != AF_INET6))
		return false;

	spin_lock_bh(&wg->tcp_accept_lock);
	for (i = 0; i < WG_TCP_ACCEPT_SOURCE_SLOTS; ++i) {
		struct wg_tcp_accept_source *candidate =
			&wg->tcp_accept_sources[i];

		if (!candidate->family) {
			if (!empty)
				empty = candidate;
			continue;
		}
		if (wg_tcp_accept_source_matches(candidate, addr)) {
			source = candidate;
			break;
		}
		if (!oldest || time_before(candidate->last_seen,
					   oldest->last_seen))
			oldest = candidate;
	}

	if (!source) {
		source = empty ? empty : oldest;
		wg_tcp_accept_source_set(source, addr, now);
	} else if (time_after_eq(now, source->window_started +
					 WG_TCP_ACCEPT_WINDOW)) {
		wg_tcp_accept_source_set(source, addr, now);
	} else if (source->accepts >= WG_TCP_ACCEPT_BURST) {
		source->last_seen = now;
		allowed = false;
	} else {
		++source->accepts;
		source->last_seen = now;
	}
	spin_unlock_bh(&wg->tcp_accept_lock);
	return allowed;
}

static unsigned int
wg_tcp_pending_from_source_locked(struct wg_device *wg,
				  const struct sockaddr *addr)
{
	struct wg_tcp_socket_list_entry *entry;
	unsigned int count = 0;

	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (entry->admission_counted &&
		    wg_sockaddrs_same_host(
			    addr, (const struct sockaddr *)&entry->src_addr))
			++count;
	}
	return count;
}

static bool wg_tcp_source_at_capacity(struct wg_device *wg,
				      const struct sockaddr *addr)
{
	bool at_capacity;

	spin_lock_bh(&wg->tcp_connection_list_lock);
	at_capacity = wg_tcp_pending_from_source_locked(wg, addr) >=
		      WG_TCP_MAX_PENDING_PER_SOURCE;
	spin_unlock_bh(&wg->tcp_connection_list_lock);
	return at_capacity;
}

static void
wg_tcp_release_admission_locked(struct wg_device *wg,
				struct wg_tcp_socket_list_entry *entry)
{
	lockdep_assert_held(&wg->tcp_connection_list_lock);
	if (!entry->admission_counted)
		return;
	entry->admission_counted = false;
	if (WARN_ON_ONCE(!wg->tcp_pending_connections))
		return;
	--wg->tcp_pending_connections;
}

static void wg_tcp_mark_connection_authenticated(struct wg_device *wg,
					 u64 connection_id)
{
	struct wg_tcp_socket_list_entry *entry;

	if (!wg || !connection_id)
		return;
	spin_lock_bh(&wg->tcp_connection_list_lock);
	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (entry->connection_id != connection_id)
			continue;
		entry->authenticated = true;
		wg_tcp_release_admission_locked(wg, entry);
		entry->timestamp = ktime_get();
		break;
	}
	spin_unlock_bh(&wg->tcp_connection_list_lock);
}

void wg_tcp_set_device_mark(struct wg_device *wg, u32 mark)
{
	struct wg_tcp_socket_list_entry *entry;

	if (!wg)
		return;
	if (wg->tcp_listen_socket4 && wg->tcp_listen_socket4->sk)
		WRITE_ONCE(wg->tcp_listen_socket4->sk->sk_mark, mark);
#if IS_ENABLED(CONFIG_IPV6)
	if (wg->tcp_listen_socket6 && wg->tcp_listen_socket6->sk)
		WRITE_ONCE(wg->tcp_listen_socket6->sk->sk_mark, mark);
#endif

	/* Accepted carriers stay device-owned until cleanup or promotion. The
	 * list lock keeps each socket alive while its mark is refreshed.
	 */
	spin_lock_bh(&wg->tcp_connection_list_lock);
	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (entry->tcp_socket && entry->tcp_socket->sk)
			WRITE_ONCE(entry->tcp_socket->sk->sk_mark, mark);
	}
	spin_unlock_bh(&wg->tcp_connection_list_lock);
}

void wg_free_peer_socket_data(struct wg_peer *peer);

void wg_free_peer_socket_data(struct wg_peer *peer)
{
	if (peer && !IS_ERR(peer))
		if (peer->peer_socket)
			if (peer->peer_socket->sk)
				if (peer->peer_socket->sk->sk_user_data)
					kfree(peer->peer_socket->sk->sk_user_data);
}



void wg_clean_peer_socket(struct wg_peer *peer, bool release, bool destroy, bool inbound)
{
	wg_dbg("Entering function wg_clean_peer_socket peer=%px, inbound=%d\n", peer, inbound);
	if (!peer || IS_ERR(peer)) {
		wg_dbg("wg_clean_peer_socket: No peer or invalid peer.\n");
		goto out;
	}
	print_peer_socket_info(peer);
	if ((inbound && peer->peer_socket == peer->inbound_socket) ||
	    (!inbound && peer->peer_socket == peer->outbound_socket)) {
		/* Cleanup partial skb buffer */
		if (peer->partial_skb) {
			kfree_skb(peer->partial_skb);
			peer->partial_skb = NULL;
		}

		/* Cancel and flush the TCP read workqueue */
		if (peer->tcp_read_worker_scheduled) {
			cancel_work_sync(&peer->tcp_read_work);
			peer->tcp_read_worker_scheduled = false;
		}
		if (peer->tcp_read_wq && destroy) {
			destroy_workqueue(peer->tcp_read_wq);
			peer->tcp_read_wq = NULL;
		}

		/* Cancel and flush the TCP write workqueue */
		if (peer->tcp_write_worker_scheduled) {
			cancel_work_sync(&peer->tcp_write_work);
			peer->tcp_write_worker_scheduled = false;
		}
		if (peer->tcp_write_wq && destroy) {
			destroy_workqueue(peer->tcp_write_wq);
			peer->tcp_write_wq = NULL;
		}

		/* Clean up packet queues */
		if (!skb_queue_empty(&peer->send_queue))
			skb_queue_purge(&peer->send_queue);

		/* Reset TCP state */
		peer->received_len = 0;
		peer->expected_len = 0;
		peer->tcp_established = false;
		peer->tcp_pending = false;
		peer->tcp_retry_scheduled = false;
	}

	/* Determine which socket and related resources to clean based on the 'inbound' flag */
	struct socket **socket_to_clean = inbound ? &peer->inbound_socket : &peer->outbound_socket;
	bool *callbacks_set_flag = inbound ? &peer->tcp_inbound_callbacks_set : &peer->tcp_outbound_callbacks_set;
	bool *connected_flag = inbound ? &peer->inbound_connected : &peer->outbound_connected;
	ktime_t *timestamp = inbound ? &peer->inbound_timestamp : &peer->outbound_timestamp;
	/* Cleanup socket if necessary */
	if (*socket_to_clean) {
		if (peer->peer_socket == *socket_to_clean)
			peer->peer_socket = NULL;
		if (release) {
			/* Directly free peer socket data as per wg_free_peer_socket_data logic */
			if (*socket_to_clean && (*socket_to_clean)->sk) {
				if ((*socket_to_clean)->sk->sk_user_data) {
					kfree((*socket_to_clean)->sk->sk_user_data);
					(*socket_to_clean)->sk->sk_user_data = NULL;
				}
			}
			kernel_sock_shutdown(*socket_to_clean, SHUT_RDWR);
			sock_release(*socket_to_clean);
		}
		*socket_to_clean = NULL;
	}

	/* Reset callbacks set flag */
	*callbacks_set_flag = false;

	/* Reset connection status and timestamp */
	*connected_flag = false;
	*timestamp = 0;

out:
	print_peer_socket_info(peer);
	wg_dbg("Exiting wg_clean_peer_socket\n");
}

void wg_tcp_peer_stop(struct wg_peer *peer)
{
	struct socket *outbound, *inbound;
	struct sock *outbound_sk, *inbound_sk;

	if (!peer || IS_ERR(peer))
		return;

	spin_lock_bh(&peer->tcp_lock);
	peer->tcp_stopping = true;
	peer->tcp_reconnect_requested = false;
	peer->tcp_outbound_remove_scheduled = true;
	peer->tcp_outbound_remove_socket = peer->outbound_socket;
	peer->tcp_inbound_remove_scheduled = true;
	spin_unlock_bh(&peer->tcp_lock);

	/* Removal workers own socket destruction. Drain them before reading a
	 * socket pointer so stop cannot race sock_release() with a callback-lock
	 * snapshot. The stop barrier above prevents any peer-owned work from
	 * being queued after these cancellation passes.
	 */
	cancel_delayed_work_sync(&peer->tcp_retry_work);
	cancel_delayed_work_sync(&peer->tcp_outbound_remove_work);
	cancel_delayed_work_sync(&peer->tcp_inbound_remove_work);

	/* A removal worker that was already running can publish its completion
	 * while the cancellation waits. Reassert the stop claims before socket
	 * snapshotting so callbacks still see a closed scheduling gate.
	 */
	spin_lock_bh(&peer->tcp_lock);
	peer->tcp_outbound_remove_scheduled = true;
	peer->tcp_outbound_remove_socket = peer->outbound_socket;
	peer->tcp_inbound_remove_scheduled = true;
	outbound = peer->outbound_socket;
	inbound = peer->inbound_socket;
	spin_unlock_bh(&peer->tcp_lock);
	outbound_sk = outbound ? outbound->sk : NULL;
	inbound_sk = inbound ? inbound->sk : NULL;
	if (outbound_sk) {
		write_lock_bh(&outbound_sk->sk_callback_lock);
		write_unlock_bh(&outbound_sk->sk_callback_lock);
	}
	if (inbound_sk && inbound_sk != outbound_sk) {
		write_lock_bh(&inbound_sk->sk_callback_lock);
		write_unlock_bh(&inbound_sk->sk_callback_lock);
	}

	cancel_work_sync(&peer->tcp_read_work);
	cancel_work_sync(&peer->tcp_write_work);
	spin_lock_bh(&peer->tcp_lock);
	peer->tcp_retry_scheduled = false;
	spin_lock(&peer->tcp_read_lock);
	peer->tcp_read_worker_scheduled = false;
	spin_unlock(&peer->tcp_read_lock);
	spin_lock(&peer->tcp_write_lock);
	peer->tcp_write_worker_scheduled = false;
	spin_unlock(&peer->tcp_write_lock);
	spin_unlock_bh(&peer->tcp_lock);

	spin_lock_bh(&peer->send_queue_lock);
	__skb_queue_purge(&peer->send_queue);
	spin_unlock_bh(&peer->send_queue_lock);

	wg_reset_tcp_socket_callbacks(peer, false);
	wg_reset_tcp_socket_callbacks(peer, true);
	wg_clean_peer_socket(peer, true, false, false);
	wg_clean_peer_socket(peer, true, false, true);

	spin_lock_bh(&peer->tcp_lock);
	peer->tcp_established = false;
	peer->tcp_pending = false;
	peer->tcp_connecting = false;
	peer->tcp_reconnect_requested = false;
	peer->inbound_connected = false;
	peer->outbound_connected = false;
	peer->tcp_outbound_remove_scheduled = false;
	peer->tcp_outbound_remove_socket = NULL;
	peer->tcp_inbound_remove_scheduled = false;
	spin_unlock_bh(&peer->tcp_lock);
}


struct wg_peer *wg_temp_peer_create(struct wg_device *wg);
int wg_add_tcp_socket_to_list(struct wg_device *wg,
			      struct socket *receive_socket,
			      struct wg_peer *temp_peer);


/* Function to copy source and destination addresses from a TCP socket */
static int copy_sock_addresses(struct socket *tcp_socket,
			       struct sockaddr_storage *inbound_source,
			       struct sockaddr_storage *inbound_dest)
{
	int local_len, remote_len;

	if (!tcp_socket || !tcp_socket->sk || !inbound_source || !inbound_dest)
		return -EINVAL;

	memset(inbound_source, 0, sizeof(*inbound_source));
	memset(inbound_dest, 0, sizeof(*inbound_dest));
	local_len = kernel_getsockname(tcp_socket,
				       (struct sockaddr *)inbound_source);
	if (local_len < 0 ||
	    !wg_sockaddr_length_valid((struct sockaddr *)inbound_source,
					      local_len))
		return local_len < 0 ? local_len : -EINVAL;
	remote_len = kernel_getpeername(tcp_socket,
					 (struct sockaddr *)inbound_dest);
	if (remote_len < 0 ||
	    !wg_sockaddr_length_valid((struct sockaddr *)inbound_dest,
					      remote_len))
		return remote_len < 0 ? remote_len : -EINVAL;
	if (inbound_source->ss_family != inbound_dest->ss_family)
		return -EAFNOSUPPORT;

	return 0;
}

static struct wg_peer *wg_find_peer_by_endpoints(struct wg_device *wg, const struct endpoint *endpoint)
{
    struct wg_peer *peer = NULL;
    struct wg_peer *matched_peer = NULL;

    if (!wg || !endpoint) {
        printk(KERN_ERR "wg_find_peer_by_endpoints: Invalid arguments, wg or endpoint is NULL\n");
        return NULL;
    }

    wg_dbg("Entering function wg_find_peer_by_endpoints\n");

    rcu_read_lock();
    list_for_each_entry_rcu(peer, &wg->peer_list, peer_list) {
        if (endpoint_eq(&peer->endpoint, endpoint) ||
            endpoint_eq(&peer->peer_endpoint, endpoint) ||
            endpoint_eq(&peer->tcp_reply_endpoint, endpoint)) {
            matched_peer = peer;
            wg_dbg("wg_find_peer_by_endpoints: Found matching peer %px\n", matched_peer);
            break;
        }
    }
    rcu_read_unlock();

    if (!matched_peer) {
        wg_dbg("wg_find_peer_by_endpoints: No matching peer found\n");
    }

    wg_dbg("Exiting function wg_find_peer_by_endpoints peer=%px\n", matched_peer);
    return matched_peer;
}


int wg_tcp_listener_worker(struct wg_device *wg, struct socket *tcp_socket)
{
	bool found = false;
	wg_dbg("Entering function wg_tcp_listener_worker\n");
	struct socket *new_peer_connection = NULL;

	if (!tcp_socket) {
	pr_err("tcp_socket is NULL\n");
	return -EINVAL;
	}
	while (!kthread_should_stop()) {
		int err;

		err = kernel_accept(tcp_socket, &new_peer_connection, 0);
		if (err < 0) {
			if (kthread_should_stop() || err == -EINVAL || err == -EBADF ||
			    err == -ENOTCONN)
				break;
			if (err == -EAGAIN || err == -ERESTARTSYS)
				continue;
			pr_err("Error accepting new connection: %d\n", err);
		continue;
		}

		if (!new_peer_connection) {
			pr_err("new_peer_connection is NULL after kernel_accept\n");
			continue;
		}
		wg_dbg("wg_tcp_listener_worker accepted socket: %px new_peer_connection: %px\n", tcp_socket, &new_peer_connection);
		WRITE_ONCE(new_peer_connection->sk->sk_mark, wg->fwmark);

		/* FIX #4: Disable Nagle's algorithm on accepted socket to avoid
		 * ~200ms delayed ACK interaction that caused 1000ms RTT
		 */
		tcp_sock_set_nodelay(new_peer_connection->sk);

	        struct wg_peer *matched_peer = NULL;
		struct wg_peer *new_temp_peer = NULL;
	        struct endpoint new_endpoint;
		struct wg_tcp_socket_list_entry *socket_iter = NULL;
		struct wg_socket_data *socket_data = NULL; /* New structure for sk_user_data */
		struct socket *old_pending_socket = NULL;

		/* BUG FIX: reset found at the start of each iteration —
		 * was never reset, so after first match all subsequent
		 * connections incorrectly entered the 'found' branches
		 */
		found = false;

		memset(&new_endpoint, 0, sizeof(new_endpoint));
		err = new_peer_connection->ops->getname(
			new_peer_connection, &new_endpoint.addr, 1);
		if (err < 0 ||
		    !wg_sockaddr_length_valid(&new_endpoint.addr, err)) {
			pr_err("Could not read accepted TCP peer address: %d\n", err);
			kernel_sock_shutdown(new_peer_connection, SHUT_RDWR);
			sock_release(new_peer_connection);
			new_peer_connection = NULL;
			continue;
		}
		if (!wg_tcp_accept_rate_allow(wg, &new_endpoint.addr) ||
		    wg_tcp_source_at_capacity(wg, &new_endpoint.addr)) {
			pr_debug_ratelimited(
				"%s: throttling unauthenticated TCP source %pISpc\n",
				wg->dev->name, &new_endpoint.addr);
			kernel_sock_shutdown(new_peer_connection, SHUT_RDWR);
			sock_release(new_peer_connection);
			new_peer_connection = NULL;
			continue;
		}

		if (!list_empty(&wg->peer_list)) {
			/*
			 * Match the inbound connection to a configured peer
			 * endpoint.
			 */
			rcu_read_lock();
			list_for_each_entry_rcu(matched_peer, &wg->peer_list, peer_list) {
				if (wg_endpoints_match(&matched_peer->endpoint, &new_endpoint)) {
					/* read data if there is any available */
					found = true;
					wg_dbg("wg_tcp_listener_worker matched existing endpoint\n");
					break;
			}
			 }
			/* BUG FIX: after list_for_each_entry_rcu exhaustion (no break),
			 * matched_peer points to the list head (bogus pointer), not NULL.
			 * Reset to NULL when no match was found.
			 */
			if (!found)
				matched_peer = NULL;
			rcu_read_unlock();
		}
		if (found)
			if (!skb_queue_empty(&new_peer_connection->sk->sk_receive_queue)) {
				wg_dbg("wg_tcp_listener_worker found lingering data, calling wg_tcp_data_ready()\n");
				wg_tcp_data_ready(new_peer_connection->sk);
			}


		/* FIX: Both matched and unmatched peers need temp peer creation.
		 * Original code dropped unmatched connections as "martians" which
		 * prevented first TCP handshakes (endpoint unknown before handshake).
		 * Now: always create a temp peer for inbound connections so the
		 * handshake can be processed and the peer promoted.
		 */
		if (!matched_peer) {
			wg_dbg("wg_tcp_listener_worker no endpoint match — new inbound connection\n");
		} else {
			wg_dbg("wg_tcp_listener_worker matched existing endpoint — reconnection\n");
		}

		{
			/* Clean up any existing pending connection from same source */
			/* BUG FIX: reset found before second search */
			found = false;
			if (!list_empty(&wg->tcp_connection_list)) {  /* BUG FIX: was peer_list — wrong list */
				rcu_read_lock();
				/* check device pending connections in tcp_connection_list */
				list_for_each_entry_rcu(socket_iter, &wg->tcp_connection_list, tcp_connection_ll) {
					/*
					 * Skip entries without the socket state
					 * required for comparison.
					 */
					if (!socket_iter) {
						wg_dbg("socket_iter is NULL\n");
						continue;
					}
					if (!socket_iter->tcp_socket) {
						wg_dbg("socket_iter->tcp_socket is NULL\n");
						continue;
					}
					if (!socket_iter->tcp_socket->sk) {
						wg_dbg("socket_iter->tcp_socket->sk is NULL\n");
						continue;
					}

					if (wg_sockaddrs_match(
						    &new_endpoint.addr,
						    (const struct sockaddr *)&socket_iter->src_addr)) {
						found = true;
						old_pending_socket = socket_iter->tcp_socket;
						break;
					}
				}
				rcu_read_unlock();
			}
			if (found) {
				wg_dbg("wg_tcp_listener_worker new connection was for an existing peer\n");
				wg_remove_from_tcp_connection_list(wg, old_pending_socket);
			}

			/*
			 * Queue a provisional roaming connection for
			 * authentication.
			 */

			new_temp_peer = wg_temp_peer_create(wg);
			wg_dbg("wg_tcp_listener_worker created temp peer for inbound new connection temp_peer=%px\n", new_temp_peer);
			if (!IS_ERR(new_temp_peer) && new_temp_peer) {
				new_temp_peer->peer_socket = new_peer_connection;
				new_temp_peer->inbound_socket = new_peer_connection;
				/* Allocate memory for the new socket data structure */
				socket_data = kzalloc(sizeof(*socket_data), GFP_KERNEL);
				if (!socket_data) {
					pr_err("Failed to allocate memory for socket_data\n");
					wg_destroy_temp_peer(new_temp_peer);
					continue;
				}

				/* Initialize the socket data with the device and the temp peer */
				socket_data->device = wg;
				socket_data->peer = new_temp_peer;
				socket_data->inbound = true;

				/* Set the socket data as sk_user_data */
				new_peer_connection->sk->sk_user_data = socket_data;

				wg_get_endpoint_from_socket(new_peer_connection, &new_temp_peer->tcp_reply_endpoint);
				new_temp_peer->endpoint = new_temp_peer->tcp_reply_endpoint;

				new_temp_peer->tcp_established = true;
				new_temp_peer->inbound_connected = true;
				new_temp_peer->inbound_timestamp = ktime_get();
				new_temp_peer->clean_inbound = false;
				new_temp_peer->tcp_inbound_callbacks_set = false;
				copy_sock_addresses(new_peer_connection, &new_temp_peer->inbound_source, &new_temp_peer->inbound_dest);
				wg_dbg("new_temp_peer Peer endpoint:");
				log_wireguard_endpoint(&new_temp_peer->endpoint);
				/* This socket's remote port is an observed ephemeral source
				 * port. A provisional peer has no authenticated dial target.
				 */
				new_temp_peer->peer_endpoint_set = false;

				if (wg_add_tcp_socket_to_list(wg, new_peer_connection,
							      new_temp_peer)) {
					wg_destroy_temp_peer(new_temp_peer);
					continue;
				}
				/*
				 * Authenticate pending traffic before promoting
				 * the peer.
				 */
				wg_setup_tcp_socket_callbacks(new_temp_peer, true);
				if (!skb_queue_empty(&new_peer_connection->sk->sk_receive_queue)) {
					wg_dbg("wg_tcp_listener_worker calling wg_tcp_data_ready() for temp peer\n");
					wg_tcp_data_ready(new_peer_connection->sk);
				}
				print_peer_socket_info(new_temp_peer);
				wg_finish_tcp_connection_init(wg,
							     new_peer_connection);
			} else {
				kernel_sock_shutdown(new_peer_connection, SHUT_RDWR);
				sock_release(new_peer_connection);
			}
		}
	}
	wg_dbg("Exiting function wg_tcp_listener_worker\n");
	return 0;
}

int wg_tcp_listener4_thread(void *data)
{
	wg_dbg("Entering function wg_tcp_listener4_thread\n");
	struct wg_device *wg = data;
	struct socket *listen_socket;

	/* Check if tcp_socket4_ready is set */
	if (!wg->tcp_socket4_ready) {
		wg_dbg("tcp_socket4 is not ready, exiting wg_tcp_listener4_thread\n");
		return 0;
	}
	listen_socket = wg->tcp_listen_socket4;

	wg_dbg("Exiting function wg_tcp_listener4_thread\n");
	return wg_tcp_listener_worker(wg, listen_socket);
}

int wg_tcp_listener6_thread(void *data)
{
	wg_dbg("Entering function wg_tcp_listener6_thread\n");
	struct wg_device *wg = data;
	struct socket *listen_socket;

	if (!wg->tcp_socket6_ready) {
		wg_dbg("tcp_socket6 is not ready, exiting wg_tcp_listener6_thread\n");
		return 0;
	}

	listen_socket = wg->tcp_listen_socket6;

	wg_dbg("Exiting function wg_tcp_listener6_thread\n");
	return wg_tcp_listener_worker(wg, listen_socket);
}

void wg_tcp_listener_socket_release(struct wg_device *wg)
{
	wg_dbg("Entering function wg_tcp_socket_release\n");

	/* Wake blocking kernel_accept() calls before waiting for the listener
	 * threads. kthread_stop() alone does not make the accept wait condition
	 * true and can otherwise wait indefinitely.
	 */
	if (wg->tcp_listen_socket4)
		kernel_sock_shutdown(wg->tcp_listen_socket4, SHUT_RDWR);
#if IS_ENABLED(CONFIG_IPV6)
	if (wg->tcp_listen_socket6)
		kernel_sock_shutdown(wg->tcp_listen_socket6, SHUT_RDWR);
#endif

	if (wg->tcp_listener4_thread) {
		wg_dbg("Stopping IPv4 listener thread\n");
	kthread_stop(wg->tcp_listener4_thread);
	wg->tcp_listener4_thread = NULL;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (wg->tcp_listener6_thread) {
	wg_dbg("Stopping IPv6 listener thread\n");
	kthread_stop(wg->tcp_listener6_thread);
	wg->tcp_listener6_thread = NULL;
	}
#endif

	/* Release IPv4 socket */
	if (wg->tcp_listen_socket4) {
	wg_dbg("Releasing IPv4 socket\n");
	sock_release(wg->tcp_listen_socket4);
	wg->tcp_listen_socket4 = NULL;
	wg->tcp_socket4_ready = false;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (wg->tcp_listen_socket6) {
		wg_dbg("Releasing IPv6 socket\n");
	sock_release(wg->tcp_listen_socket6);
	wg->tcp_listen_socket6 = NULL;
	wg->tcp_socket6_ready = false;
	}
#endif
	wg->tcp_socket4_ready = false;
	wg->tcp_socket6_ready = false;

	wg_dbg("Exiting function wg_tcp_socket_release\n");
}

int wg_setup_tcp_listen4(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket)
{
	struct socket *socket = NULL;
	struct sockaddr_in addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr = { htonl(INADDR_ANY) }
	};
	int ret;

	if (!wg || !net || !listen_socket || port == 0) {
		printk(KERN_ERR "wg_setup_tcp_listen4: Invalid arguments\n");
		return -EINVAL;
	}
	*listen_socket = NULL;
	wg_dbg("Entering function wg_setup_tcp_listen4\n");

	wg_dbg("Creating IPv4 socket\n");
	ret = sock_create_kern(net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 TCP socket, error: %d\n", wg->dev->name, ret);
		return ret;
	}
	WRITE_ONCE(socket->sk->sk_mark, wg->fwmark);
	wg_dbg("IPv4 socket created successfully\n");

	/* Set socket options to reuse port */
	sock_set_reuseport(socket->sk);

	wg_dbg("Binding IPv4 socket\n");
	ret = kernel_bind(socket, (struct sockaddr *)&addr4, sizeof(addr4));
	if (ret < 0) {
		pr_err("%s: Could not bind IPv4 TCP socket, error: %d\n", wg->dev->name, ret);
		goto error;
	}
	wg_dbg("IPv4 socket bound successfully\n");

	wg_dbg("Starting to listen on IPv4 socket\n");
	ret = kernel_listen(socket, SOMAXCONN);
	if (ret < 0) {
		pr_err("%s: Could not listen on IPv4 TCP socket, error: %d\n", wg->dev->name, ret);
		goto error;
	}
	wg_dbg("IPv4 socket is now listening\n");
	*listen_socket = socket;
	wg_dbg("Exiting function wg_setup_tcp_listen4 with ret=%d\n", ret);
	return 0;

error:
	sock_release(socket);
	wg_dbg("Exiting function wg_setup_tcp_listen4 with ret=%d\n", ret);
	return ret;
}

int wg_setup_tcp_listen6(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct socket *socket = NULL;
	struct sockaddr_in6 addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};
	int ret;

	if (!wg || !net || !listen_socket || port == 0) {
		printk(KERN_ERR "wg_setup_tcp_listen6: Invalid arguments\n");
		return -EINVAL;
	}
	*listen_socket = NULL;
	wg_dbg("Entering function wg_setup_tcp_listen6\n");

	wg_dbg("Creating IPv6 socket\n");
	ret = sock_create_kern(net, AF_INET6, SOCK_STREAM, IPPROTO_TCP, &socket);
	if (ret < 0) {
		pr_err("%s: Could not create IPv6 TCP socket, error: %d\n", wg->dev->name, ret);
		return ret;
	}
	WRITE_ONCE(socket->sk->sk_mark, wg->fwmark);
	wg_dbg("IPv6 socket created successfully\n");

	/* Keep the IPv4 and IPv6 wildcard listeners independent. */
	ret = ip6_sock_set_v6only(socket->sk);
	if (ret < 0) {
		pr_err("%s: Could not make IPv6 TCP listener v6-only, error: %d\n",
		       wg->dev->name, ret);
		goto error;
	}

	wg_dbg("Binding IPv6 socket\n");
	ret = kernel_bind(socket, (struct sockaddr *)&addr6, sizeof(addr6));
	if (ret < 0) {
		pr_err("%s: Could not bind IPv6 TCP socket, error: %d\n", wg->dev->name, ret);
		goto error;
	}
	wg_dbg("IPv6 socket bound successfully\n");

	wg_dbg("Starting to listen on IPv6 socket\n");
	ret = kernel_listen(socket, SOMAXCONN);
	if (ret < 0) {
		pr_err("%s: Could not listen on IPv6 TCP socket, error: %d\n", wg->dev->name, ret);
		goto error;
	}
	wg_dbg("IPv6 socket is now listening\n");
	*listen_socket = socket;
	wg_dbg("Exiting function wg_setup_tcp_listen6 with ret=%d\n", ret);
	return 0;

error:
	sock_release(socket);
	wg_dbg("Exiting function wg_setup_tcp_listen6 with ret=%d\n", ret);
	return ret;
#else
	return -EAFNOSUPPORT;
#endif
}

int wg_tcp_listener_socket_init(struct wg_device *wg, u16 port)
{
	struct socket *listen_socket4 = NULL, *listen_socket6 = NULL;
	struct net *net;
	int ret;

	if (!wg || port == 0) {
		printk(KERN_ERR "wg_tcp_listener_socket_init: Invalid arguments\n");
		return -EINVAL;
	}
	wg_dbg("Entering function wg_tcp_listener_socket_init\n");

	if (wg->tcp_socket4_ready || wg->tcp_socket6_ready) {
		wg_dbg("TCP sockets are already initialized, exiting\n");
		return 0;
	}

	if (!wg->dev) {
		wg_dbg("Net Device not initialized in wg_device, exiting\n");
		return -EINVAL;
	}

	wg_dbg("Locking RCU and dereferencing wg->creating_net\n");
	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	wg_dbg("RCU lock released\n");

	if (unlikely(!net)) {
		printk(KERN_ERR "Error: net is NULL, exiting wg_tcp_listener_socket_init\n");
		return -ENONET;
	}




	/* Match the UDP transport's family policy: IPv4 is required and IPv6 is
	 * added when the module is available. Wildcard binds do not require a
	 * default route or a globally selected interface.
	 */
	ret = wg_setup_tcp_listen4(wg, net, port, &listen_socket4);
	if (ret < 0)
		goto error_sockets;

#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6_mod_enabled()) {
		ret = wg_setup_tcp_listen6(wg, net, port, &listen_socket6);
		if (ret < 0)
			goto error_sockets;
	}
#endif

	if (!listen_socket4 && !listen_socket6) {
		ret = -EADDRNOTAVAIL;
		pr_err("%s: No address family is available for a TCP listener\n",
		       wg->dev->name);
		goto error_sockets;
	}

	wg->tcp_listen_socket4 = listen_socket4;
	wg->tcp_listen_socket6 = listen_socket6;
	wg->tcp_socket4_ready = listen_socket4 != NULL;
	wg->tcp_socket6_ready = listen_socket6 != NULL;

	if (wg->tcp_listen_socket4) {
		wg_dbg("Starting IPv4 listener thread\n");
		wg->tcp_listener4_thread = kthread_run(wg_tcp_listener4_thread,
						       (void *)wg, "wg_listener4");
		if (IS_ERR(wg->tcp_listener4_thread)) {
			ret = PTR_ERR(wg->tcp_listener4_thread);
			wg->tcp_listener4_thread = NULL;
			pr_err("%s: Failed to establish IPv4 TCP listener thread: %d\n",
			       wg->dev->name, ret);
			goto error_listeners;
		}
		wg_dbg("IPv4 listener thread started successfully\n");
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (wg->tcp_listen_socket6) {
		wg_dbg("Starting IPv6 listener thread\n");
		wg->tcp_listener6_thread = kthread_run(wg_tcp_listener6_thread,
						       (void *)wg, "wg_listener6");
		if (IS_ERR(wg->tcp_listener6_thread)) {
			ret = PTR_ERR(wg->tcp_listener6_thread);
			wg->tcp_listener6_thread = NULL;
			pr_err("%s: Failed to establish IPv6 TCP listener thread: %d\n",
			       wg->dev->name, ret);
			goto error_listeners;
		}
		wg_dbg("IPv6 listener thread started successfully\n");
	}
#endif

	put_net(net);
	wg_dbg("Exiting function wg_tcp_listener_socket_init\n");
	return 0;

error_listeners:
	wg_tcp_listener_socket_release(wg);
	goto out_net;
error_sockets:
	if (listen_socket4)
		sock_release(listen_socket4);
#if IS_ENABLED(CONFIG_IPV6)
	if (listen_socket6)
		sock_release(listen_socket6);
#endif
out_net:
	put_net(net);
	wg_dbg("Exiting function wg_tcp_listener_socket_init with error: %d\n", ret);
	return ret;
}
static void wg_tcp_connect_unwind(struct wg_peer *peer, struct socket *socket)
{
	struct wg_socket_data *socket_data = NULL;
	struct sock *sk = socket ? socket->sk : NULL;
	bool queue_reconnect = false;
	bool owns_socket = false;

	/* A connect callback can publish ESTABLISHED before kernel_connect()
	 * returns. Claim removal and drain any writer queued in that window before
	 * releasing a failed connection attempt.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (socket && (peer->peer_socket == socket ||
		       peer->outbound_socket == socket)) {
		peer->tcp_outbound_remove_scheduled = true;
		peer->tcp_outbound_remove_socket = socket;
		owns_socket = true;
	}
	spin_unlock_bh(&peer->tcp_lock);
	if (owns_socket) {
		cancel_work_sync(&peer->tcp_read_work);
		cancel_work_sync(&peer->tcp_write_work);
		peer->tcp_read_worker_scheduled = false;
		peer->tcp_write_worker_scheduled = false;
	}

	/* Stop WireGuard callbacks and detach their wrapper while the socket is
	 * still alive. This waits for any callback already holding callback_lock.
	 */
	if (socket && READ_ONCE(peer->outbound_socket) == socket)
		wg_reset_tcp_socket_callbacks(peer, false);
	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		socket_data = sk->sk_user_data;
		sk->sk_user_data = NULL;
		write_unlock_bh(&sk->sk_callback_lock);
	}

	/* Publish one coherent disconnected state before releasing the socket.
	 * Consumers either see this state or the still-live socket above.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (peer->peer_socket == socket)
		peer->peer_socket = NULL;
	if (peer->outbound_socket == socket)
		peer->outbound_socket = NULL;
	peer->tcp_connecting = false;
	peer->tcp_pending = false;
	peer->tcp_established = false;
	peer->outbound_connected = false;
	peer->tcp_outbound_callbacks_set = false;
	peer->tcp_outbound_remove_socket = NULL;
	if (peer->tcp_reconnect_requested && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    peer->device->transport == WG_TRANSPORT_TCP) {
		peer->tcp_outbound_remove_scheduled = true;
		queue_reconnect = true;
	} else if (!peer->tcp_stopping) {
		peer->tcp_outbound_remove_scheduled = false;
	}
	peer->clean_outbound = false;
	peer->outbound_timestamp = ktime_set(0, 0);
	peer->original_outbound_state_change = NULL;
	peer->original_outbound_write_space = NULL;
	peer->original_outbound_data_ready = NULL;
	peer->original_outbound_error_report = NULL;
	peer->original_outbound_destruct = NULL;
	spin_unlock_bh(&peer->tcp_lock);

	kfree(socket_data);
	if (socket)
		sock_release(socket);
	if (queue_reconnect) {
		/* The socket is gone before replacement work can run. Recheck the
		 * stop barrier under the ownership lock so peer_stop cannot drain the
		 * work item and then lose a late queue.
		 */
		spin_lock_bh(&peer->tcp_lock);
		if (!peer->tcp_stopping && peer->tcp_reconnect_requested &&
		    peer->tcp_outbound_remove_scheduled)
			mod_delayed_work(system_wq,
					 &peer->tcp_outbound_remove_work, 0);
		spin_unlock_bh(&peer->tcp_lock);
	}
}

/* Attempt to establish a TCP connection */
int wg_tcp_connect(struct wg_peer *peer)
{
	struct wg_socket_data *socket_data;
	struct socket *socket = NULL;
	struct net *net;
	struct endpoint target;
	struct sockaddr_storage addr_storage;
	struct sockaddr *addr = (struct sockaddr *)&addr_storage;
	unsigned long timeout = 30 * HZ;
	bool queue_remove = false;
	bool queue_retry = false;
	int family;
	int ret;

	if (!peer || IS_ERR(peer) || !peer->device)
		return -EINVAL;

	wg_dbg("Entering function wg_tcp_connect peer=%px\n", peer);
	print_peer_socket_info(peer);

	if (peer->device->transport != WG_TRANSPORT_TCP) {
		pr_err("Invalid state for TCP connection attempt.\n");
		return -EINVAL;
	}

	/* One connect attempt must use one coherent target even if an
	 * authenticated packet or netlink update changes the next retry target.
	 */
	read_lock_bh(&peer->endpoint_lock);
	if (peer->peer_endpoint_set)
		target = peer->peer_endpoint;
	else
		memset(&target, 0, sizeof(target));
	read_unlock_bh(&peer->endpoint_lock);
	family = target.addr.sa_family;

	wg_dbg("(Device) Peer transport: %d, TCP established: %d\n",
	       peer->device->transport, peer->tcp_established);
	wg_dbg("Peer endpoint address family: %d\n", family);
	log_wireguard_endpoint(&target);

	if (family != AF_INET && family != AF_INET6) {
		printk(KERN_ERR "Invalid address family for connection: %d\n",
		       family);
		return -EAFNOSUPPORT;
	}

	/* tcp_pending is also the connect-attempt ownership claim. It prevents
	 * retry, send, and endpoint-update paths from publishing a second socket.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP ||
	    !netif_running(peer->device->dev) || peer->tcp_established ||
	    peer->tcp_pending ||
	    peer->inbound_connected || peer->outbound_connected ||
	    peer->tcp_outbound_remove_scheduled) {
		spin_unlock_bh(&peer->tcp_lock);
		return 0;
	}
	if (peer->peer_socket || peer->outbound_socket) {
		spin_unlock_bh(&peer->tcp_lock);
		return -EALREADY;
	}
	peer->tcp_connecting = true;
	peer->tcp_pending = true;
	peer->tcp_established = false;
	peer->outbound_connected = false;
	peer->tcp_outbound_callbacks_set = false;
	peer->outbound_timestamp = ktime_set(0, 0);
	spin_unlock_bh(&peer->tcp_lock);

	memset(&addr_storage, 0, sizeof(addr_storage));

	if (family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr_storage;
		addr4->sin_family = AF_INET;
		addr4->sin_port = target.addr4.sin_port;
		addr4->sin_addr.s_addr = target.addr4.sin_addr.s_addr;
		addr = (struct sockaddr *)addr4;
		wg_dbg("Setting up IPv4 connection to %pI4:%d\n", &addr4->sin_addr, ntohs(addr4->sin_port));
	}
#ifdef CONFIG_IPV6
	else if (family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr_storage;
		addr6->sin6_family = AF_INET6;
		addr6->sin6_port = target.addr6.sin6_port;
		addr6->sin6_addr = target.addr6.sin6_addr;
		addr6->sin6_scope_id = target.addr6.sin6_scope_id;
		addr = (struct sockaddr *)addr6;
		wg_dbg("Setting up IPv6 connection to [%pI6c]:%d\n", &addr6->sin6_addr, ntohs(addr6->sin6_port));
	}
#endif
	else {
		pr_err("Unsupported address family: %d\n", family);
		wg_dbg("Exiting function wg_tcp_connect\n");
		ret = -EAFNOSUPPORT;
		goto fail;
	}

	/* The device can outlive a move into another namespace, so use the
	 * retained creation namespace just as the UDP and TCP listeners do.
	 */
	rcu_read_lock();
	net = rcu_dereference(peer->device->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net)) {
		ret = -ENONET;
		goto fail;
	}

	/* Create the socket */
	wg_dbg("Creating socket for address family: %d\n", family);
	ret = sock_create_kern(net, family,
			       SOCK_STREAM, IPPROTO_TCP, &socket);
	put_net(net);
	if (ret) {
		pr_err("Failed to create TCP socket for address family %d: %d\n",
		       family, ret);
		wg_dbg("Exiting function wg_tcp_connect\n");
		goto fail;
	}
	WRITE_ONCE(socket->sk->sk_mark, peer->device->fwmark);
	spin_lock_bh(&peer->tcp_lock);
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP ||
	    !netif_running(peer->device->dev) || !peer->tcp_connecting ||
	    !peer->tcp_pending || peer->peer_socket || peer->outbound_socket) {
		spin_unlock_bh(&peer->tcp_lock);
		ret = -ESHUTDOWN;
		goto fail;
	}
	peer->peer_socket = socket;
	peer->outbound_socket = socket;
	spin_unlock_bh(&peer->tcp_lock);

	wg_dbg("Allocating socket data\n");
	socket_data = kzalloc(sizeof(*socket_data), GFP_KERNEL);
	if (!socket_data) {
		pr_err("Failed to allocate memory for wg_socket_data\n");
		ret = -ENOMEM;
		goto fail;
	}
	socket_data->device = peer->device;
	socket_data->peer = peer;
	socket_data->inbound = false;
	write_lock_bh(&socket->sk->sk_callback_lock);
	socket->sk->sk_user_data = socket_data;
	write_unlock_bh(&socket->sk->sk_callback_lock);

	/* Print diagnostic information about the created socket */
	wg_dbg("Socket created, sk=%px, family=%d, state=%d\n",
	       socket->sk, socket->sk->sk_family, socket->sk->sk_state);

	/* Set up the socket callbacks before initiating the connect */
	wg_dbg("Setting up socket callbacks\n");
	wg_setup_tcp_socket_callbacks(peer, false); /* set outbound callbacks */

	/* Set socket timeouts for send and receive operations */
	wg_dbg("Setting socket timeouts\n");
	ret = wg_set_socket_timeouts(socket, timeout, timeout);
	if (ret) {
		pr_err("Failed to set socket timeouts: %d\n", ret);
		goto fail;
	}

	wg_dbg("Ready to initiate connection, sk_state=%d\n",
	       socket->sk->sk_state);

	/* Initiate the non-blocking connect */
	wg_dbg("Initiating non-blocking connect\n");
	ret = kernel_connect(socket, addr,
			     addr->sa_family == AF_INET ?
				     sizeof(struct sockaddr_in) :
				     sizeof(struct sockaddr_in6),
			     O_NONBLOCK);

	/* FIX #4: Disable Nagle's algorithm on outbound socket to avoid
	 * ~200ms delayed ACK interaction that caused 1000ms RTT
	 */
	tcp_sock_set_nodelay(socket->sk);

	if (ret != -EINPROGRESS && ret != 0) {
		pr_err("TCP connection attempt failed: %d\n", ret);
		goto fail;
	}

	/* kernel_connect() selects the route, local address, and ephemeral source
	 * port. Cache the tuple only after that selection; the pre-connect socket
	 * fields are commonly still zero.
	 */
	{
		struct inet_sock *inet = inet_sk(socket->sk);

		memset(&peer->outbound_source, 0,
		       sizeof(peer->outbound_source));
		memset(&peer->outbound_dest, 0, sizeof(peer->outbound_dest));
		if (family == AF_INET) {
			struct sockaddr_in *source =
				(struct sockaddr_in *)&peer->outbound_source;
			struct sockaddr_in *dest =
				(struct sockaddr_in *)&peer->outbound_dest;

			source->sin_family = AF_INET;
			source->sin_port = inet->inet_sport;
			source->sin_addr.s_addr = inet->inet_saddr;
			dest->sin_family = AF_INET;
			dest->sin_port = inet->inet_dport;
			dest->sin_addr.s_addr = inet->inet_daddr;
#ifdef CONFIG_IPV6
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *source6 =
				(struct sockaddr_in6 *)&peer->outbound_source;
			struct sockaddr_in6 *dest6 =
				(struct sockaddr_in6 *)&peer->outbound_dest;

			source6->sin6_family = AF_INET6;
			source6->sin6_port = inet->inet_sport;
			source6->sin6_addr = inet6_sk(socket->sk)->saddr;
			dest6->sin6_family = AF_INET6;
			dest6->sin6_port = inet->inet_dport;
			dest6->sin6_addr = socket->sk->sk_v6_daddr;
			dest6->sin6_scope_id = target.addr6.sin6_scope_id;
#endif
		}
	}

	wg_dbg("TCP connection attempt initiated\n");
	spin_lock_bh(&peer->tcp_lock);
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP ||
	    !netif_running(peer->device->dev) ||
	    peer->peer_socket != socket || peer->outbound_socket != socket ||
	    READ_ONCE(socket->sk->sk_state) == TCP_CLOSE) {
		spin_unlock_bh(&peer->tcp_lock);
		ret = -ECONNABORTED;
		goto fail;
	}
	peer->tcp_connecting = false;
	if (peer->tcp_reconnect_requested && !peer->tcp_stopping &&
	    !peer->tcp_outbound_remove_scheduled) {
		peer->tcp_outbound_remove_scheduled = true;
		peer->tcp_outbound_remove_socket = socket;
		queue_remove = true;
	} else if (peer->tcp_pending && !peer->tcp_retry_scheduled) {
		peer->tcp_retry_scheduled = true;
		queue_retry = true;
	}
	if (queue_remove)
		mod_delayed_work(system_wq, &peer->tcp_outbound_remove_work, 0);
	if (queue_retry) {
		wg_dbg("Scheduling TCP retry work.\n");
		mod_delayed_work(system_wq, &peer->tcp_retry_work,
				 msecs_to_jiffies(10000));
	}
	spin_unlock_bh(&peer->tcp_lock);

	wg_dbg("Exiting function wg_tcp_connect\n");
	return 0;

fail:
	wg_tcp_connect_unwind(peer, socket);
	wg_dbg("Exiting function wg_tcp_connect with error: %d\n", ret);
	return ret;
}

/* Function to release and clean up an old peer TCP connection - clean the active connection */
static void __maybe_unused wg_release_peer_tcp_connection(struct wg_peer *peer)
{
	bool inbound = false;
	wg_dbg("Entering function wg_release_old_peer_tcp_connection\n");
	if (unlikely(!peer) || unlikely(IS_ERR(peer))){
		wg_dbg("Exiting function wg_release_old_peer_tcp_connection - no peer to tear down.\n");
		goto out;
	}
	print_peer_socket_info(peer);
	if (!peer->peer_socket || !(peer->tcp_established || peer->tcp_pending)){
		wg_dbg("Exiting function wg_release_old_peer_tcp_connection - no connection to tear down.\n");
		goto out;
	}
	if (peer->peer_socket == peer->inbound_socket)
		inbound = true;
	/* Reset socket callbacks and release the socket */
	wg_reset_tcp_socket_callbacks(peer, inbound);

	/* Perform a graceful shutdown and release the socket */
	kernel_sock_shutdown(peer->peer_socket, SHUT_RDWR);
	sock_release(peer->peer_socket);

	/* Lock to safely modify the peer's TCP connection state */
	spin_lock_bh(&peer->tcp_lock);
	peer->peer_socket = NULL;
	if (inbound)
		peer->inbound_socket = NULL;
	else
		peer->outbound_socket = NULL;
	/* Clear TCP connection flags */
	peer->tcp_pending = false;  /* BUG FIX: was true — blocked wg_tcp_connect() from reconnecting */
	peer->tcp_established = false;
	spin_unlock_bh(&peer->tcp_lock);
	/* flush any partial data before we switch and free the held buffer */
	if (peer->partial_skb) {
                kfree_skb(peer->partial_skb);
		peer->partial_skb = NULL;
	}

	/* Check if a retry is scheduled and clean up */
	if (peer->tcp_retry_scheduled) {
	peer->tcp_retry_scheduled = false;
	cancel_delayed_work_sync(&peer->tcp_retry_work);
	}

	/* Clean up packet queues */
	skb_queue_purge(&peer->send_queue);


out:
	wg_dbg("Exiting function wg_release_old_peer_tcp_connection\n");
}


void wg_extract_endpoint_from_sock(struct sock *sk,
                                   struct endpoint *endpoint)
{
	wg_dbg("Entering function wg_extract_endpoint_from_sock\n");
	if (!sk || !endpoint) {
		pr_warn("Socket or endpoint is NULL.\n");
		return;
	}
	memset(endpoint, 0, sizeof(*endpoint)); /* Clear the endpoint structure */

	if (sk->sk_family == AF_INET) {
		/* IPv4 */
		struct inet_sock *inet = inet_sk(sk);

		endpoint->addr4.sin_family = AF_INET;
		endpoint->addr4.sin_port = inet->inet_dport; /* Destination port */
		endpoint->addr4.sin_addr.s_addr = inet->inet_daddr; /* Destination IP address */
	} else if (sk->sk_family == AF_INET6) {
#if IS_ENABLED(CONFIG_IPV6)
		/* IPv6 */
		endpoint->addr6.sin6_family = AF_INET6;
		endpoint->addr6.sin6_port = sk->sk_dport; /* Destination port */
		endpoint->addr6.sin6_addr = sk->sk_v6_daddr; /* Destination IP address */

		if (ipv6_addr_type((struct in6_addr *)&sk->sk_v6_daddr) & IPV6_ADDR_LINKLOCAL) {
			/*
			 * Preserve the bound interface as the scope of a
			 * link-local destination.
			 */
			endpoint->addr6.sin6_scope_id = sk->sk_bound_dev_if;
		} else {
			/* Not a link-local address; no scope ID required */
			endpoint->addr6.sin6_scope_id = 0;
		}
	} else {
#endif
		pr_warn("Unsupported socket family: %d.\n", sk->sk_family);
	}
	wg_dbg("Exiting function wg_extract_endpoint_from_sock\n");
}


void wg_tcp_state_change(struct sock *sk)
{
	struct wg_device *cleanup_device = NULL;
	struct wg_socket_data *socket_data = NULL;
	struct wg_peer *peer = NULL;
	bool cleanup_temp = false;
	bool cancel_retry = false;
	bool queue_inbound_remove = false;
	bool queue_outbound_remove = false;

	wg_dbg("Entering function wg_tcp_state_change\n");

	/* Check if the socket is valid */
	if (!sk || IS_ERR(sk)) {
		pr_err("wg_tcp_state_change: Invalid socket passed to the function\n");
		goto out;
	}

	/* Retrieve the socket user data */
	socket_data = sk->sk_user_data;

	/* Check if socket_data is valid */
	if (!socket_data || IS_ERR(socket_data)) {
		pr_err("wg_tcp_state_change: Invalid or NULL socket_data for socket %px\n", sk);
		goto out;
	}

	/* Retrieve the peer from the socket_data */
	peer = socket_data->peer;

	/* Check if peer is valid or being torn down */
	if (!peer || IS_ERR(peer) || READ_ONCE(peer->is_dead) ||
	    (!socket_data->inbound &&
	     READ_ONCE(peer->tcp_outbound_remove_scheduled)) ||
	    (socket_data->inbound &&
	     READ_ONCE(peer->tcp_inbound_remove_scheduled))) {
		goto out;
	}
	print_peer_socket_info(peer);
	/* Diagnostic information about the current state */
#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_dump_sock(sk, "state_change", 0, 0);
#endif
	wg_dbg("wg_tcp_state_change: Socket state=%d, Socket error=%d\n", sk->sk_state, sk->sk_err);
	wg_dbg("wg_tcp_state_change: Peer=%px, Device=%px\n", peer, socket_data->device);

	/* Additional diagnostic information for peer-specific data */
	wg_dbg("wg_tcp_state_change: Peer TCP established=%d, TCP pending=%d\n",
	        peer->tcp_established, peer->tcp_pending);



	/* Log detailed state information */
	wg_dbg("wg_tcp_state_change: sk=%px, sk_state=%d, sk_err=%d, sk_shutdown=%d, sk_send_head=%px\n",
		sk, sk->sk_state, sk->sk_err, sk->sk_shutdown, sk->sk_send_head);
	/* Log TCP specific state information if available */
	const char *tcp_state_name;

	switch (sk->sk_state) {
		case TCP_ESTABLISHED:
		tcp_state_name = "TCP_ESTABLISHED";
			break;
		case TCP_SYN_SENT:
			tcp_state_name = "TCP_SYN_SENT";
			break;
		case TCP_SYN_RECV:
			tcp_state_name = "TCP_SYN_RECV";
			break;
		case TCP_FIN_WAIT1:
			tcp_state_name = "TCP_FIN_WAIT1";
			break;
		case TCP_FIN_WAIT2:
			tcp_state_name = "TCP_FIN_WAIT2";
			break;
		case TCP_TIME_WAIT:
			tcp_state_name = "TCP_TIME_WAIT";
			break;
		case TCP_CLOSE:
			tcp_state_name = "TCP_CLOSE";
			break;
		case TCP_CLOSE_WAIT:
			tcp_state_name = "TCP_CLOSE_WAIT";
			break;
		case TCP_LAST_ACK:
			tcp_state_name = "TCP_LAST_ACK";
			break;
		case TCP_LISTEN:
			tcp_state_name = "TCP_LISTEN";
			break;
		case TCP_CLOSING:
			tcp_state_name = "TCP_CLOSING";
			break;
		case TCP_NEW_SYN_RECV:
			tcp_state_name = "TCP_NEW_SYN_RECV";
			break;
		default:
			tcp_state_name = "UNKNOWN_STATE";
		break;
	}

	wg_dbg("TCP state: %s (%d)\n", tcp_state_name, sk->sk_state);

	if (sk->sk_state == TCP_ESTABLISHED) {
		struct tcp_sock *tp = tcp_sk(sk);
		wg_dbg("TCP_ESTABLISHED: snd_una=%u, snd_nxt=%u, snd_wnd=%u, rcv_wnd=%u, rcv_nxt=%u\n",
			tp->snd_una, tp->snd_nxt, tp->snd_wnd, tp->rcv_wnd, tp->rcv_nxt);
	}

	/* first lets figure out if this is an inbound connect */

	switch (sk->sk_state) {
		case TCP_ESTABLISHED:
			if (peer->temp_peer) {
				pr_err("Wireguard: Inbound peer connection previously established.\n");
				break;
			}
			if (socket_data->inbound)
				break;
			spin_lock_bh(&peer->tcp_lock);
			if (peer->outbound_socket &&
			    peer->outbound_socket->sk == sk &&
			    !peer->tcp_established && !peer->outbound_connected) {
				peer->tcp_pending = false;
			peer->tcp_established = true;
				peer->outbound_connected = true;
				peer->outbound_timestamp = ktime_get();
				if (peer->tcp_retry_scheduled) {
					peer->tcp_retry_scheduled = false;
					cancel_retry = true;
				}
				wg_dbg("TCP connection established.\n");
			} else
				pr_err("Wireguard: Outbound connection previously established.\n");
			spin_unlock_bh(&peer->tcp_lock);
			if (cancel_retry)
				cancel_delayed_work(&peer->tcp_retry_work);
			break;
		case TCP_CLOSE:
		case TCP_CLOSE_WAIT:
		case TCP_CLOSING:
		case TCP_FIN_WAIT1:
		case TCP_FIN_WAIT2:
		case TCP_LAST_ACK:
			if (peer->temp_peer) {
				WRITE_ONCE(peer->is_dead, true);
				cleanup_device = peer->device;
				cleanup_temp = true;
				break;
			}
			wg_dbg("TCP connection failed or closed, handling state.\n");
			spin_lock_bh(&peer->tcp_lock);
			if (socket_data->inbound) {
				if (!peer->inbound_socket ||
				    peer->inbound_socket->sk != sk) {
					spin_unlock_bh(&peer->tcp_lock);
					break;
				}
				peer->inbound_timestamp = ktime_set(0, 0);
				peer->inbound_connected = false;
				if (!peer->tcp_inbound_remove_scheduled) {
					peer->tcp_inbound_remove_scheduled = true;
					queue_inbound_remove = true;
				}
			} else {
				if (!peer->outbound_socket ||
				    peer->outbound_socket->sk != sk) {
					spin_unlock_bh(&peer->tcp_lock);
					break;
				}
				peer->outbound_timestamp = ktime_set(0, 0);
				peer->outbound_connected = false;
				peer->tcp_pending = false;
				if (peer->tcp_connecting) {
					spin_unlock_bh(&peer->tcp_lock);
					break;
				}
				peer->tcp_reconnect_requested = true;
				if (!peer->tcp_outbound_remove_scheduled) {
					peer->tcp_outbound_remove_scheduled = true;
					peer->tcp_outbound_remove_socket =
						peer->outbound_socket;
					queue_outbound_remove = true;
				}
			}
			if (!peer->inbound_connected && !peer->outbound_connected)
				peer->tcp_established = false;
			spin_unlock_bh(&peer->tcp_lock);
			break;
		default:
			break;
	}
out:
	/* Work that frees sk_user_data is queued only after the original callback
	 * has run, so this callback keeps a stable wrapper for its whole lifetime.
	 */
	if (sk && socket_data && peer) {
		if (socket_data->inbound) {
			if (peer->original_inbound_state_change)
				peer->original_inbound_state_change(sk);
		} else {
			if (peer->original_outbound_state_change)
				peer->original_outbound_state_change(sk);
		}
	}
	if (peer && (queue_inbound_remove || queue_outbound_remove)) {
		/* The original callback can overlap device or peer stop. Recheck the
		 * barrier and publish work while holding tcp_lock so a completed
		 * cancel_delayed_work_sync() cannot be followed by a late queue.
		 */
		spin_lock_bh(&peer->tcp_lock);
		if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
		    READ_ONCE(peer->device->tcp_cleanup_scheduled)) {
			if (queue_inbound_remove &&
			    peer->tcp_inbound_remove_scheduled &&
			    peer->inbound_socket &&
			    peer->inbound_socket->sk == sk)
				mod_delayed_work(system_wq,
						 &peer->tcp_inbound_remove_work, 0);
			if (queue_outbound_remove &&
			    peer->tcp_outbound_remove_scheduled &&
			    peer->tcp_outbound_remove_socket ==
				    peer->outbound_socket &&
			    peer->outbound_socket &&
			    peer->outbound_socket->sk == sk)
				mod_delayed_work(system_wq,
						 &peer->tcp_outbound_remove_work, 0);
		}
		spin_unlock_bh(&peer->tcp_lock);
	}
	if (cleanup_temp && READ_ONCE(cleanup_device->tcp_cleanup_scheduled))
		mod_delayed_work(system_wq, &cleanup_device->tcp_cleanup_work, 0);
	wg_dbg("Exiting function wg_tcp_state_change\n");
}



void log_wireguard_endpoint(struct endpoint *ep)
{
#ifndef WG_TCP_VERBOSE
	return;
#else
    char addr_str[INET6_ADDRSTRLEN];

    if (!ep) {
        wg_dbg("WireGuard: Endpoint is NULL.\n");
        return;
    }

    switch (ep->addr.sa_family) {
    case AF_INET: {
        /* Handle IPv4 address */
        struct sockaddr_in *sin = &ep->addr4;
        snprintf(addr_str, sizeof(addr_str), "%pI4", &sin->sin_addr);
        wg_dbg("Endpoint IPv4: %s:%u\n",
               addr_str, ntohs(sin->sin_port));
        if (ep->src_if4 != 0) {
            snprintf(addr_str, sizeof(addr_str), "%pI4", &ep->src4);
            wg_dbg("Source IPv4: %s, Source Interface: %d\n",
                   addr_str, ep->src_if4);
        }
        break;
    }
    case AF_INET6: {
        /* Handle IPv6 address */
        struct sockaddr_in6 *sin6 = &ep->addr6;
        snprintf(addr_str, sizeof(addr_str), "%pI6", &sin6->sin6_addr);
        wg_dbg("Endpoint IPv6: [%s]:%u, Scope ID: %u\n",
               addr_str, ntohs(sin6->sin6_port), sin6->sin6_scope_id);
        snprintf(addr_str, sizeof(addr_str), "%pI6", &ep->src6);
        wg_dbg("Source IPv6: [%s]\n", addr_str);
        break;
    }
    default:
        wg_dbg("Unsupported address family: %d\n", ep->addr.sa_family);
        break;
    }
#endif
}



void wg_get_endpoint_from_socket(struct socket *epsocket, struct endpoint *ep)
{
    /* Validate input parameters */
    if (!epsocket || !ep) {
        printk(KERN_ERR "Invalid input: epsocket or ep is NULL\n");
        return;
    }

    /* Validate the socket's `sock` structure */
    if (!epsocket->sk) {
        printk(KERN_ERR "Invalid socket: epsocket->sk is NULL\n");
        return;
    }

    struct sock *sk = epsocket->sk;
    int family = sk->sk_family;

    if (family == AF_INET) {
        struct inet_sock *inet = inet_sk(sk);

        /* Validate inet_sk */
        if (!inet) {
            printk(KERN_ERR "inet_sk is NULL for IPv4 socket\n");
            return;
        }

        /* Ensure that the inet_daddr and inet_dport are valid before accessing */
        if (inet->inet_daddr == 0 || inet->inet_dport == 0) {
            printk(KERN_ERR "Invalid IPv4 address or port\n");
            return;
        }

        /* Populate the endpoint with IPv4 address and port */
        ep->addr4.sin_family = AF_INET;
        ep->addr4.sin_addr.s_addr = inet->inet_daddr; /* Remote IPv4 address */
        ep->addr4.sin_port = inet->inet_dport; /* Remote port */

        /* Populate src4 fields with local information */
        ep->src4.s_addr = inet->inet_saddr; /* Local IPv4 address */
        ep->src_if4 = sk->sk_bound_dev_if; /* Interface index */

        /* Diagnostics */
        wg_dbg("IPv4 endpoint: remote %pI4:%u, local %pI4:%u\n",
               &ep->addr4.sin_addr.s_addr, ntohs(ep->addr4.sin_port),
               &ep->src4.s_addr, ntohs(inet->inet_sport));

    }
#if IS_ENABLED(CONFIG_IPV6)
    else if (family == AF_INET6) {
        struct ipv6_pinfo *np = inet6_sk(sk);

        /* Validate ipv6_pinfo */
        if (!np) {
            printk(KERN_ERR "ipv6_pinfo is NULL for IPv6 socket\n");
            return;
        }

        /* Ensure that the IPv6 address and port are valid before accessing */
        if (ipv6_addr_any(&sk->sk_v6_daddr) || inet_sk(sk)->inet_dport == 0) {
            printk(KERN_ERR "Invalid IPv6 address or port\n");
            return;
        }

        /* Populate the endpoint with IPv6 address and port */
        ep->addr6.sin6_family = AF_INET6;
        ep->addr6.sin6_addr = sk->sk_v6_daddr; /* Remote IPv6 address */
        ep->addr6.sin6_port = inet_sk(sk)->inet_dport; /* Remote port */
        ep->addr6.sin6_scope_id = ipv6_iface_scope_id(&sk->sk_v6_rcv_saddr, sk->sk_bound_dev_if);

        /* Populate src6 fields with local information */
        ep->src6 = sk->sk_v6_rcv_saddr; /* Local IPv6 address */

        /* Diagnostics */
        wg_dbg("IPv6 endpoint: remote %pI6c:%u, local %pI6c:%u\n",
               &ep->addr6.sin6_addr, ntohs(ep->addr6.sin6_port),
               &ep->src6, ntohs(inet_sk(sk)->inet_sport));
    }
#endif
    else {
        printk(KERN_ERR "Unsupported address family: %d\n", family);
        return;
    }
}

int wg_tcp_queuepkt(struct wg_peer *peer, const void *data,
                           size_t len)
{
	struct sk_buff *frame;
	struct sk_buff *skb;
	int ret;

	wg_dbg("Entering function wg_tcp_queuepkt peer=%px\n", peer);

	struct endpoint current_endpoint;
	/* BUG FIX: current_endpoint was never initialized — reads garbage in log_wireguard_endpoint */
	memset(&current_endpoint, 0, sizeof(current_endpoint));

	if (!peer || IS_ERR(peer)) {
		wg_dbg("Exiting function wg_tcp_queuepkt, no peer.\n");
		return -EINVAL;
	}
	print_peer_socket_info(peer);
	if (!data || len == 0) {
		wg_dbg("Exiting function wg_tcp_queuepkt, invalid parameters\n");
		return -EINVAL;
	}

	/* Print TCP-related flags */
	wg_dbg("wg_peer: temp_peer = %d\n", peer->temp_peer);
	wg_dbg("wg_peer: tcp_established = %d\n", peer->tcp_established);
	wg_dbg("wg_peer: tcp_pending = %d\n", peer->tcp_pending);
	wg_dbg("wg_peer: outbound_connected = %d\n", peer->outbound_connected);
	wg_dbg("wg_peer: inbound_connected = %d\n", peer->inbound_connected);
	wg_dbg("wg_peer: tcp_outbound_callbacks_set = %d\n", peer->tcp_outbound_callbacks_set);
	wg_dbg("wg_peer: tcp_inbound_callbacks_set = %d\n", peer->tcp_inbound_callbacks_set);
	log_wireguard_endpoint(&peer->endpoint);

	peer = wg_find_peer_by_endpoints(peer->device, &peer->endpoint);
	if (!peer || IS_ERR(peer)) {
	wg_dbg("wg_queuepkt: No matching peer found for endpoint\n");
	return -ENOENT;
	}

	skb = alloc_skb(len + SKB_HEADER_LEN, GFP_ATOMIC);
	if (!skb) {
		wg_dbg("Exiting function wg_tcp_queuepkt\n");
		return -ENOMEM;
	}

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_put_data(skb, data, len);
	memset(skb->cb, 0, sizeof(skb->cb));

	/* Diagnostic: Print packet details and check for fragmentation markers */
	wg_dbg("wg_tcp_queuepkt: Created skb=%px, len=%zu, skb->len=%u,"
		"skb->data_len=%u\n", skb, len, skb->len, skb->data_len);
	wg_dbg("wg_tcp_queuepkt: First 32 bytes: %*ph\n",
		min_t(int, skb->len, 32), skb->data);  /* BUG FIX: was %*px (pointer with width) not %*ph (hex dump) */

	/* Check if this looks like a fragmented packet (look for potential markers) */
	if (skb->len >= 4) {
		__be32 *potential_frag_header = (__be32 *)skb->data;
		wg_dbg("wg_tcp_queuepkt: Potential frag header: "
			"0x%08x\n", ntohl(*potential_frag_header));
	}

	/* If this packet will get a TCP encap header, show what we expect */
	wg_dbg("wg_tcp_queuepkt: Expected TCP encap header length "
		"will be: %zu + %zu = %zu\n", len, WG_TCP_ENCAP_HDR_LEN,
		len + WG_TCP_ENCAP_HDR_LEN);

	frame = wg_tcp_build_frame(skb);
	kfree_skb(skb);
	if (IS_ERR(frame))
		return PTR_ERR(frame);
	skb = frame;

	if (!peer->peer_socket) {
		/* peer connenction is down reconnect */
		if (wg_tcp_connect(peer) < 0) {
			kfree_skb(skb);
			wg_dbg("Exiting function wg_tcp_queuepkt due to connection failure\n");
			return -ECONNREFUSED; /* Connection attempt failed */
		}
	}

	wg_dbg("Current endpoint:");
	log_wireguard_endpoint(&current_endpoint);
	wg_dbg("Peer endpoint:");
	log_wireguard_endpoint(&peer->endpoint);
	wg_dbg("Peer peer_endpoint:");
	log_wireguard_endpoint(&peer->peer_endpoint);

	if (!peer->tcp_established) {
		/* peer connenction is down reconnect */
		if (wg_tcp_connect(peer) < 0) {
			kfree_skb(skb);
			wg_dbg("Exiting function wg_tcp_queuepkt due to connection failure\n");
			return -ECONNREFUSED; /* Connection attempt failed */
		}
	}
	ret = wg_tcp_enqueue_frame(peer, skb);
	print_peer_socket_info(peer);
	wg_dbg("Exiting function wg_tcp_queuepkt\n");
	return ret;
}

/* Simple checksum function for TCP encapsulation header */
static __be16 wg_header_checksum(const struct wg_tcp_encap_header *hdr)
{
	wg_dbg("Entering function wg_header_checksum\n");
	uint16_t checksum = 0;
	uint32_t length = ntohl(hdr->length);

	checksum ^= (length >> 16) & 0xFFFF;
	checksum ^= length & 0xFFFF;
	checksum ^= (hdr->flags << 8) | hdr->type;

	checksum = (checksum << 5) | (checksum >> (16 - 5));

	/* Avoid trivial all-zero or all-one checksums. */
	const uint16_t constant = 0xA5A5;
	checksum ^= constant;

	wg_dbg("Exiting function wg_header_checksum\n");
	return htons(checksum);
}

/* Function to validate the header checksum */
static bool wg_validate_header_checksum(const struct wg_tcp_encap_header *hdr)
{
	wg_dbg("Entering function wg_validate_header_checksum\n");
	wg_dbg("Exiting function wg_validate_header_checksum\n");
	return wg_header_checksum(hdr) == hdr->checksum;
}


static int wg_tcp_send_frame(struct socket *sock, const struct sk_buff *frame)
{
	size_t send_len = wg_tcp_test_send_len(frame->len);
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec vec = {
		.iov_base = (void *)frame->data,
		.iov_len = send_len
	};
	int sent;

#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_dump_sock(sock->sk, "tx:frame:pre", 0, frame->len);
#endif
	sent = kernel_sendmsg(sock, &msg, &vec, 1, send_len);
#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)
	if (sent > 0 && (unsigned int)sent < frame->len)
		atomic64_inc(&wg_tcp_test_short_writes);
#endif
#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_dump_sock(sock->sk, "tx:frame:post", sent, frame->len);
	if (sent > 0)
		atomic64_add(sent, &wg_tcp_stats_tx_bytes);
	if (sent >= 0 && (unsigned int)sent < frame->len)
		atomic64_inc(&wg_tcp_stats_short_writes);
#endif
	return sent;
}

static void wg_tcp_arm_write_space(struct socket *socket)
{
	set_bit(SOCK_NOSPACE, &socket->flags);
	/* Pair with the writeability recheck before the worker releases its
	 * scheduled claim, as tcp_poll() does when arming EPOLLOUT.
	 */
	smp_mb__after_atomic();
}

void wg_tcp_write_worker(struct work_struct *work)
{

	struct wg_peer *peer = container_of(work, struct wg_peer, tcp_write_work);
	struct socket *socket = NULL;
	struct sock *sk = NULL;
	struct sk_buff *skb;
	unsigned int write_delay_ms;
	int sent;

	wg_dbg("Entering function wg_tcp_write_worker\n");

	if (!peer) {
               wg_dbg("wg_tcp_write_worker: Invalid peer or socket\n");
	       goto out;
	}
	/* A remover sets its direction flag under tcp_lock before calling
	 * cancel_work_sync(). Once captured here, the socket therefore remains
	 * alive until this worker returns.
	 */
	spin_lock_bh(&peer->tcp_lock);
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled && peer->peer_socket &&
	    peer->tcp_established) {
		socket = peer->peer_socket;
		sk = socket->sk;
	}
	spin_unlock_bh(&peer->tcp_lock);
	if (!socket || !sk) {
		wg_dbg("wg_tcp_write_worker: Socket is being removed\n");
		goto out;
	}
#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_dump_sock(sk, "tx:write_worker:start", 0, skb_queue_len(&peer->send_queue));
#endif
	wg_dbg("wg_tcp_write_worker: start peer=%llu send_queue_len=%u\n",
				 peer->internal_id, skb_queue_len(&peer->send_queue));

	/* A single bounded DEBUG delay lets the fully counted queue fill without
	 * making teardown wait once per queued frame. Recheck ownership after the
	 * sleep because a remover can publish its stop flag while waiting for this
	 * worker to return.
	 */
	write_delay_ms = wg_tcp_test_take_write_delay_ms();
	if (write_delay_ms) {
		msleep(write_delay_ms);
		spin_lock_bh(&peer->tcp_lock);
		if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
		    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
		    peer->tcp_outbound_remove_scheduled ||
		    peer->tcp_inbound_remove_scheduled ||
		    peer->peer_socket != socket || !peer->tcp_established)
			socket = NULL;
		spin_unlock_bh(&peer->tcp_lock);
		if (!socket)
			goto out;
	}

	/* BUG FIX: dequeue under lock, send outside lock.
	 * kernel_sendmsg() calls lock_sock() which can sleep —
	 * must NOT hold a spinlock across it.
	 *
	 * Do not gate the send on sk_stream_is_writeable(). A nonblocking send
	 * that reaches EAGAIN arms SOCK_NOSPACE inside the stream layer, which is
	 * what makes the later write-space callback reliable.
	 */
	while (true) {
		spin_lock_bh(&peer->send_queue_lock);
		skb = __skb_dequeue(&peer->send_queue);
		spin_unlock_bh(&peer->send_queue_lock);

		if (!skb)
			break;

		/* The skb already contains the complete stream frame. A short write
		 * advances that exact byte sequence; it must never be reframed.
		 */
		sent = wg_tcp_send_frame(socket, skb);
		if (sent > 0) {
			if ((unsigned int)sent > skb->len) {
				pr_err("wg_tcp_write_worker: invalid write count %d/%u\n",
				       sent, skb->len);
				kfree_skb(skb);
				break;
			}
			skb_pull(skb, sent);
			if (skb->len) {
#if WG_TCP_DIAG_ENABLED
				wg_tcp_diag_dump_sock(sk, "tx:write_worker:partial",
						      sent, skb->len);
#endif
				spin_lock_bh(&peer->send_queue_lock);
				__skb_queue_head(&peer->send_queue, skb);
				spin_unlock_bh(&peer->send_queue_lock);
				wg_tcp_arm_write_space(socket);
				break;
			}
#if WG_TCP_DIAG_ENABLED
			atomic64_inc(&wg_tcp_stats_tx_packets);
#endif
			kfree_skb(skb);
		} else if (!sent || sent == -EAGAIN || sent == -EWOULDBLOCK) {
#if WG_TCP_DIAG_ENABLED
			if (sent == -EAGAIN || sent == -EWOULDBLOCK)
				atomic64_inc(&wg_tcp_stats_tx_eagain);
			wg_tcp_diag_pressure(sk, peer->internal_id);
#endif
			spin_lock_bh(&peer->send_queue_lock);
			__skb_queue_head(&peer->send_queue, skb);
			spin_unlock_bh(&peer->send_queue_lock);
			wg_tcp_arm_write_space(socket);
			break;
		} else {
			pr_err("wg_tcp_write_worker: send error=%d peer=%llu frame_len=%u\n",
			       sent, peer->internal_id, skb->len);
#if WG_TCP_DIAG_ENABLED
			wg_tcp_diag_dump_sock(sk, "tx:write_worker:error", sent,
					      skb->len);
			atomic64_inc(&wg_tcp_stats_tx_errors);
#endif
			kfree_skb(skb);
			break;
		}
	}

out:
	/* Clear and, if needed, reclaim the writer atomically with respect to
	 * producers and socket removal. A producer blocked on these locks will
	 * observe the cleared flag and queue the work itself.
	 */
	spin_lock_bh(&peer->tcp_lock);
	spin_lock(&peer->tcp_write_lock);
	peer->tcp_write_worker_scheduled = false;
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled && socket && sk &&
	    peer->peer_socket == socket && peer->tcp_established &&
	    peer->tcp_write_wq && skb_queue_len(&peer->send_queue) > 0 &&
	    sk_stream_is_writeable(sk)) {
		peer->tcp_write_worker_scheduled = true;
		queue_work(peer->tcp_write_wq, &peer->tcp_write_work);
	}
	spin_unlock(&peer->tcp_write_lock);
	spin_unlock_bh(&peer->tcp_lock);
#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_aggregate();  /* Periodic aggregate stats */
#endif
	wg_dbg("Exiting function wg_tcp_write_work\n");
}

void wg_peer_discard_partial_read(struct wg_peer *peer);

void wg_peer_discard_partial_read(struct wg_peer *peer)
{
	if (peer->partial_skb)
		kfree_skb(peer->partial_skb);
	peer->partial_skb = NULL;
	peer->expected_len = 0;
	peer->received_len = 0;
}

bool wg_sync_header(struct wg_peer *peer, struct socket *socket);

bool wg_sync_header(struct wg_peer *peer, struct socket *socket)
{
	size_t i, suffix_len;

	if (!peer || !socket || !socket->sk)
		return false;

	wg_dbg("Entering function wg_sync_header\n");
	wg_dbg("wg_sync_header: Trying to synchonize to new header.\n");
	if (!peer->partial_skb ||
	    peer->received_len < WG_TCP_ENCAP_HDR_LEN)
		return false;

	for (i = 0; i <= peer->received_len - WG_TCP_ENCAP_HDR_LEN; ++i) {
		struct wg_tcp_encap_header *potential_hdr =
			(struct wg_tcp_encap_header *)(peer->partial_skb->data + i);
		struct wg_tcp_encap_header candidate;

		if (wg_check_potential_header_validity(potential_hdr,
						       peer->received_len - i)) {
			memcpy(&candidate, potential_hdr, sizeof(candidate));
			wg_dbg("wg_sync_header: Found new header.\n");
			skb_pull(peer->partial_skb, i);
			peer->received_len -= i;
			peer->expected_len = ntohl(candidate.length);
			wg_dbg("Exiting function wg_sync_header\n");
			return true;
		}
	}

	/* No complete candidate exists yet. Preserve the maximum possible header
	 * prefix so the next ordinary reader invocation can append bytes from a
	 * later TCP segment. Keeping fewer than a full header also prevents the
	 * worker from spinning on known-invalid data.
	 */
	suffix_len = min_t(size_t, peer->received_len,
			   WG_TCP_ENCAP_HDR_LEN - 1);
	memmove(peer->partial_skb->data,
		peer->partial_skb->data + peer->received_len - suffix_len,
		suffix_len);
	skb_trim(peer->partial_skb, suffix_len);
	peer->received_len = suffix_len;
	peer->expected_len = 0;
	wg_dbg("Exiting function wg_sync_header\n");
	return false;
}

/* Function to check if the given data pointer has a valid WireGuard TCP encapsulation header */
bool wg_check_potential_header_validity(struct wg_tcp_encap_header *hdr, size_t remaining_len)
{
	struct wg_tcp_encap_header candidate;
	size_t minimum_len = WG_TCP_ENCAP_HDR_LEN + MESSAGE_MINIMUM_LENGTH;
	u32 total_len;

	if (remaining_len < WG_TCP_ENCAP_HDR_LEN)
		return false;
	memcpy(&candidate, hdr, sizeof(candidate));
	if (!wg_validate_header_checksum(&candidate))
		return false;
	if (candidate.type != WG_TCP_RECORD_DATA)
		return false;
	if (candidate.flags & ~WG_TCP_FRAG_FLAG)
		return false;
	if (candidate.flags & WG_TCP_FRAG_FLAG)
		minimum_len += WG_TCP_FRAG_HDR_LEN;
	total_len = ntohl(candidate.length);
	return total_len >= minimum_len && total_len <= WG_MAX_PACKET_SIZE;
}

static int wg_tcp_build_fake_headers(struct sk_buff *skb, struct wg_peer *peer,
				     struct socket *socket)
{
	struct iphdr *iph;
	struct udphdr *udph;
	struct sock *sk;
	struct inet_sock *inet;
	struct sockaddr_in outbound_source, outbound_dest;
	int payload_len;
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 outbound_source6, outbound_dest6;
#endif

	/* Diagnostic: Print SKB state on entry */
	wg_dbg("Entering wg_tcp_build_fake_headers. SKB state on entry: "
	       "skb=%px, len=%d, head=%px, data=%px, tail=%u, end=%u, headroom=%d, tailroom=%d\n",
	       skb, skb->len, skb->head, skb->data, skb->tail, skb->end, skb_headroom(skb), skb_tailroom(skb));

	log_wireguard_endpoint(&peer->endpoint);

	/* Initialize address pointers */
	struct sockaddr_in *source = NULL;
	struct sockaddr_in *dest = NULL;
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 *source6 = NULL;
	struct sockaddr_in6 *dest6 = NULL;
#endif
	if (!socket || !socket->sk)
		return -ENOTCONN;
	sk = socket->sk;

	/* Use the socket pinned by the reader. For outbound streams, derive the
	 * tuple from the connected socket so route-selected source addresses and
	 * ephemeral ports cannot be stale.
	 */
	if (socket == READ_ONCE(peer->inbound_socket)) {
		if (peer->inbound_source.ss_family == AF_INET) {
			source = (struct sockaddr_in *)&peer->inbound_dest;
			dest = (struct sockaddr_in *)&peer->inbound_source;
#if IS_ENABLED(CONFIG_IPV6)
		} else if (peer->inbound_source.ss_family == AF_INET6) {
			source6 = (struct sockaddr_in6 *)&peer->inbound_dest;
			dest6 = (struct sockaddr_in6 *)&peer->inbound_source;
#endif
		}
	} else if (sk->sk_family == AF_INET) {
		inet = inet_sk(sk);
		memset(&outbound_source, 0, sizeof(outbound_source));
		memset(&outbound_dest, 0, sizeof(outbound_dest));
		outbound_source.sin_family = AF_INET;
		outbound_source.sin_port = inet->inet_sport;
		outbound_source.sin_addr.s_addr = inet->inet_saddr;
		outbound_dest.sin_family = AF_INET;
		outbound_dest.sin_port = inet->inet_dport;
		outbound_dest.sin_addr.s_addr = inet->inet_daddr;
		source = &outbound_dest;
		dest = &outbound_source;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (sk->sk_family == AF_INET6) {
		inet = inet_sk(sk);
		memset(&outbound_source6, 0, sizeof(outbound_source6));
		memset(&outbound_dest6, 0, sizeof(outbound_dest6));
		outbound_source6.sin6_family = AF_INET6;
		outbound_source6.sin6_port = inet->inet_sport;
		outbound_source6.sin6_addr = inet6_sk(sk)->saddr;
		outbound_dest6.sin6_family = AF_INET6;
		outbound_dest6.sin6_port = inet->inet_dport;
		outbound_dest6.sin6_addr = sk->sk_v6_daddr;
		source6 = &outbound_dest6;
		dest6 = &outbound_source6;
#endif
	} else {
		return -EAFNOSUPPORT;
	}

	/* Check for paged data in the skb before forcibly linearizing it */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb) != 0) {
			printk(KERN_ERR "wg_tcp_build_fake_headers: Failed to linearize SKB.\n");
			return -ENOMEM;
		} else {
			skb_reset_tail_pointer(skb);
		}
	}

	/* Diagnostic: Print SKB state after linearization */
	wg_dbg("After skb_linearize: skb=%px, len=%d, head=%px, data=%px, tail=%u, end=%u, skb->len=%d, headroom=%d, tailroom=%d\n",
	       skb, skb->len, skb->head, skb->data, skb->tail, skb->end, skb->len, skb_headroom(skb), skb_tailroom(skb));

	/* Calculate the payload length: initial length of skb before any header is added */
	payload_len = skb->len;

	/* Push and reset for UDP header */
	skb_push(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	/* Diagnostic: Print UDP header location */
	wg_dbg("UDP header location: %px, length: %zu\n",
	       skb_transport_header(skb), sizeof(struct udphdr));

	/* Push and reset for IP header */
	if (source) {
		skb_push(skb, sizeof(struct iphdr));
		skb_reset_network_header(skb);
		wg_dbg("IPv4 header location: %px, length: %zu\n",
		       skb_network_header(skb), sizeof(struct iphdr));
#if IS_ENABLED(CONFIG_IPV6)
	} else if (source6) {
		skb_push(skb, sizeof(struct ipv6hdr));
		skb_reset_network_header(skb);
		wg_dbg("IPv6 header location: %px, length: %zu\n",
		       skb_network_header(skb), sizeof(struct ipv6hdr));
#endif
	} else {
		printk(KERN_ERR "wg_tcp_build_fake_headers: Unsupported address family.\n");
		return -EAFNOSUPPORT;
	}

	/* Diagnostic: Print SKB state after header manipulation */
	wg_dbg("After header manipulation: skb=%px, len=%d, head=%px, data=%px, tail=%u, end=%u, skb->len=%d, headroom=%d, tailroom=%d\n",
	       skb, skb->len, skb->head, skb->data, skb->tail, skb->end, skb->len, skb_headroom(skb), skb_tailroom(skb));

	/* Set UDP header fields */
	udph = udp_hdr(skb);
	if (source) { /* IPv4 case */
		udph->source = source->sin_port;
		udph->dest = dest->sin_port;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (source6) { /* IPv6 case */
		udph->source = source6->sin6_port;
		udph->dest = dest6->sin6_port;
#endif
	}
	udph->len = htons(sizeof(struct udphdr) + payload_len);
	udph->check = 0; /* Checksum will be calculated later */

	if (source) {
		/* Fill in the IPv4 header */
		iph = ip_hdr(skb);
		iph->version = 4;
		iph->ihl = 5;
		iph->tos = 0;
		iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len);
		iph->ttl = 64;
		iph->protocol = IPPROTO_UDP;
		iph->check = 0;
		iph->saddr = source->sin_addr.s_addr;
		iph->daddr = dest->sin_addr.s_addr;

		/* Calculate IP checksum */
		iph->check = ip_fast_csum((u8 *)iph, iph->ihl);

		/* Calculate UDP checksum for IPv4 */
		__wsum csum = csum_partial(udph, ntohs(udph->len), 0);
		udph->check = htons(csum_tcpudp_magic(iph->saddr, iph->daddr, udph->len, IPPROTO_UDP, csum));
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;

		skb->protocol = htons(ETH_P_IP);
#if IS_ENABLED(CONFIG_IPV6)
	} else if (source6) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		/* Fill in the IPv6 header */
		ip6h->version = 6;
		ip6h->priority = 0;
		memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
		ip6h->payload_len = htons(sizeof(struct udphdr) + payload_len);
		ip6h->nexthdr = IPPROTO_UDP;
		ip6h->hop_limit = 64;
		ip6h->saddr = source6->sin6_addr;
		ip6h->daddr = dest6->sin6_addr;

		/* Calculate UDP checksum for IPv6 */
		__wsum csum = csum_partial(udph, ntohs(udph->len), 0);
		csum = csum_partial(&ip6h->saddr, sizeof(struct in6_addr), csum);
		csum = csum_partial(&ip6h->daddr, sizeof(struct in6_addr), csum);
		csum = csum_add(csum, htons(ntohs(udph->len)));
		csum = csum_add(csum, htons(IPPROTO_UDP));

		udph->check = csum_fold(csum);
		if (udph->check == 0)
			udph->check = CSUM_MANGLED_0;

		/* endpoint_from_skb derives a link-local scope from skb_iif. Carry
		 * the accepted/dialed socket's scope through the synthetic datagram so
		 * authenticated roaming does not replace a scoped target with scope 0.
		 */
		skb->skb_iif = source6->sin6_scope_id;
		if (!skb->skb_iif)
			skb->skb_iif = READ_ONCE(sk->sk_bound_dev_if);
		skb->protocol = htons(ETH_P_IPV6);
#endif
	} else {
		printk(KERN_ERR "wg_tcp_build_fake_headers: Unsupported address family.\n");
		return -EAFNOSUPPORT;
	}

	/* Diagnostic: Print SKB state after header manipulation */
	wg_dbg("After header pull on exit: skb=%px, len=%d, head=%px, data=%px, tail=%u, end=%u, headroom=%d, tailroom=%d\n",
	       skb, skb->len, skb->head, skb->data, skb->tail, skb->end, skb_headroom(skb), skb_tailroom(skb));

	return 0;
}



void wg_tcp_read_worker(struct work_struct *work)
{

	wg_dbg("Entering function wg_tcp_read_worker\n");
	struct wg_tcp_frag_header frag_hdr;
	bool has_frag_header = false;
	struct wg_peer *peer = container_of(work, struct wg_peer, tcp_read_work);
	struct socket *socket = NULL;
	struct sock *sk;
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec vec;
	size_t packet_header_length;
	ssize_t read_bytes;
	unsigned int packets_processed = 0;
	bool budget_exhausted = false;
	struct sk_buff *new_skb = NULL;

	/* Pin the selected socket while holding the same lifetime lock used by
	 * removers. Once a remover publishes its flag, cancel_work_sync() keeps
	 * this socket alive until the reader returns.
	 */
	if (!peer || IS_ERR(peer))
		goto out;
	spin_lock_bh(&peer->tcp_lock);
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled && peer->tcp_established &&
	    peer->peer_socket && peer->peer_socket->sk) {
		socket = peer->peer_socket;
		sk = socket->sk;
	}
	spin_unlock_bh(&peer->tcp_lock);
	if (!socket)
		goto out;
	print_peer_socket_info(peer);
	while (true) {
		bool record_ready;

		wg_dbg("wg_peer diagnostic: partial_skb=%px, expected_len=%zu, received_len=%zu\n",
		       peer->partial_skb, peer->expected_len, peer->received_len);
		if (!peer->partial_skb) {
			wg_dbg("wg_tcp_read_worker: Allocating new skb.\n");
			/*
			 * Leave room for the maximum record and its synthetic
			 * network headers.
			 */
			new_skb = alloc_skb(WG_TCP_SKB_READ_ALLOC_SIZE +
					    WG_TCP_RESERVED_HEADER_SIZE +
					    NET_IP_ALIGN,
					    GFP_ATOMIC);
			if (!new_skb) {
				pr_err("WireGuard: Failed to allocate skb\n");
				break;
			}
			/* Reserve space for headers and align the data correctly */
			skb_reserve(new_skb, WG_TCP_RESERVED_HEADER_SIZE + NET_IP_ALIGN);

			peer->expected_len = 0;
			peer->partial_skb = new_skb;
		}
		record_ready = peer->expected_len ?
			peer->received_len >= peer->expected_len :
			peer->received_len >= WG_TCP_ENCAP_HDR_LEN;
		if (!record_ready) {
			/* Make sure we have enough room for at least an encapsulation header */
			if (skb_tailroom(peer->partial_skb) < WG_TCP_ENCAP_HDR_LEN) {
				wg_dbg("wg_tcp_read_worker: Reallocating skb to fit the encapsulation header.\n");
				new_skb = skb_copy_expand(peer->partial_skb, skb_headroom(peer->partial_skb),
							  WG_TCP_SKB_READ_ALLOC_SIZE + WG_TCP_RESERVED_HEADER_SIZE + NET_IP_ALIGN,
							  GFP_ATOMIC);
				if (!new_skb) {
					pr_err("WireGuard: Failed to reallocate skb\n");
					wg_peer_discard_partial_read(peer);
					break;
				}
				/* Replace the old skb with the new one */
				kfree_skb(peer->partial_skb);
				peer->partial_skb = new_skb;
			}
			/*
			 * Read as much data as fits into the skb buffer
			 * When reading more data, make sure to append after existing data
			 */
			vec.iov_base = skb_tail_pointer(peer->partial_skb);
			vec.iov_len = skb_tailroom(peer->partial_skb);
			if (!vec.iov_len)
				break;
			read_bytes = kernel_recvmsg(socket, &msg, &vec, 1,
					    vec.iov_len, msg.msg_flags);
			if (read_bytes > 0) {
#if WG_TCP_DIAG_ENABLED
				wg_tcp_diag_dump_sock(sk, "rx:recvmsg", read_bytes, vec.iov_len);
#endif
#if WG_TCP_DIAG_ENABLED
				atomic64_add(read_bytes, &wg_tcp_stats_rx_bytes);
#endif
			}
			if (read_bytes <= 0) {
				if (read_bytes == -EAGAIN) {
					wg_dbg("wg_tcp_read_worker: No more data available (-EAGAIN).\n");
					break; /* No more data available, exit the loop */
				} else if (read_bytes == 0) {
					wg_dbg("wg_tcp_read_worker: peer closed the TCP stream\n");
					wg_peer_discard_partial_read(peer);
					break;
				} else {
					pr_err("wg_tcp_read_worker: kernel_recvmsg error=%zd peer=%llu received_len=%zu expected_len=%zu\n",
						read_bytes, peer->internal_id, peer->received_len, peer->expected_len);
#if WG_TCP_DIAG_ENABLED
					wg_tcp_diag_dump_sock(sk, "rx:read_worker:error", read_bytes, vec.iov_len);
#endif
#if WG_TCP_DIAG_ENABLED
					atomic64_inc(&wg_tcp_stats_rx_errors);
#endif
					wg_peer_discard_partial_read(peer);
					break;
				}
			}
			/* Keep negative lengths out of the %*ph field width. */
			wg_dbg("wg_tcp_read_worker: kernel_recvmsg read %zd bytes: %*ph\n", read_bytes, (int)read_bytes, vec.iov_base);
			wg_dbg("wg_tcp_read_worker: Read %zd bytes, total "
				"received_len=%zu, expected_len=%zu\n", read_bytes,
				peer->received_len, peer->expected_len);
			skb_put(peer->partial_skb, read_bytes);
			peer->received_len += read_bytes;
		}
		/* check header */
		if (peer->received_len >= WG_TCP_ENCAP_HDR_LEN) {
			struct wg_tcp_encap_header header;

			/* Complete header received, validate and prepare for packet data */
			wg_dbg("wg_tcp_read_worker: We have a header, let's check it.\n");
			memcpy(&header, peer->partial_skb->data, sizeof(header));

			/* Enhanced header diagnostics */
			wg_dbg("wg_tcp_read_worker: Processing TCP Encap Header\n");
			wg_dbg("wg_tcp_read_worker: Raw header bytes: %*phN\n",
				(int)WG_TCP_ENCAP_HDR_LEN, &header);
			wg_dbg("wg_tcp_read_worker: Header fields - length=0x%08x (%u),"
				" type=%u, flags=0x%02x, checksum=0x%04x\n",
				header.length, ntohl(header.length), header.type,
				header.flags, ntohs(header.checksum));
			wg_dbg("wg_tcp_read_worker: Expected total packet "
				"size: %u bytes\n", ntohl(header.length));

			if (!wg_check_potential_header_validity(&header,
							peer->received_len)) {
				pr_debug_ratelimited(
					"WireGuard: Invalid TCP record header, attempting resynchronization\n");
				if (!wg_sync_header(peer, socket)) {
					/* A bounded suffix may be an incomplete header split
					 * across recvmsg calls. Keep it for data_ready rather
					 * than treating normal stream segmentation as damage.
					 */
					if (peer->partial_skb &&
					    peer->received_len < WG_TCP_ENCAP_HDR_LEN)
						break;
					pr_debug_ratelimited(
						"WireGuard: No valid TCP record header found\n");
					wg_peer_discard_partial_read(peer);
					break;
				}
#if defined(DEBUG) && defined(WG_TCP_FAULT_INJECTION)
				atomic64_inc(&wg_tcp_test_resyncs);
#endif
				/* Resynchronization can pull, free, or replace partial_skb.
				 * Copy and validate the selected candidate again before use.
				 */
				if (!peer->partial_skb ||
				    peer->received_len < WG_TCP_ENCAP_HDR_LEN) {
					wg_peer_discard_partial_read(peer);
					break;
				}
				memcpy(&header, peer->partial_skb->data,
				       sizeof(header));
				if (!wg_check_potential_header_validity(
					    &header, peer->received_len)) {
					wg_peer_discard_partial_read(peer);
					break;
				}
			}
			peer->expected_len = ntohl(header.length);
			wg_dbg("wg_tcp_read_worker: sk=%px hdr: total_len=%zu type=%u flags=0x%02x checksum=0x%04x received_len=%zu\n",
					 sk, peer->expected_len, header.type, header.flags,
					 ntohs(header.checksum), peer->received_len);
#if WG_TCP_DIAG_ENABLED
			wg_tcp_diag_dump_sock(sk, "rx:hdr", peer->received_len, peer->expected_len);
#endif
			/* Check for fragment header flag */
			if (header.flags & WG_TCP_FRAG_FLAG) {
				has_frag_header = true;
				packet_header_length = WG_TCP_ENCAP_HDR_LEN + WG_TCP_FRAG_HDR_LEN;
				wg_dbg("wg_tcp_read_worker: Fragment header flag detected\n");
			} else {
				has_frag_header = false;
				packet_header_length = WG_TCP_ENCAP_HDR_LEN;
			}
			wg_dbg("wg_tcp_read_worker: Set expected_len=%zu "
				"(includes %zu byte header)\n", peer->expected_len,
				packet_header_length);

		} else {
			/* not enough data */
			break;
		}
		wg_dbg("wg_tcp_read_worker: We have a header, let's process the packet body.\n");
		/*
		 * A read may contain the current record plus bytes from the
		 * next one.
		 */
		if (peer->received_len < peer->expected_len) {
			size_t needed = peer->expected_len - peer->received_len;

			if (skb_tailroom(peer->partial_skb) < needed) {
				wg_dbg("wg_tcp_read_worker: We need more data for a full packet expected len=%d received_len=%d\n", (int)peer->expected_len, (int)peer->received_len);
				wg_dbg("wg_tcp_read_worker: Expanding buffer to fit whole packet.\n");
				struct sk_buff *resized_skb = skb_copy_expand(peer->partial_skb,
									      skb_headroom(peer->partial_skb),
									      needed,
									      GFP_ATOMIC);
				if (!resized_skb) {
					pr_err("WireGuard: Failed to resize skb\n");
					wg_peer_discard_partial_read(peer);
					break;
				}
				if (peer->partial_skb)
					kfree_skb(peer->partial_skb);
				peer->partial_skb = resized_skb;
			}
		}
		wg_dbg("Expected Length: %zu Received Length: %zu\n", peer->expected_len, peer->received_len);
		wg_dbg("wg_tcp_read_worker: Packet complete check - Expected: %zu, Received: %zu\n",
			peer->expected_len, peer->received_len);

		/* Enhanced diagnostics for complete packet */
		if (peer->received_len >= peer->expected_len) {
		wg_dbg("wg_tcp_read_worker: Complete packet received, first 32 bytes: %*ph\n", min_t(int, peer->partial_skb->len, 32), peer->partial_skb->data);

		}
		/* Check if we've received the complete packet now */
		if (peer->received_len >= peer->expected_len && peer->received_len > WG_TCP_ENCAP_HDR_LEN) {
			wg_dbg("wg_tcp_read_worker: We have a complete packet.\n");

			if (has_frag_header) {
				__be32 *after_tcp_hdr = (__be32 *)(peer->partial_skb->data + WG_TCP_ENCAP_HDR_LEN);
				wg_dbg("wg_tcp_read_worker: After TCP "
					"header, next 4 bytes: 0x%08x\n", ntohl(*after_tcp_hdr));
				wg_dbg("wg_tcp_read_worker: After TCP header, "
					"next 16 bytes: %*ph\n",
					16, peer->partial_skb->data + WG_TCP_ENCAP_HDR_LEN);  /* BUG FIX: was missing width arg for %*ph */
			}

			if (has_frag_header) {
				/* BUG FIX: check for encap + frag header combined length,
				 * not just frag header alone (frag follows encap)
				 */
				if (peer->received_len >= WG_TCP_ENCAP_HDR_LEN + WG_TCP_FRAG_HDR_LEN) {
					memcpy(&frag_hdr,
					       peer->partial_skb->data + WG_TCP_ENCAP_HDR_LEN,
					       sizeof(frag_hdr));
					wg_dbg("wg_tcp_read_worker: Fragment header extracted - id=0x%04x, frag_off=0x%04x\n",
						ntohs(frag_hdr.id),
						ntohs(frag_hdr.frag_off));
				} else {
					pr_err("wg_tcp_read_worker: Not enough data for fragment header\n");
					break;
				}
			}

			/* Remove the encapsulation header from the skb */
			skb_pull(peer->partial_skb, packet_header_length);
			peer->received_len -= packet_header_length;
			peer->expected_len -= packet_header_length;

			wg_dbg("wg_tcp_read_worker: After removing "
				"encapsulation header - skb->len=%u, "
				"received_len=%zu, expected_len=%zu\n",
				peer->partial_skb->len, peer->received_len,
				peer->expected_len);

			wg_dbg("Packet: %px\n", peer->partial_skb->data);
			wg_dbg("partial_skb->len=%d received_len=%zu expected_len=%zu\n", peer->partial_skb->len, peer->received_len, peer->expected_len);
			/* Check if the skb has a valid length */
			if (unlikely(peer->partial_skb->len <= 0)) {
				pr_warn("wg_receive: Dropped packet with invalid length %d\n", peer->partial_skb->len);
				wg_peer_discard_partial_read(peer); /* Reset for the next packet */
				break;
			}
			/* Calculate leftover data length */
			size_t leftover_len = peer->received_len - peer->expected_len;
			struct sk_buff *leftover_skb = NULL;
			if (leftover_len > 0) {
				wg_dbg("wg_tcp_read_worker: Leftover data at "
					"end of packet, leftover_len=%zu\n", leftover_len);
				wg_dbg("wg_tcp_read_worker: Last %zu bytes of packet: %*ph\n",
					leftover_len, min_t(int, (int)leftover_len, 64),
					peer->partial_skb->data + peer->expected_len);

				leftover_skb = alloc_skb(leftover_len +
							 WG_TCP_RESERVED_HEADER_SIZE +
							 NET_IP_ALIGN,
							 GFP_ATOMIC);
				if (!leftover_skb) {
					pr_err("WireGuard: Failed to allocate leftover skb\n");
					break;
				}
				/*
				 * BUG FIX: only reserve header space, not the full alloc size,
				 * otherwise tailroom is zero and skb_put/copy overflows
				 */
				skb_reserve(leftover_skb, WG_TCP_RESERVED_HEADER_SIZE +
							 NET_IP_ALIGN);

				/* Diagnostic: Check skb pointers and lengths after skb_reserve */
				wg_dbg("wg_tcp_read_worker: leftover_skb after reserve: skb=%px, len=%d, headroom=%d, tailroom=%d\n",
						leftover_skb, leftover_skb->len, skb_headroom(leftover_skb), skb_tailroom(leftover_skb));

				/*
				 * BUG FIX: copy leftover data BEFORE trimming partial_skb,
				 * because skb_copy_bits fails when offset >= skb->len
				 * (skb_trim sets len = expected_len, making offset == len)
				 */
				if (skb_copy_bits(peer->partial_skb, peer->expected_len, leftover_skb->data, leftover_len) < 0) {
					pr_err("wg_tcp_read_worker: Failed to copy leftover data (offset=%zu, skb->len=%u, copy_len=%zu)\n",
						peer->expected_len, peer->partial_skb->len, leftover_len);
					kfree_skb(leftover_skb);
					leftover_skb = NULL;
					wg_peer_discard_partial_read(peer);
					break;
				}
				skb_put(leftover_skb, leftover_len);

				/* Now trim partial_skb after the copy is done */
				skb_trim(peer->partial_skb, peer->expected_len);

				wg_dbg("wg_tcp_read_worker: leftover_skb after copy, leftover_skb=%px, len=%d, headroom=%d, data=%px, tail=%u, end=%u\n",
					leftover_skb, leftover_skb->len, skb_headroom(leftover_skb), leftover_skb->data, leftover_skb->tail, leftover_skb->end);
			}
			skb_set_tail_pointer(peer->partial_skb, peer->expected_len);
			/* Store fragment info in packet_cb if we had a fragment header */
			if (has_frag_header) {
				PACKET_CB(peer->partial_skb)->frag_id =
					frag_hdr.id;
				PACKET_CB(peer->partial_skb)->frag_off =
					frag_hdr.frag_off;
			} else {
				PACKET_CB(peer->partial_skb)->frag_id = 0;
				PACKET_CB(peer->partial_skb)->frag_off = 0;
			}

			/* Build the UDP and IP headers */
			if (wg_tcp_build_fake_headers(peer->partial_skb, peer,
						      socket)) {
				pr_err("WireGuard: Failed to build UDP/IP headers\n");
				wg_peer_discard_partial_read(peer);
				break;
			}

			/* Restore fragment fields if present */
                       if (has_frag_header && peer->partial_skb->protocol == htons(ETH_P_IP)) {
                               struct iphdr *iph = ip_hdr(peer->partial_skb);
                               iph->id = frag_hdr.id;
                               iph->frag_off = frag_hdr.frag_off;
                               /* Recalculate IP checksum */
                               iph->check = 0;
                               iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
                               wg_dbg("wg_tcp_read_worker: Restored fragment fields to IP header\n");
                       }

			/* Process the complete packet */
			wg_dbg("wg_tcp_read_worker: partial_skb after trim, partial_skb=%px, len=%d, head=%px, data=%px, tail=%u, end=%u\n",
							peer->partial_skb, peer->partial_skb->len, peer->partial_skb->head,
							peer->partial_skb->data, peer->partial_skb->tail, peer->partial_skb->end);

			wg_dbg("wg_tcp_read_worker: DELIVER sk=%px peer=%llu payload_len=%u wg_type=%u frag_id=%u frag_off=0x%x leftover_len=%zu\n",
					 sk, peer->internal_id, peer->partial_skb->len,
					 wg_tcp_diag_peek_msg_type(peer->partial_skb),
					 ntohs(PACKET_CB(peer->partial_skb)->frag_id),
					 ntohs(PACKET_CB(peer->partial_skb)->frag_off),
					 leftover_len);
#if WG_TCP_DIAG_ENABLED
			wg_tcp_diag_dump_sock(sk, "rx:deliver", peer->partial_skb->len, peer->partial_skb->len);
#endif
#if WG_TCP_DIAG_ENABLED
			atomic64_inc(&wg_tcp_stats_rx_packets);
#endif
			wg_receive(sk, peer->partial_skb); /* wg_receive consumes the skb */

			peer->partial_skb = NULL; /* wg_receive ate the data skb */
			if (leftover_len > 0) {
				/* Store the leftover skb (if any) in peer->partial_skb */
				peer->partial_skb = leftover_skb;
				peer->received_len = leftover_len;

			} else {
				peer->received_len = 0;
			}
			peer->expected_len = 0; /* Reset for the next packet */
		}
		if (++packets_processed >= 64) {
			budget_exhausted = true;
			break;
		}
	}
out:
	/* Close the lost-wakeup window between the final nonblocking read and
	 * clearing the scheduled flag. data_ready uses the same lock, so either
	 * it queues the next worker or this worker observes pending receive data
	 * and queues itself again. tcp_lock is outermost, matching stream
	 * teardown, so no reader can be queued after a remover has claimed either
	 * socket and completed cancel_work_sync().
	 */
	spin_lock_bh(&peer->tcp_lock);
	spin_lock(&peer->tcp_read_lock);
	peer->tcp_read_worker_scheduled = false;
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled && peer->tcp_read_wq &&
	    socket && peer->peer_socket == socket && socket->sk &&
	    (!skb_queue_empty(&socket->sk->sk_receive_queue) ||
	     (budget_exhausted && peer->partial_skb &&
	      !peer->expected_len &&
	      peer->received_len >= WG_TCP_ENCAP_HDR_LEN))) {
		peer->tcp_read_worker_scheduled = true;
		queue_work(peer->tcp_read_wq, &peer->tcp_read_work);
	}
	spin_unlock(&peer->tcp_read_lock);
	spin_unlock_bh(&peer->tcp_lock);
	wg_dbg("Exiting function wg_tcp_read_worker\n");
}

void wg_tcp_data_ready(struct sock *sk)
{
	wg_dbg("Entering function wg_tcp_data_ready\n");

	/* Ensure the socket is valid */
	if (!sk || IS_ERR(sk)) {
		printk(KERN_ERR "wg_tcp_data_ready: Invalid socket\n");
		goto out;
	}

	/* Retrieve the socket user data */
	struct wg_socket_data *socket_data = sk->sk_user_data;

	/* Check if socket_data is valid */
	if (!socket_data || IS_ERR(socket_data)) {
		printk(KERN_ERR "wg_tcp_data_ready: Invalid or NULL socket_data\n");
		goto out;
	}

	/* Retrieve the peer from the socket_data */
	struct wg_peer *peer = socket_data->peer;

	/* Check if peer is valid or being torn down */
	if (!peer || IS_ERR(peer) || READ_ONCE(peer->is_dead)) {
		goto out;
	}
	if (peer->temp_peer)
		wg_touch_tcp_connection(peer);


	/* Match teardown's lifetime lock before taking the read scheduler lock.
	 * Queue while both are held so cancellation cannot miss newly claimed
	 * work after either socket removal has begun.
	 */
	spin_lock_bh(&peer->tcp_lock);
	spin_lock(&peer->tcp_read_lock);

	/* Check if the worker is already scheduled and wq still exists */
	if (!READ_ONCE(peer->is_dead) && !peer->tcp_stopping &&
	    READ_ONCE(peer->device->tcp_cleanup_scheduled) &&
	    !peer->tcp_outbound_remove_scheduled &&
	    !peer->tcp_inbound_remove_scheduled &&
	    !peer->tcp_read_worker_scheduled && peer->tcp_read_wq) {
	peer->tcp_read_worker_scheduled = true;
#if WG_TCP_DIAG_ENABLED
		wg_tcp_diag_dump_sock(sk, "data_ready", 0, 0);
#endif
		wg_dbg("wg_tcp_data_ready: schedule read worker peer=%llu sk=%px rcvq=%u\n",
				 peer->internal_id, sk, skb_queue_len(&sk->sk_receive_queue));
		queue_work(peer->tcp_read_wq, &peer->tcp_read_work);
	}

	spin_unlock(&peer->tcp_read_lock);
	spin_unlock_bh(&peer->tcp_lock);

out:
	/* BUG FIX: guard against NULL sk, sk_user_data, or peer —
	 * early goto out jumps here when any of these are invalid
	 */
	if (sk && sk->sk_user_data) {
		struct wg_socket_data *sd = (struct wg_socket_data *)sk->sk_user_data;
		struct wg_peer *p = sd->peer;
		if (p) {
			if (sd->inbound) {
				if (p->original_inbound_data_ready)
					p->original_inbound_data_ready(sk);
			} else {
				if (p->original_outbound_data_ready)
					p->original_outbound_data_ready(sk);
			}
		}
	}
	wg_dbg("Exiting function wg_tcp_data_ready\n");
}

void wg_tcp_write_space(struct sock *sk)
{
	wg_dbg("Entering function wg_tcp_write_space\n");
	struct wg_peer *peer;
	struct wg_socket_data *socket_data;
	if (!sk)
		goto out;
	socket_data = sk->sk_user_data;
	if (!socket_data || IS_ERR(socket_data))
		goto out;
	peer = socket_data->peer;
	if (!peer || IS_ERR(peer) || READ_ONCE(peer->is_dead)) {
		goto out;
	}
	if (!peer->tcp_write_wq) {
		wg_dbg("wg_tcp_write_space peer->tcp_write_wq is NULL\n");
		goto out;
	}

	wg_dbg("wg_tcp_write_space scheduling serial writer\n");
#if WG_TCP_DIAG_ENABLED
	wg_tcp_diag_dump_sock(sk, "write_space", 0, 0);
#endif
	wg_dbg("wg_tcp_write_space: schedule write worker peer=%llu sk=%px writeq=%u\n",
		 peer->internal_id, sk, skb_queue_len(&sk->sk_write_queue));
	wg_tcp_schedule_write(peer);
out:
	/* BUG FIX: guard against NULL sk, sk_user_data, or peer —
	 * early goto out jumps here when any of these are invalid
	 */
	if (sk && sk->sk_user_data) {
		struct wg_socket_data *sd = (struct wg_socket_data *)sk->sk_user_data;
		struct wg_peer *p = sd->peer;
		if (p) {
			if (sd->inbound) {
				if (p->original_inbound_write_space)
					p->original_inbound_write_space(sk);
			} else {
				if (p->original_outbound_write_space)
					p->original_outbound_write_space(sk);
			}
		}
	}
	wg_dbg("Exiting function wg_tcp_write_space\n");
}

void wg_setup_tcp_socket_callbacks(struct wg_peer *peer, bool inbound)
{
	wg_dbg("Entering function wg_setup_tcp_socket_callbacks\n");
	if (!peer || IS_ERR(peer)) {
		wg_dbg("Exiting function wg_setup_tcp_socket_callbacks, no peer.\n");
		return;
	}
	struct socket *target_socket = inbound ? peer->inbound_socket : peer->outbound_socket;

	if (!target_socket || (inbound ? peer->tcp_inbound_callbacks_set : peer->tcp_outbound_callbacks_set)) {
		wg_dbg("Exiting function wg_setup_tcp_socket_callbacks, nothing to do.\n");
		return;
	}

	struct sock *sk = target_socket->sk;
	struct wg_socket_data *socket_data;

	if (inbound)
		peer->tcp_inbound_callbacks_set = true;
	else
		peer->tcp_outbound_callbacks_set = true;

	/* Acquire lock to safely modify socket callbacks */
	write_lock_bh(&sk->sk_callback_lock);

	/* Check if sk_user_data is already allocated */
	socket_data = sk->sk_user_data;
	if (socket_data) {
		/* If already allocated, update the peer */
		wg_dbg("wg_setup_tcp_socket_callbacks: sk_user_data already exists, updating peer.\n");
		socket_data->device = peer->device;
		socket_data->peer = peer;
	} else {
		/* Allocate memory for wg_socket_data */
		socket_data = kzalloc(sizeof(*socket_data), GFP_ATOMIC);  /* BUG FIX: GFP_KERNEL can sleep; called under write_lock_bh */
		if (!socket_data) {
			printk(KERN_ERR "Failed to allocate memory for wg_socket_data\n");
			write_unlock_bh(&sk->sk_callback_lock);
			return;
		}

		/* Initialize wg_socket_data with device and peer */
		socket_data->device = peer->device;
		socket_data->peer = peer;
		socket_data->inbound = inbound;

		/* Set sk_user_data to the newly allocated socket_data */
		sk->sk_user_data = socket_data;
	}

	/* Save the original callbacks based on the direction (inbound or outbound) */
	if (inbound) {
		peer->original_inbound_state_change = sk->sk_state_change;
		peer->original_inbound_write_space = sk->sk_write_space;
		peer->original_inbound_data_ready = sk->sk_data_ready;
	} else {
		peer->original_outbound_state_change = sk->sk_state_change;
		peer->original_outbound_write_space = sk->sk_write_space;
		peer->original_outbound_data_ready = sk->sk_data_ready;
	}

	/* Assign new callbacks and pass `peer` as user data for callback functions */
	sk->sk_state_change = wg_tcp_state_change;
	sk->sk_write_space = wg_tcp_write_space;
	sk->sk_data_ready = wg_tcp_data_ready;

	write_unlock_bh(&sk->sk_callback_lock);
	wg_dbg("Exiting function wg_setup_tcp_socket_callbacks\n");
}

void wg_reset_tcp_socket_callbacks(struct wg_peer *peer, bool inbound)
{
	wg_dbg("Entering function wg_reset_tcp_socket_callbacks\n");
	struct sock *sk;
	struct socket *target_socket;

	/* BUG FIX: null check peer BEFORE dereferencing it */
	if (!peer || IS_ERR(peer)) {
		wg_dbg("Exiting function wg_reset_tcp_socket_callbacks, no peer.\n");
		return;
	}
	target_socket = inbound ? peer->inbound_socket : peer->outbound_socket;
	if (!target_socket || (inbound ? !peer->tcp_inbound_callbacks_set : !peer->tcp_outbound_callbacks_set)) {
		wg_dbg("Exiting function wg_reset_tcp_socket_callbacks, nothing to do.\n");
		return;
	}

	if (inbound)
		peer->tcp_inbound_callbacks_set = false;
	else
		peer->tcp_outbound_callbacks_set = false;

	sk = target_socket->sk;

	/* Lock the socket to safely update callback pointers */
	write_lock_bh(&sk->sk_callback_lock);

	/* Check if we previously saved original callbacks and restore them */
	if (inbound) {
		if (peer->original_inbound_state_change) {
			sk->sk_state_change = peer->original_inbound_state_change;
			peer->original_inbound_state_change = NULL;
		}
		if (peer->original_inbound_write_space) {
			sk->sk_write_space = peer->original_inbound_write_space;
			peer->original_inbound_write_space = NULL;
		}
		if (peer->original_inbound_data_ready) {
			sk->sk_data_ready = peer->original_inbound_data_ready;
			peer->original_inbound_data_ready = NULL;
		}
	} else {
		if (peer->original_outbound_state_change) {
			sk->sk_state_change = peer->original_outbound_state_change;
			peer->original_outbound_state_change = NULL;
		}
		if (peer->original_outbound_write_space) {
			sk->sk_write_space = peer->original_outbound_write_space;
			peer->original_outbound_write_space = NULL;
		}
		if (peer->original_outbound_data_ready) {
			sk->sk_data_ready = peer->original_outbound_data_ready;
			peer->original_outbound_data_ready = NULL;
		}
	}

	/* Clear the user data to avoid any dangling references */
	if (sk->sk_user_data)
		kfree(sk->sk_user_data);
	sk->sk_user_data = NULL;

	write_unlock_bh(&sk->sk_callback_lock);
	wg_dbg("Exiting function wg_reset_tcp_socket_callbacks\n");
}

void wg_tcp_retry_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, tcp_retry_work.work);
	bool queue_outbound_remove = false;
	bool removal_pending;
	int ret;

	wg_dbg("Entering function wg_tcp_retry_worker peer=%px\n", peer);
	spin_lock_bh(&peer->tcp_lock);
	peer->tcp_retry_scheduled = false;
	if (READ_ONCE(peer->is_dead) || peer->tcp_stopping ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP) {
		spin_unlock_bh(&peer->tcp_lock);
		goto out;
	}
	if (!peer->tcp_established && peer->tcp_pending) {
		/* Delegate destruction to the single outbound removal owner. It sets
		 * the lifetime flag before canceling stream work and releasing the
		 * socket, and reconnects after the old attempt is fully quiescent.
		 */
		peer->tcp_reconnect_requested = true;
		if (!peer->tcp_outbound_remove_scheduled) {
			peer->tcp_outbound_remove_scheduled = true;
			peer->tcp_outbound_remove_socket = peer->outbound_socket;
			queue_outbound_remove = true;
		}
	}
	if (queue_outbound_remove)
		mod_delayed_work(system_wq, &peer->tcp_outbound_remove_work, 0);
	removal_pending = peer->tcp_outbound_remove_scheduled;
	spin_unlock_bh(&peer->tcp_lock);
	if (removal_pending)
		goto out;

	ret = wg_tcp_connect(peer);
	if (ret < 0) {
		spin_lock_bh(&peer->tcp_lock);
		if (!peer->tcp_stopping && !peer->tcp_retry_scheduled) {
			peer->tcp_retry_scheduled = true;
			mod_delayed_work(system_wq, &peer->tcp_retry_work,
					 msecs_to_jiffies(30000));
		}
		spin_unlock_bh(&peer->tcp_lock);
	}

out:
	wg_dbg("Exiting function wg_tcp_retry_worker\n");
}

int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *receive_socket,
			      struct wg_peer *temp_peer)
{
	wg_dbg("Entering function wg_add_tcp_socket_to_list\n");
	struct wg_tcp_socket_list_entry *entry;
	struct wg_socket_data *socket_data;
	struct sockaddr_storage addr;
	int ret;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		pr_err("Failed to allocate wg_tcp_socket_list_entry\n");
		return -ENOMEM;
	}

	entry->tcp_socket = receive_socket;
	entry->temp_peer = temp_peer;  /* BUG FIX: store temp_peer in list entry */
	socket_data = receive_socket && receive_socket->sk ?
		READ_ONCE(receive_socket->sk->sk_user_data) : NULL;
	if (!socket_data || socket_data->peer != temp_peer ||
	    !socket_data->inbound) {
		kfree(entry);
		return -EINVAL;
	}
	entry->created_at = ktime_get();
	entry->timestamp = entry->created_at;
	entry->connection_id = atomic64_inc_return(
		&wg->tcp_connection_sequence);
	entry->admission_counted = true;
	entry->initializing = true;
	temp_peer->tcp_connection_id = entry->connection_id;

	memset(&addr, 0, sizeof(addr));

	ret = receive_socket->ops->getname(receive_socket,
					    (struct sockaddr *)&addr, 1);
	if (ret < 0 ||
	    !wg_sockaddr_length_valid((const struct sockaddr *)&addr, ret)) {
		pr_err("Failed to get peer address from socket\n");
		kfree(entry);
		return ret < 0 ? ret : -EINVAL;
	}
	if (!READ_ONCE(wg->tcp_cleanup_scheduled)) {
		kfree(entry);
		return -ESHUTDOWN;
	}

	memcpy(&entry->src_addr, &addr, sizeof(addr));

	spin_lock_bh(&wg->tcp_connection_list_lock);
	if (!READ_ONCE(wg->tcp_cleanup_scheduled) ||
	    wg->tcp_tracked_connections >= WG_TCP_MAX_TRACKED_CONNECTIONS ||
	    wg->tcp_pending_connections >= WG_TCP_MAX_PENDING_CONNECTIONS ||
	    wg_tcp_pending_from_source_locked(
		    wg, (const struct sockaddr *)&addr) >=
		    WG_TCP_MAX_PENDING_PER_SOURCE) {
		spin_unlock_bh(&wg->tcp_connection_list_lock);
		kfree(entry);
		return -ENOSPC;
	}
	/* Serialize carrier publication with live device-mark refresh. Either
	 * this write observes the new mark, or the updater sees the published
	 * entry and applies it while holding the same list lock.
	 */
	if (receive_socket->sk)
		WRITE_ONCE(receive_socket->sk->sk_mark, wg->fwmark);
	list_add_tail_rcu(&entry->tcp_connection_ll, &wg->tcp_connection_list);
	++wg->tcp_pending_connections;
	++wg->tcp_tracked_connections;
	spin_unlock_bh(&wg->tcp_connection_list_lock);
	/* Run once immediately, then the worker keeps checking live provisional
	 * sockets until the list is empty. mod_delayed_work also closes the race
	 * with a worker that is just finishing an empty-list pass.
	 */
	mod_delayed_work(system_wq, &wg->tcp_cleanup_work, 0);

	wg_dbg("Exiting function wg_add_tcp_socket_to_list\n");
	return 0;
}

static void wg_finish_tcp_connection_init(struct wg_device *wg,
					  struct socket *socket)
{
	struct wg_tcp_socket_list_entry *entry;
	bool cleanup = false;

	spin_lock_bh(&wg->tcp_connection_list_lock);
	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (entry->tcp_socket != socket)
			continue;
		if (!socket->sk ||
		    READ_ONCE(socket->sk->sk_state) != TCP_ESTABLISHED ||
		    !entry->temp_peer || IS_ERR(entry->temp_peer) ||
		    READ_ONCE(entry->temp_peer->is_dead)) {
			if (entry->temp_peer && !IS_ERR(entry->temp_peer))
				WRITE_ONCE(entry->temp_peer->is_dead, true);
			cleanup = true;
		}
		entry->initializing = false;
		break;
	}
	spin_unlock_bh(&wg->tcp_connection_list_lock);

	if (cleanup && READ_ONCE(wg->tcp_cleanup_scheduled))
		mod_delayed_work(system_wq, &wg->tcp_cleanup_work, 0);
}

static void wg_touch_tcp_connection(struct wg_peer *peer)
{
	struct wg_tcp_socket_list_entry *entry;
	struct wg_device *wg;

	if (!peer || IS_ERR(peer) || !peer->temp_peer || !peer->device)
		return;
	wg = peer->device;
	spin_lock_bh(&wg->tcp_connection_list_lock);
	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (entry->temp_peer == peer) {
			entry->timestamp = ktime_get();
			break;
		}
	}
	spin_unlock_bh(&wg->tcp_connection_list_lock);
}

static struct wg_tcp_socket_list_entry *
wg_claim_tcp_connection(struct wg_device *wg, struct socket *pending_socket,
			bool cleanup_only)
{
	struct wg_tcp_socket_list_entry *entry;
	struct wg_tcp_socket_list_entry *claimed = NULL;
	const ktime_t now = ktime_get();

	spin_lock_bh(&wg->tcp_connection_list_lock);
	list_for_each_entry(entry, &wg->tcp_connection_list, tcp_connection_ll) {
		if (pending_socket && entry->tcp_socket != pending_socket)
			continue;
		if (cleanup_only && entry->initializing)
			continue;
		if (cleanup_only && entry->temp_peer &&
		    !IS_ERR(entry->temp_peer) &&
		    !READ_ONCE(entry->temp_peer->is_dead) &&
		    (entry->authenticated ||
		     (ktime_ms_delta(now, entry->timestamp) <
			     WG_TCP_AUTH_IDLE_TIMEOUT_MS &&
		      ktime_ms_delta(now, entry->created_at) <
			     WG_TCP_AUTH_MAX_LIFETIME_MS)))
			continue;
		wg_tcp_release_admission_locked(wg, entry);
		if (WARN_ON_ONCE(!wg->tcp_tracked_connections))
			wg->tcp_tracked_connections = 0;
		else
			--wg->tcp_tracked_connections;
		list_del_rcu(&entry->tcp_connection_ll);
		claimed = entry;
		break;
	}
	spin_unlock_bh(&wg->tcp_connection_list_lock);
	if (claimed)
		synchronize_rcu();
	return claimed;
}

static void wg_destroy_temp_peer(struct wg_peer *peer)
{
	struct socket *socket;
	struct sock *sk;

	if (!peer || IS_ERR(peer))
		return;

	WRITE_ONCE(peer->is_dead, true);
	socket = peer->inbound_socket;
	sk = socket ? socket->sk : NULL;
	/* Wait out a callback that passed the is_dead check before canceling
	 * work that may dereference sk_user_data.
	 */
	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		write_unlock_bh(&sk->sk_callback_lock);
	}
	cancel_delayed_work_sync(&peer->tcp_retry_work);
	cancel_delayed_work_sync(&peer->tcp_outbound_remove_work);
	cancel_delayed_work_sync(&peer->tcp_inbound_remove_work);
	cancel_work_sync(&peer->tcp_read_work);
	cancel_work_sync(&peer->tcp_write_work);
	peer->tcp_read_worker_scheduled = false;
	peer->tcp_write_worker_scheduled = false;

	/* The workers are quiescent, so the wrapper can now be detached. */
	wg_reset_tcp_socket_callbacks(peer, true);
	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		if (sk->sk_user_data) {
			kfree(sk->sk_user_data);
			sk->sk_user_data = NULL;
		}
		write_unlock_bh(&sk->sk_callback_lock);
	}
	/* Both pointers reference the device-scoped provisional queue. It remains
	 * alive until every pending entry has been drained during device teardown.
	 */
	peer->tcp_read_wq = NULL;
	peer->tcp_write_wq = NULL;
	if (peer->partial_skb)
		kfree_skb(peer->partial_skb);
	skb_queue_purge(&peer->send_queue);

	peer->peer_socket = NULL;
	peer->inbound_socket = NULL;
	peer->outbound_socket = NULL;
	if (socket) {
		kernel_sock_shutdown(socket, SHUT_RDWR);
		sock_release(socket);
	}
	kfree(peer);
}

static void
wg_destroy_tcp_connection_entry(struct wg_device *wg,
				struct wg_tcp_socket_list_entry *entry)
{
	if (!entry)
		return;
	if (entry->temp_peer && !IS_ERR(entry->temp_peer)) {
		wg_destroy_temp_peer(entry->temp_peer);
	} else if (entry->tcp_socket) {
		kernel_sock_shutdown(entry->tcp_socket, SHUT_RDWR);
		sock_release(entry->tcp_socket);
	}
	kfree(entry);
}

void wg_remove_from_tcp_connection_list(struct wg_device *wg,
					struct socket *pending_socket)
{
	struct wg_tcp_socket_list_entry *entry;

	wg_dbg("Entering function wg_remove_from_tcp_connection_list\n");
	if (!wg || !pending_socket)
		return;
	entry = wg_claim_tcp_connection(wg, pending_socket, false);
	wg_destroy_tcp_connection_entry(wg, entry);
	wg_dbg("Exiting function wg_remove_from_tcp_connection_list\n");
}

void wg_tcp_outbound_remove_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, tcp_outbound_remove_work.work);
	struct socket *socket;
	struct sock *sk;
	bool clean_claim, reclaim_current = false;
	bool retry_needed, reconnect, stopping;
	int ret;

	wg_dbg("Entering function wg_tcp_outbound_remove _worker\n");
	spin_lock_bh(&peer->tcp_lock);
	socket = peer->tcp_outbound_remove_socket;
	clean_claim = socket ? peer->outbound_socket == socket :
				 !peer->outbound_socket;
	sk = clean_claim && socket ? socket->sk : NULL;
	spin_unlock_bh(&peer->tcp_lock);

	/* No new stream work is queued while the remove flag is set. Wait for
	 * callbacks that passed that check, then quiesce workers before freeing
	 * the sk_user_data wrapper.
	 */
	if (sk) {
		write_lock_bh(&sk->sk_callback_lock);
		write_unlock_bh(&sk->sk_callback_lock);
	}
	cancel_work_sync(&peer->tcp_read_work);
	cancel_work_sync(&peer->tcp_write_work);
	peer->tcp_read_worker_scheduled = false;
	peer->tcp_write_worker_scheduled = false;

	/* State change normally arms retry before removal. Preserve that intent,
	 * but cancel the old instance so it cannot race socket destruction or
	 * connect through the stale target.
	 */
	retry_needed = READ_ONCE(peer->tcp_retry_scheduled) ||
			 delayed_work_pending(&peer->tcp_retry_work);
	cancel_delayed_work_sync(&peer->tcp_retry_work);
	peer->tcp_retry_scheduled = false;
	if (clean_claim) {
		wg_reset_tcp_socket_callbacks(peer, false);
		wg_clean_peer_socket(peer, true, false, false);
	} else {
		/* Never let an old work item tear down a replacement socket. */
		reclaim_current = true;
	}

	spin_lock_bh(&peer->tcp_lock);
	reconnect = peer->tcp_reconnect_requested;
	stopping = peer->tcp_stopping;
	peer->tcp_reconnect_requested = false;
	peer->tcp_outbound_remove_scheduled = false;
	peer->tcp_outbound_remove_socket = NULL;
	spin_unlock_bh(&peer->tcp_lock);

	if (stopping || READ_ONCE(peer->is_dead) ||
	    !READ_ONCE(peer->device->tcp_cleanup_scheduled) ||
	    peer->device->transport != WG_TRANSPORT_TCP)
		goto out;
	if (reclaim_current) {
		wg_tcp_peer_request_reconnect(peer);
		goto out;
	}
	if (reconnect) {
		ret = wg_tcp_connect(peer);
		if (ret < 0) {
			spin_lock_bh(&peer->tcp_lock);
			if (!peer->tcp_stopping &&
			    !peer->tcp_retry_scheduled) {
				peer->tcp_retry_scheduled = true;
				mod_delayed_work(system_wq, &peer->tcp_retry_work,
						 msecs_to_jiffies(30000));
			}
			spin_unlock_bh(&peer->tcp_lock);
		}
	} else if (retry_needed) {
		spin_lock_bh(&peer->tcp_lock);
		if (!peer->tcp_stopping && !peer->tcp_retry_scheduled) {
			peer->tcp_retry_scheduled = true;
			mod_delayed_work(system_wq, &peer->tcp_retry_work,
					 msecs_to_jiffies(10000));
		}
		spin_unlock_bh(&peer->tcp_lock);
	}

out:
	wg_dbg("Exiting function wg_tcp_outbound_remove_worker\n");
}

void wg_tcp_inbound_remove_worker(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer, tcp_inbound_remove_work.work);

	wg_dbg("Entering function wg_tcp_inbound_remove _worker\n");

	if (peer->temp_peer) {
		WRITE_ONCE(peer->is_dead, true);
		if (READ_ONCE(peer->device->tcp_cleanup_scheduled))
			mod_delayed_work(system_wq,
					 &peer->device->tcp_cleanup_work, 0);
	} else {
		wg_reset_tcp_socket_callbacks(peer, true);
		wg_clean_peer_socket(peer, true, false, true); /* clean and release */
		spin_lock_bh(&peer->tcp_lock);
		peer->tcp_inbound_remove_scheduled = false;
		spin_unlock_bh(&peer->tcp_lock);
	}
	wg_dbg("Exiting function wg_inbound_remove_worker\n");
}

void wg_destruct_tcp_connection_list(struct wg_device *wg)
{
	struct wg_tcp_socket_list_entry *entry;

	wg_dbg("Entering function wg_destruct_tcp_connection_list\n");
	if (!wg)
		return;
	while ((entry = wg_claim_tcp_connection(wg, NULL, false)))
		wg_destroy_tcp_connection_entry(wg, entry);

	wg_dbg("Exiting function wg_destruct_tcp_connection_list\n");
}

void wg_tcp_cleanup_worker(struct work_struct *work)
{
	struct wg_device *wg = container_of(work, struct wg_device, tcp_cleanup_work.work);
	struct wg_tcp_socket_list_entry *entry;
	bool pending;

	wg_dbg("Entering function wg_tcp_cleanup_worker\n");
	while ((entry = wg_claim_tcp_connection(wg, NULL, true)))
		wg_destroy_tcp_connection_entry(wg, entry);
	spin_lock_bh(&wg->tcp_connection_list_lock);
	pending = !list_empty(&wg->tcp_connection_list);
	spin_unlock_bh(&wg->tcp_connection_list_lock);
	if (pending && READ_ONCE(wg->tcp_cleanup_scheduled))
		mod_delayed_work(system_wq, &wg->tcp_cleanup_work,
				 msecs_to_jiffies(WG_TCP_CLEANUP_INTERVAL_MS));
	wg_dbg("Exiting function wg_tcp_cleanup_worker\n");
}

struct wg_peer *wg_temp_peer_create(struct wg_device *wg)
{
	struct wg_peer *peer;
	int ret = -ENOMEM;

	wg_dbg("wg_peer_create: entry with wg=%px\n", wg);

	peer = kzalloc(sizeof(struct wg_peer), GFP_KERNEL);  /* BUG FIX: was kmalloc — left spinlocks, wq ptrs, flags uninitialized */
	if (unlikely(!peer)) {
		wg_dbg("wg_temp_peer_create: exit with ERR_PTR(ret)\n");
		return ERR_PTR(ret);
	}

	peer->device = wg;
	rwlock_init(&peer->endpoint_lock);

	/* initialize TCP fields */
	peer->peer_socket = NULL; /* Initialize the peer socket to NULL */

	/* Initialize the original socket callbacks to NULL */
	peer->original_outbound_state_change = NULL;
	peer->original_outbound_write_space = NULL;
	peer->original_outbound_data_ready = NULL;
	peer->original_outbound_error_report = NULL;
	peer->original_outbound_destruct = NULL;

	peer->original_inbound_state_change = NULL;
	peer->original_inbound_write_space = NULL;
	peer->original_inbound_data_ready = NULL;
	peer->original_inbound_error_report = NULL;
	peer->original_inbound_destruct = NULL;

	peer->partial_skb = NULL; /* Initialize the partial skb pointer to NULL */
	peer->expected_len = 0; /* Initialize expected length to 0 */
	peer->received_len = 0; /* Initialize received length to 0 */

	/* Initialize the delayed work for TCP connection retry */
	INIT_DELAYED_WORK(&peer->tcp_retry_work, wg_tcp_retry_worker);

	/* Initialize the delayed work for TCP socket removal */
	INIT_DELAYED_WORK(&peer->tcp_inbound_remove_work, wg_tcp_inbound_remove_worker);
	INIT_DELAYED_WORK(&peer->tcp_outbound_remove_work, wg_tcp_outbound_remove_worker);

	/* Initialize TCP connection status flags */
	peer->tcp_established = false;
	peer->tcp_pending = false;
	peer->tcp_connecting = false;
	peer->tcp_inbound_callbacks_set = false;
	peer->tcp_outbound_callbacks_set = false;
	peer->clean_inbound = false;
	peer->clean_outbound = false;
	peer->inbound_connected = false;
	peer->outbound_connected = false;
	peer->tcp_retry_scheduled = false;
	peer->tcp_inbound_remove_scheduled = false;
	peer->tcp_outbound_remove_scheduled = false;
	peer->tcp_reconnect_requested = false;
	peer->tcp_stopping = false;
	peer->tcp_outbound_remove_socket = NULL;
	peer->tcp_roaming_connection_id = 0;

	/* Initialize the spinlock for protecting TCP-related state */
	spin_lock_init(&peer->tcp_lock);

	/* Initialize the skb queue for the TX send queue */
	skb_queue_head_init(&peer->send_queue);

	/* Initialize the spinlock for the TX send queue */
	spin_lock_init(&peer->send_queue_lock);

	/* BUG FIX: tcp_read_lock and tcp_write_lock were never initialized —
	 * using uninitialized spinlocks in data_ready/write_space is UB/crash
	 */
	spin_lock_init(&peer->tcp_read_lock);
	spin_lock_init(&peer->tcp_write_lock);

	/* Initialize the work structure, associating it with the worker functions */
	INIT_WORK(&peer->tcp_read_work, wg_tcp_read_worker);
	peer->tcp_read_wq = wg->tcp_auth_wq;

	INIT_WORK(&peer->tcp_write_work, wg_tcp_write_worker);
	peer->tcp_write_wq = wg->tcp_auth_wq;
	if (!peer->tcp_read_wq) {
		pr_err("Provisional TCP workqueue is unavailable\n");
		goto err;
	}

	/* Note this is a temp peer */
	peer->temp_peer = true;

	pr_debug("%s: Temp Peer %llu created\n", wg->dev->name, peer->internal_id);
	wg_dbg("wg_temp_peer_create: exit with peer=%px\n", peer);
	return peer;

err:
	kfree(peer);
	wg_dbg("wg_temp_peer_create: exit with ERR_PTR(ret) on err\n");
	return ERR_PTR(ret);
}

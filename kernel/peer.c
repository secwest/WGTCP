// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#include "peer.h"
#include "device.h"
#include "queueing.h"
#include "timers.h"
#include "peerlookup.h"
#include "noise.h"
#include "socket.h"

#include <linux/kref.h>
#include <linux/lockdep.h>
#include <linux/rcupdate.h>
#include <linux/list.h>
#include <linux/wireguard.h>
#include "wg_tcp_debug.h"

static struct kmem_cache *peer_cache;
static atomic64_t peer_counter = ATOMIC64_INIT(0);

void wg_clean_peer_socket(struct wg_peer *peer, bool release, bool destroy, bool inbound);
void wg_reset_tcp_socket_callbacks(struct wg_peer *peer, bool inbound);

struct wg_peer *wg_peer_create(struct wg_device *wg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN])
{
	wg_dbg("wg_peer_create: entry with wg=%px, public_key=%px, preshared_key=%px\n", wg, public_key, preshared_key);
	struct wg_peer *peer;
	int ret = -ENOMEM;

	lockdep_assert_held(&wg->device_update_lock);

	if (wg->num_peers >= MAX_PEERS_PER_DEVICE) {
		wg_dbg("wg_peer_create: exit with ERR_PTR(ret)\n");
		return ERR_PTR(ret);
	}

	peer = kmem_cache_zalloc(peer_cache, GFP_KERNEL);
	if (unlikely(!peer)) {
		wg_dbg("wg_peer_create: exit with ERR_PTR(ret)\n");
		return ERR_PTR(ret);
	}
	if (unlikely(dst_cache_init(&peer->endpoint_cache, GFP_KERNEL))) {
		goto err_free_peer;
	}

	peer->device = wg;
	wg_noise_handshake_init(&peer->handshake, &wg->static_identity,
				public_key, preshared_key, peer);
	peer->internal_id = atomic64_inc_return(&peer_counter);
	peer->serial_work_cpu = nr_cpumask_bits;
	wg_cookie_init(&peer->latest_cookie);
	wg_timers_init(peer);
	wg_cookie_checker_precompute_peer_keys(peer);
	spin_lock_init(&peer->keypairs.keypair_update_lock);
	INIT_WORK(&peer->transmit_handshake_work, wg_packet_handshake_send_worker);
	INIT_WORK(&peer->transmit_packet_work, wg_packet_tx_worker);
	wg_prev_queue_init(&peer->tx_queue);
	wg_prev_queue_init(&peer->rx_queue);
	rwlock_init(&peer->endpoint_lock);
	kref_init(&peer->refcount);
	skb_queue_head_init(&peer->staged_packet_queue);
	wg_noise_reset_last_sent_handshake(&peer->last_sent_handshake);
	/* TCP field initialization */
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

	/* Initialize the TCP retry scheduled flag to false */
	peer->tcp_retry_scheduled = false;

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
	peer->tcp_outbound_remove_scheduled = false;
	peer->tcp_reconnect_requested = false;
	peer->tcp_stopping = false;
	peer->tcp_outbound_remove_socket = NULL;
	peer->tcp_roaming_connection_id = 0;
	peer->tcp_inbound_remove_scheduled = false;
	peer->peer_endpoint_set = false;

	/* Initialize the spinlock for protecting TCP-related state */
	spin_lock_init(&peer->tcp_lock);
	spin_lock_init(&peer->tcp_read_lock);
	spin_lock_init(&peer->tcp_write_lock);

	/* Initialize the skb queue for the TX send queue */
	skb_queue_head_init(&peer->send_queue);

	/* Initialize the spinlock for the TX send queue */
	spin_lock_init(&peer->send_queue_lock);

	/* Initialize the list head for pending connection list */
	INIT_LIST_HEAD(&peer->pending_connection_list);

	/* Initialize the work structure, associating it with the worker functions */
	INIT_WORK(&peer->tcp_read_work, wg_tcp_read_worker);
	INIT_WORK(&peer->tcp_write_work, wg_tcp_write_worker);
	if (wg->transport == WG_TRANSPORT_TCP) {
		peer->tcp_read_wq = alloc_workqueue("tcp_read_wq",
						    WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
		if (!peer->tcp_read_wq) {
			pr_err("Failed to allocate read workqueue\n");
			goto err_destroy_endpoint_cache;
		}

		peer->tcp_write_wq = alloc_workqueue("tcp_write_wq",
						     WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
		if (!peer->tcp_write_wq) {
			pr_err("Failed to allocate write workqueue\n");
			goto err_destroy_tcp_read_wq;
		}
	}

	/* Indicate this is a real peer not a temp peer */
	peer->temp_peer = false;
	peer->peer_endpoint = peer->endpoint;

	set_bit(NAPI_STATE_NO_BUSY_POLL, &peer->napi.state);
	netif_napi_add(wg->dev, &peer->napi, wg_packet_rx_poll);
	napi_enable(&peer->napi);
	list_add_tail(&peer->peer_list, &wg->peer_list);
	INIT_LIST_HEAD(&peer->allowedips_list);
	wg_pubkey_hashtable_add(wg->peer_hashtable, peer);

	++wg->num_peers;
	pr_debug("%s: Peer %llu created\n", wg->dev->name, peer->internal_id);
	wg_dbg("wg_peer_create: exit with peer=%px\n", peer);
	return peer;

err_destroy_tcp_read_wq:
	destroy_workqueue(peer->tcp_read_wq);
err_destroy_endpoint_cache:
	dst_cache_destroy(&peer->endpoint_cache);
err_free_peer:
	kmem_cache_free(peer_cache, peer);
	wg_dbg("wg_peer_create: exit with ERR_PTR(ret) on err\n");
	return ERR_PTR(ret);
}

struct wg_peer *wg_peer_get_maybe_zero(struct wg_peer *peer)
{
	wg_dbg("wg_peer_get_maybe_zero: entry with peer=%px\n", peer);
	RCU_LOCKDEP_WARN(!rcu_read_lock_bh_held(),
			 "Taking peer reference without holding the RCU read lock");
	if (unlikely(!peer || !kref_get_unless_zero(&peer->refcount))) {
		wg_dbg("wg_peer_get_maybe_zero: exit with NULL\n");
		return NULL;
	}
	wg_dbg("wg_peer_get_maybe_zero: exit with peer=%px\n", peer);
	return peer;
}



static void peer_make_dead(struct wg_peer *peer)
{
	wg_dbg("peer_make_dead: entry with peer=%px\n", peer);
	if(!peer || IS_ERR(peer)){
		wg_dbg("Exiting function peer_remove_after_dead, no peer.\n");
		return;
	}

	/* Remove from configuration-time lookup structures. */
	list_del_init(&peer->peer_list);
	wg_allowedips_remove_by_peer(&peer->device->peer_allowedips, peer,
				     &peer->device->device_update_lock);
	wg_pubkey_hashtable_remove(peer->device->peer_hashtable, peer);

	/* Mark as dead, so that we don't allow jumping contexts after. */
	WRITE_ONCE(peer->is_dead, true);

	/* Reset socket callbacks BEFORE destroying workqueues to prevent
	 * callbacks from firing queue_work on already-destroyed wqs.
	 */
	wg_reset_tcp_socket_callbacks(peer, false);
	wg_reset_tcp_socket_callbacks(peer, true);

	/* Cancel any pending remove/retry delayed work (non-sync to avoid
	 * self-deadlock if called from a remove worker context).
	 */
	cancel_delayed_work(&peer->tcp_outbound_remove_work);
	peer->tcp_outbound_remove_scheduled = false;
	peer->tcp_outbound_remove_socket = NULL;
	peer->tcp_reconnect_requested = false;
	peer->tcp_stopping = true;
	cancel_delayed_work(&peer->tcp_inbound_remove_work);
	peer->tcp_inbound_remove_scheduled = false;
	cancel_delayed_work(&peer->tcp_retry_work);
	peer->tcp_retry_scheduled = false;

	/* Check if the TCP read work is scheduled before canceling it */
	if (peer->tcp_read_worker_scheduled) {
		cancel_work_sync(&peer->tcp_read_work);
		peer->tcp_read_worker_scheduled = false;
	}

	/* Destroy the TCP read workqueue if it exists */
	if (peer->tcp_read_wq) {
		destroy_workqueue(peer->tcp_read_wq);
		peer->tcp_read_wq = NULL; /* Avoid dangling pointers */
	}

	/* Check if the TCP write work is scheduled before canceling it */
	if (peer->tcp_write_worker_scheduled) {
		cancel_work_sync(&peer->tcp_write_work);
		peer->tcp_write_worker_scheduled = false; /* Reset the flag after canceling */
    	}

	/* Destroy the TCP write workqueue if it exists */
	if (peer->tcp_write_wq) {
		destroy_workqueue(peer->tcp_write_wq);
		peer->tcp_write_wq = NULL; /* Avoid dangling pointers */
	}

	/* clean up any partial TCP data if it exists */
	if (peer->partial_skb) {
		kfree_skb(peer->partial_skb);
	    	peer->partial_skb = NULL;
	}

	/* The caller must now synchronize_net() for this to take effect. */
	wg_dbg("peer_make_dead: exit\n");
}

static void peer_remove_after_dead(struct wg_peer *peer)
{
	wg_dbg("peer_remove_after_dead: entry with peer=%px\n", peer);
	WARN_ON(!peer->is_dead);

	/* No more keypairs can be created for this peer, since is_dead protects
	 * add_new_keypair, so we can now destroy existing ones.
	 */
	wg_noise_keypairs_clear(&peer->keypairs);

	/* Destroy all ongoing timers that were in-flight at the beginning of
	 * this function.
	 */
	wg_timers_stop(peer);

	/* The transition between packet encryption/decryption queues isn't
	 * guarded by is_dead, but each reference's life is strictly bounded by
	 * two generations: once for parallel crypto and once for serial
	 * ingestion, so we can simply flush twice, and be sure that we no
	 * longer have references inside these queues.
	 */

	/* a) For encrypt/decrypt. */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.1) For send (but not receive, since that's napi). */
	flush_workqueue(peer->device->packet_crypt_wq);
	/* b.2.1) For receive (but not send, since that's wq). */
	napi_disable(&peer->napi);
	/* b.2.1) It's now safe to remove the napi struct, which must be done
	 * here from process context.
	 */
	netif_napi_del(&peer->napi);

	/* Ensure any workstructs we own (like transmit_handshake_work or
	 * clear_peer_work) no longer are in use.
	 */
	flush_workqueue(peer->device->handshake_send_wq);

	/* After the above flushes, a peer might still be active in a few
	 * different contexts: 1) from xmit(), before hitting is_dead and
	 * returning, 2) from wg_packet_consume_data(), before hitting is_dead
	 * and returning, 3) from wg_receive_handshake_packet() after a point
	 * where it has processed an incoming handshake packet, but where
	 * all calls to pass it off to timers fails because of is_dead. We won't
	 * have new references in (1) eventually, because we're removed from
	 * allowedips; we won't have new references in (2) eventually, because
	 * wg_index_hashtable_lookup will always return NULL, since we removed
	 * all existing keypairs and no more can be created; we won't have new
	 * references in (3) eventually, because we're removed from the pubkey
	 * hash table, which allows for a maximum of one handshake response,
	 * via the still-uncleared index hashtable entry, but not more than one,
	 * and in wg_cookie_message_consume, the lookup eventually gets a peer
	 * with a refcount of zero, so no new reference is taken.
	 */

	--peer->device->num_peers;
	wg_peer_put(peer);
	wg_dbg("peer_remove_after_dead: exit\n");
}

/* We have a separate "remove" function make sure that all active places where
 * a peer is currently operating will eventually come to an end and not pass
 * their reference onto another context.
 */
void wg_peer_remove(struct wg_peer *peer)
{
	wg_dbg("wg_peer_remove: entry with peer=%px\n", peer);
	if (unlikely(!peer)) {
		wg_dbg("wg_peer_remove: exit (peer is NULL)\n");
		return;
	}
	lockdep_assert_held(&peer->device->device_update_lock);
	/* Claim both directions, detach callbacks, and quiesce stream workers
	 * before either socket or its sk_user_data wrapper can be released.
	 */
	wg_tcp_peer_stop(peer);
	peer_make_dead(peer);
	synchronize_net();
	peer_remove_after_dead(peer);
	wg_dbg("wg_peer_remove: exit\n");
}

void wg_peer_remove_all(struct wg_device *wg)
{
	wg_dbg("wg_peer_remove_all: entry with wg=%px\n", wg);
	struct wg_peer *peer, *temp;
	LIST_HEAD(dead_peers);

	lockdep_assert_held(&wg->device_update_lock);

	/* Avoid having to traverse individually for each one. */
	wg_allowedips_free(&wg->peer_allowedips, &wg->device_update_lock);

	/* First pass: claim and quiesce both TCP directions for every peer before
	 * peer_make_dead destroys their workqueues.
	 */
	list_for_each_entry(peer, &wg->peer_list, peer_list)
		wg_tcp_peer_stop(peer);

	list_for_each_entry_safe(peer, temp, &wg->peer_list, peer_list) {
		peer_make_dead(peer);
		list_add_tail(&peer->peer_list, &dead_peers);
	}
	synchronize_net();
	list_for_each_entry_safe(peer, temp, &dead_peers, peer_list)
		peer_remove_after_dead(peer);
	wg_dbg("wg_peer_remove_all: exit\n");
}

static void rcu_release(struct rcu_head *rcu)
{
	wg_dbg("rcu_release: entry with rcu=%px\n", rcu);
	struct wg_peer *peer = container_of(rcu, struct wg_peer, rcu);

	dst_cache_destroy(&peer->endpoint_cache);
	WARN_ON(wg_prev_queue_peek(&peer->tx_queue) || wg_prev_queue_peek(&peer->rx_queue));

	/* The final zeroing takes care of clearing any remaining handshake key
	 * material and other potentially sensitive information.
	 */
	memzero_explicit(peer, sizeof(*peer));
	kmem_cache_free(peer_cache, peer);
	wg_dbg("rcu_release: exit\n");
}

static void kref_release(struct kref *refcount)
{
	wg_dbg("kref_release: entry with refcount=%px\n", refcount);
	struct wg_peer *peer = container_of(refcount, struct wg_peer, refcount);

	pr_debug("%s: Peer %llu (%pISpfsc) destroyed\n",
		 peer->device->dev->name, peer->internal_id,
		 &peer->endpoint.addr);

	/* Remove ourself from dynamic runtime lookup structures, now that the
	 * last reference is gone.
	 */
	wg_index_hashtable_remove(peer->device->index_hashtable,
				  &peer->handshake.entry);

	/* Remove any lingering packets that didn't have a chance to be
	 * transmitted.
	 */
	wg_packet_purge_staged_packets(peer);

	/* Free the memory used. */
	call_rcu(&peer->rcu, rcu_release);
	wg_dbg("kref_release: exit\n");
}

void wg_peer_put(struct wg_peer *peer)
{
	wg_dbg("wg_peer_put: entry with peer=%px\n", peer);
	if (unlikely(!peer)) {
		wg_dbg("wg_peer_put: exit (peer is NULL)\n");
		return;
	}
	kref_put(&peer->refcount, kref_release);
	wg_dbg("wg_peer_put: exit\n");
}

int __init wg_peer_init(void)
{
	wg_dbg("wg_peer_init: entry\n");
	peer_cache = KMEM_CACHE(wg_peer, 0);
	wg_dbg("wg_peer_init: exit with %d\n", peer_cache ? 0 : -ENOMEM);
	return peer_cache ? 0 : -ENOMEM;
}

void wg_peer_uninit(void)
{
	wg_dbg("wg_peer_uninit: entry\n");
	kmem_cache_destroy(peer_cache);
	wg_dbg("wg_peer_uninit: exit\n");
}

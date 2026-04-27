/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#ifndef _WG_PEER_H
#define _WG_PEER_H

#include "device.h"
#include "noise.h"
#include "cookie.h"

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/spinlock.h>
#include <linux/kref.h>
#include <net/dst_cache.h>

struct wg_device;


struct wg_tcp_transfer_work {
    struct work_struct work;
    struct sk_buff *skb;
    struct wg_peer *peer;
};

struct wg_peer {
	struct wg_device *device;
	struct prev_queue tx_queue, rx_queue;
	struct sk_buff_head staged_packet_queue;
	int serial_work_cpu;
	bool is_dead;
	struct noise_keypairs keypairs;
	struct endpoint endpoint, tcp_reply_endpoint, peer_endpoint;
	struct dst_cache endpoint_cache;
	rwlock_t endpoint_lock;
	struct noise_handshake handshake;
	atomic64_t last_sent_handshake;
	struct work_struct transmit_handshake_work, clear_peer_work, transmit_packet_work;
	struct cookie latest_cookie;
	struct hlist_node pubkey_hash;
	u64 rx_bytes, tx_bytes;
	struct timer_list timer_retransmit_handshake, timer_send_keepalive;
	struct timer_list timer_new_handshake, timer_zero_key_material;
	struct timer_list timer_persistent_keepalive;
	unsigned int timer_handshake_attempts;
	u16 persistent_keepalive_interval;
	bool timer_need_another_keepalive;
	bool sent_lastminute_handshake;
	struct timespec64 walltime_last_handshake;
	struct kref refcount;
	struct rcu_head rcu;
	struct list_head peer_list;
	struct list_head allowedips_list;
	struct napi_struct napi;
	u64 internal_id;

        // TCP-related members
	bool peer_endpoint_set;
	struct socket *peer_socket, *inbound_socket, *outbound_socket;
	void (*original_outbound_state_change)(struct sock *sk);
	void (*original_outbound_write_space)(struct sock *sk);
	void (*original_outbound_data_ready)(struct sock *sk);
	void (*original_outbound_error_report)(struct sock *sk);
	void (*original_outbound_destruct)(struct sock *sk);
	void (*original_inbound_state_change)(struct sock *sk);
	void (*original_inbound_write_space)(struct sock *sk);
	void (*original_inbound_data_ready)(struct sock *sk);
	void (*original_inbound_error_report)(struct sock *sk);
	void (*original_inbound_destruct)(struct sock *sk);
	bool tcp_outbound_callbacks_set;			// Flag to track if the inbound socket callbacks have been set
	bool tcp_inbound_callbacks_set;				// Flag to track if the inbound socket callbacks have been set
	ktime_t outbound_timestamp, inbound_timestamp;	// timestamps for connections
	struct sockaddr_storage	inbound_source, outbound_source, inbound_dest, outbound_dest;

	struct sk_buff *partial_skb;
	size_t expected_len;
	size_t received_len;

	struct delayed_work tcp_retry_work;	// Work for retrying TCP connection
	bool tcp_retry_scheduled;		// Flag to track connect retry scheduling

	struct delayed_work tcp_outbound_remove_work;	// Work for removing outbound peer TCP connection
	bool tcp_outbound_remove_scheduled;		// Flag to track outbound peer removal scheduling
	struct delayed_work tcp_inbound_remove_work;	// Work for removing inbound peer TCP connection
	bool tcp_inbound_remove_scheduled;		// Flag to track inbound peer removal scheduling

	struct delayed_work tcp_cleanup_work;	// Work for removing TCP connections in pending list
	bool tcp_cleanup_scheduled;		// Flag to track removal scheduling

	bool tcp_established;			// Flag to track TCP connection status
	bool tcp_pending;			// Flag to track outbount pending TCP connection status
	bool inbound_connected;			// peer connected to us
	bool outbound_connected;		// we connected to them
	bool clean_outbound;			// release outbound at next cleanup
	bool clean_inbound;			// release inbound at next cleanup
	bool temp_peer;				// is this a temporary peer


	struct sk_buff_head send_queue;		// TX queue
        spinlock_t send_queue_lock;		// TX lock

	struct list_head pending_connection_list;	//peers pending connection handshake
	spinlock_t tcp_lock;			// Protects TCP-related state

	struct work_struct tcp_read_work;	// Work struct for scheduling the worker
	struct workqueue_struct *tcp_read_wq;	// Workqueue for handling TCP data processing
	spinlock_t tcp_read_lock;		// Spinlock to protect access to the socket data
	bool tcp_read_worker_scheduled;		// Flag to indicate if the TCP read worker is scheduled

	struct work_struct tcp_write_work;      // Work struct for scheduling the worker
	struct workqueue_struct *tcp_write_wq;	// Workqueue for handling TCP data processing
	spinlock_t tcp_write_lock;              // Spinlock to protect access to the socket data
	bool tcp_write_worker_scheduled; 	// Flag to indicate if the TCP write worker is scheduled

};



struct wg_peer *wg_peer_create(struct wg_device *wg,
			       const u8 public_key[NOISE_PUBLIC_KEY_LEN],
			       const u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN]);

struct wg_peer *__must_check wg_peer_get_maybe_zero(struct wg_peer *peer);
static inline struct wg_peer *wg_peer_get(struct wg_peer *peer)
{
	kref_get(&peer->refcount);
	return peer;
}
void wg_peer_put(struct wg_peer *peer);
void wg_peer_remove(struct wg_peer *peer);
void wg_peer_remove_all(struct wg_device *wg);

int wg_peer_init(void);
void wg_peer_uninit(void);

void wg_peer_tcp_connect(struct work_struct *work);
void wg_peer_tcp_send(struct work_struct *work);
void wg_peer_tcp_receive(struct work_struct *work);
void wg_tcp_inbound_remove_worker(struct work_struct *work);
void wg_tcp_outbound_remove_worker(struct work_struct *work);

void wg_tcp_retry_worker(struct work_struct *work);

#endif /* _WG_PEER_H */

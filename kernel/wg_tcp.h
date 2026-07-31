/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2024-2026 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#ifndef _WG_TCP_H
#define _WG_TCP_H

#include <linux/stddef.h>
#include <linux/types.h>

struct endpoint;
struct net;
struct sk_buff;
struct sock;
struct socket;
struct work_struct;
struct wg_device;
struct wg_peer;
struct wg_tcp_encap_header;

struct wg_socket_data {
	struct wg_device *device;
	struct wg_peer *peer;
	bool inbound;
};

int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb,
			       u8 ds);
void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_configured(struct wg_peer *peer,
					    const struct endpoint *endpoint);
void wg_socket_set_peer_endpoint_authenticated(struct wg_peer *peer,
					       const struct endpoint *endpoint,
					       u64 connection_id);
void wg_socket_set_peer_endpoint_authenticated_from_skb(
	struct wg_peer *peer, const struct sk_buff *skb);
void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb);
void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer);
void log_wireguard_endpoint(struct endpoint *endpoint);

void wg_destruct_tcp_connection_list(struct wg_device *wg);
void print_peer_socket_info(struct wg_peer *peer);
void wg_tcp_state_change(struct sock *sk);
void wg_extract_endpoint_from_sock(struct sock *sk, struct endpoint *endpoint);
bool wg_check_potential_header_validity(struct wg_tcp_encap_header *hdr,
					size_t remaining_len);

int wg_tcp_queuepkt(struct wg_peer *peer, const void *data, size_t len);
void wg_tcp_write_space(struct sock *sk);
void wg_tcp_data_ready(struct sock *sk);
void wg_tcp_inbound_remove_worker(struct work_struct *work);
void wg_tcp_outbound_remove_worker(struct work_struct *work);
int wg_add_tcp_socket_to_list(struct wg_device *wg, struct socket *sock,
			      struct wg_peer *temp_peer);
void wg_remove_from_tcp_connection_list(struct wg_device *wg,
					struct socket *sock);

int wg_tcp_listener_socket_init(struct wg_device *wg, u16 port);
void wg_tcp_listener_socket_release(struct wg_device *wg);
int wg_tcp_connect(struct wg_peer *peer);
int wg_tcp_listener_worker(struct wg_device *wg, struct socket *tcp_socket);
int wg_setup_tcp_listen4(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket);
int wg_setup_tcp_listen6(struct wg_device *wg, struct net *net, u16 port,
			 struct socket **listen_socket);
int wg_tcp_listener4_thread(void *data);
int wg_tcp_listener6_thread(void *data);

void wg_clean_peer_socket(struct wg_peer *peer, bool release, bool destroy,
			  bool inbound);
void wg_reset_tcp_socket_callbacks(struct wg_peer *peer, bool inbound);
void wg_tcp_peer_stop(struct wg_peer *peer);
void wg_tcp_peer_request_reconnect(struct wg_peer *peer);
void wg_tcp_set_device_mark(struct wg_device *wg, u32 mark);
void wg_tcp_write_worker(struct work_struct *work);
void wg_tcp_read_worker(struct work_struct *work);
void wg_tcp_cleanup_worker(struct work_struct *work);
void wg_tcp_retry_worker(struct work_struct *work);

#endif /* _WG_TCP_H */

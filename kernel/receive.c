// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#include "queueing.h"
#include "device.h"
#include "peer.h"
#include "timers.h"
#include "messages.h"
#include "cookie.h"
#include "socket.h"

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/ip.h>
#include "wg_tcp_debug.h"

#define WG_TRANSPORT_UDP	0
#define WG_TRANSPORT_TCP	1
bool endpoint_eq(const struct endpoint *a, const struct endpoint *b);
void log_wireguard_endpoint(struct endpoint *ep);

struct wg_tcp_socket_list_entry {
	struct socket *tcp_socket; /* Socket associated with the connection */
	struct sockaddr_storage src_addr; /* Source address for the connection */
	struct wg_peer *temp_peer; /* temporary peer for dataready */
	struct list_head tcp_connection_ll; /* List pointer for the linked list */
	ktime_t timestamp; /* Timestamp when the connection was added */
};

struct wg_socket_data {
	struct wg_device *device;
	struct wg_peer *peer;
	bool inbound;
};


/* Must be called with bh disabled. */
static void update_rx_stats(struct wg_peer *peer, size_t len)
{
	wg_dbg("Entering update_rx_stats: peer=%px, len=%zu\n", peer, len);
	dev_sw_netstats_rx_add(peer->device->dev, len);
	peer->rx_bytes += len;
	wg_dbg("Exiting update_rx_stats\n");
}

/* FIX: removed unused forward declarations for wg_print_wireguard_skb()
 * and wg_print_wireguard_packet() — functions are static in send.c
 */

#define SKB_TYPE_LE32(skb) (((struct message_header *)(skb)->data)->type)

#ifdef ORIGINAL
static size_t validate_header_len(struct sk_buff *skb)
{
	wg_dbg("Entering validate_header_len: skb=%px\n", skb);
	if (unlikely(skb->len < sizeof(struct message_header)))
		return 0;
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_DATA) &&
	    skb->len >= MESSAGE_MINIMUM_LENGTH)
		return sizeof(struct message_data);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION) &&
	    skb->len == sizeof(struct message_handshake_initiation))
		return sizeof(struct message_handshake_initiation);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE) &&
	    skb->len == sizeof(struct message_handshake_response))
		return sizeof(struct message_handshake_response);
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE) &&
	    skb->len == sizeof(struct message_handshake_cookie))
		return sizeof(struct message_handshake_cookie);
	wg_dbg("Exiting validate_header_len\n");
	return 0;
}
#endif /* ORIGINAL */

static size_t validate_header_len(struct sk_buff *skb)
{
	wg_dbg("Entering validate_header_len: skb=%px\n", skb);
	/* FIX: -Wformat — skb->tail/end are sk_buff_data_t (unsigned int),
	 * not pointers; use %u instead of %px throughout this function
	 */
	wg_dbg("SKB state: len=%d, head=%px, data=%px, tail=%u, end=%u\n",
		skb->len, skb->head, skb->data, skb->tail, skb->end);

	wg_dbg("sizeof(struct message_header)=%zu\n", sizeof(struct message_header));
	if (unlikely(skb->len < sizeof(struct message_header))) {
		wg_dbg("Exiting validate_header_len: skb len (%d) is less "
		       "than sizeof(struct message_header) (%zu)\n",
		       skb->len, (size_t)sizeof(struct message_header));
		return 0;
	}

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_DATA)) {
		wg_dbg("SKB_TYPE_LE32(skb) matches MESSAGE_DATA, checking length.\n");
		/* FIX: -Wformat — MESSAGE_MINIMUM_LENGTH is enum (int), not size_t */
		wg_dbg("MESSAGE_MINIMUM_LENGTH=%d, sizeof(struct message_data)=%zu\n",
		       MESSAGE_MINIMUM_LENGTH, sizeof(struct message_data));
		if (skb->len >= MESSAGE_MINIMUM_LENGTH) {
			wg_dbg("Exiting validate_header_len: skb len (%d) is greater than or "
			       "equal to MESSAGE_MINIMUM_LENGTH (%d), returning sizeof(struct "
			       "message_data) (%zu)\n",
			       skb->len, MESSAGE_MINIMUM_LENGTH, sizeof(struct message_data));
			return sizeof(struct message_data);
		}
	}

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION)) {
		wg_dbg("SKB_TYPE_LE32(skb) matches MESSAGE_HANDSHAKE_INITIATION, checking length.\n");
		wg_dbg("sizeof(struct message_handshake_initiation)=%zu\n",
		       sizeof(struct message_handshake_initiation));
		if (skb->len == sizeof(struct message_handshake_initiation)) {
			wg_dbg("Exiting validate_header_len: skb len (%d) matches "
			       "sizeof(struct message_handshake_initiation) (%zu)\n",
			       skb->len, sizeof(struct message_handshake_initiation));
			return sizeof(struct message_handshake_initiation);
		}
	}

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE)) {
		wg_dbg("SKB_TYPE_LE32(skb) matches MESSAGE_HANDSHAKE_RESPONSE, checking length.\n");
		wg_dbg("sizeof(struct message_handshake_response)=%zu\n",
		sizeof(struct message_handshake_response));
		if (skb->len == sizeof(struct message_handshake_response)) {
			wg_dbg("Exiting validate_header_len: skb len (%d) matches "
			       "sizeof(struct message_handshake_response) (%zu)\n",
			       skb->len, sizeof(struct message_handshake_response));
			return sizeof(struct message_handshake_response);
		}
	}

	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE)) {
		wg_dbg("SKB_TYPE_LE32(skb) matches MESSAGE_HANDSHAKE_COOKIE, checking length.\n");
		wg_dbg("sizeof(struct message_handshake_cookie)=%zu\n",
		sizeof(struct message_handshake_cookie));
		if (skb->len == sizeof(struct message_handshake_cookie)) {
			wg_dbg("Exiting validate_header_len: skb len (%d) matches "
			       "sizeof(struct message_handshake_cookie) (%zu)\n",
			       skb->len, sizeof(struct message_handshake_cookie));
			return sizeof(struct message_handshake_cookie);
		}
	}

	wg_dbg("Exiting validate_header_len: no valid message type found or length mismatch.\n");
	return 0;
}

static int prepare_skb_header(struct sk_buff *skb, struct wg_device *wg)
{
	wg_dbg("Entering prepare_skb_header: skb=%px, wg=%px\n", skb, wg);
	size_t data_offset, data_len, header_len;
	struct udphdr _udp, *udp;
	wg_dbg("wg: prepare_skb_header: ENTER\n"
               "    skb->len=%u, skb->data_len=%u\n"
               "    headroom=%u, tailroom=%u\n"
               "    skb->head=%px, skb->data=%px, skb->tail=%u, skb->end=%u\n",
	       skb->len, skb->data_len,
	       skb_headroom(skb), skb_tailroom(skb),
	       skb->head, skb->data, skb->tail, skb->end);

	/* FIX: -Wformat — skb->tail/end are sk_buff_data_t (unsigned int) */
	/* Initial SKB state diagnostics */
	wg_dbg("Initial skb state: head=%px, data=%px, tail=%u, end=%u, len=%d, headroom=%d\n",
		skb->head, skb->data, skb->tail, skb->end, skb->len, skb_headroom(skb));

	/* Check packet protocol and header validity */
	if (unlikely(!wg_check_packet_protocol(skb) ||
		     skb_transport_header(skb) < skb->head ||
		     (skb_transport_header(skb) + sizeof(struct udphdr)) >
			    skb_tail_pointer(skb))) {
		wg_dbg("Exiting prepare_skb_header with error -EINVAL: "
		       "Invalid transport header or protocol check failed.\n");
		return -EINVAL; /* Bogus IP header */
	}
	wg_dbg("wg: prepare_skb_header: protocol checks "
	       "passed.\n");

	/* Safely access UDP header using skb_header_pointer */
	udp = skb_header_pointer(skb, skb_transport_offset(skb), sizeof(_udp), &_udp);
	if (!udp) {
		wg_dbg("Exiting prepare_skb_header with error "
		       "-EINVAL: Failed to access UDP header using "
		       "skb_header_pointer.\n");
		return -EINVAL;
	}

	wg_dbg("UDP header source=%u, dest=%u\n",
	       ntohs(udp->source), ntohs(udp->dest));

	/* Calculate data offset and validate */
	data_offset = skb_transport_offset(skb) + sizeof(struct udphdr);
	wg_dbg("Data offset calculated: data_offset=%zu\n",
	       data_offset);

	if (unlikely(data_offset > U16_MAX ||
		     data_offset + sizeof(struct udphdr) > skb->len)) {
		wg_dbg("Exiting prepare_skb_header with error"
		       " -EINVAL: Invalid data offset or UDP header size "
		       "too large.\n");
		return -EINVAL;
	}

	/* Get the UDP length field */
	data_len = ntohs(udp->len);
	wg_dbg("UDP length field: data_len=%zu\n", data_len);

	/* Validate data length */
	if (unlikely(data_len < sizeof(struct udphdr) ||
		     data_len > skb->len - skb_transport_offset(skb))) {
		wg_dbg("Exiting prepare_skb_header with error "
		       "-EINVAL: UDP length field too small or larger than "
		       "available data.\n");

		return -EINVAL;
	}

	/* Adjust data length to exclude UDP header */
	data_len -= sizeof(struct udphdr);
	data_offset = skb_transport_offset(skb) + sizeof(struct udphdr);
	wg_dbg("Adjusted data_len=%zu, adjusted data_offset=%zu\n",
	       data_len, data_offset);

	/* Check pull and trim capabilities */
	if (unlikely(!pskb_may_pull(skb,
				data_offset + sizeof(struct message_header)) ||
		     pskb_trim(skb, data_len + data_offset) < 0)) {
		wg_dbg("Exiting prepare_skb_header with error "
		       "-EINVAL: pskb_may_pull or pskb_trim failed. "
		       "data_offset=%zu, data_len=%zu, len=%d\n",
		       data_offset, data_len, skb->len);
		return -EINVAL;
	}

	/* Diagnostics before pulling SKB data */
	wg_dbg("Before skb_pull: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);
	skb_pull(skb, data_offset);
	/* Diagnostics after pulling SKB data */
	wg_dbg("After skb_pull: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);

	/* Validate the SKB length against calculated data length */
	if (unlikely(skb->len != data_len)) {
		wg_dbg("Exiting prepare_skb_header with error -EINVAL: "
		       "Final length does not match calculated length. len=%d, expected data_len=%zu\n",
		       skb->len, data_len);
		return -EINVAL;
	}

	/* Validate header length */
	header_len = validate_header_len(skb);
	wg_dbg("Header length validated: header_len=%zu\n", header_len);

	if (unlikely(!header_len)) {
		wg_dbg("Exiting prepare_skb_header with error -EINVAL\n");
		return -EINVAL;
	}

	/* Diagnostics before pushing SKB data back */
	wg_dbg("Before __skb_push: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);
	__skb_push(skb, data_offset);
	/* Diagnostics after pushing SKB data back */
	wg_dbg("After __skb_push: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);

	/* Check pull capabilities after push */
	if (unlikely(!pskb_may_pull(skb, data_offset + header_len))) {
		wg_dbg("Exiting prepare_skb_header with error -EINVAL: "
		       "pskb_may_pull failed after __skb_push. data_offset=%zu, header_len=%zu\n",
		data_offset, header_len);
		return -EINVAL;
	}

	/* Diagnostics before pulling SKB data again */
	wg_dbg("Before __skb_pull: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);
	__skb_pull(skb, data_offset);
	/* Diagnostics after pulling SKB data again */
	wg_dbg("After __skb_pull: len=%d, data=%px, tail=%u\n", skb->len,
	       skb->data, skb->tail);

	/* FIX: -Wunused-label — removed unused 'out:' label (no goto out) */
	wg_dbg("Exiting prepare_skb_header successfully: "
	       "final len=%d, data=%px, head=%px, tail=%u, end=%u, headroom=%d, "
	       "tailroom=%d\n", skb->len, skb->data, skb->head, skb->tail,
	       skb->end, skb_headroom(skb), skb_tailroom(skb));
	return 0;
}

/* FIX: -Wmissing-prototypes — made static (file-local only) */
/* Function to extract source and destination sockaddr_storage from an skb */
static int extract_sockaddr_from_skb(struct sk_buff *skb, struct sockaddr_storage *source,
			      struct sockaddr_storage *dest)
{
	struct iphdr *ip_header;
	struct ipv6hdr *ipv6_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;

	if (!skb) {
		return -1; /* Invalid skb */
	}

	/* Handle IPv4 packets */
	if (skb->protocol == htons(ETH_P_IP)) {
		ip_header = ip_hdr(skb);
			if (!ip_header) {
			return -1; /* Failed to get IP header */
		}

		struct sockaddr_in *src_in = (struct sockaddr_in *)source;
		struct sockaddr_in *dest_in = (struct sockaddr_in *)dest;

		memset(src_in, 0, sizeof(struct sockaddr_in));
		memset(dest_in, 0, sizeof(struct sockaddr_in));

		src_in->sin_family = AF_INET;
		dest_in->sin_family = AF_INET;

		src_in->sin_addr.s_addr = ip_header->saddr;
		dest_in->sin_addr.s_addr = ip_header->daddr;

		/* Determine transport protocol */
		if (ip_header->protocol == IPPROTO_TCP) {
			tcp_header = tcp_hdr(skb);
			if (!tcp_header) {
				return -1; /* Failed to get TCP header */
			}
			src_in->sin_port = tcp_header->source;
			dest_in->sin_port = tcp_header->dest;
		} else if (ip_header->protocol == IPPROTO_UDP) {
			udp_header = udp_hdr(skb);
			if (!udp_header) {
				return -1; /* Failed to get UDP header */
			}
			src_in->sin_port = udp_header->source;
			dest_in->sin_port = udp_header->dest;
		} else {
			return -1; /* Unsupported protocol */
		}
	}

#if IS_ENABLED(CONFIG_IPV6)
	/* Handle IPv6 packets */
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		ipv6_header = ipv6_hdr(skb);
		if (!ipv6_header) {
			return -1; /* Failed to get IPv6 header */
		}

		struct sockaddr_in6 *src_in6 = (struct sockaddr_in6 *)source;
		struct sockaddr_in6 *dest_in6 = (struct sockaddr_in6 *)dest;

		memset(src_in6, 0, sizeof(struct sockaddr_in6));
		memset(dest_in6, 0, sizeof(struct sockaddr_in6));

		src_in6->sin6_family = AF_INET6;
		dest_in6->sin6_family = AF_INET6;

		src_in6->sin6_addr = ipv6_header->saddr;
		dest_in6->sin6_addr = ipv6_header->daddr;

		/* Determine transport protocol */
		if (ipv6_header->nexthdr == IPPROTO_TCP) {
			tcp_header = tcp_hdr(skb);
			if (!tcp_header) {
				return -1; /* Failed to get TCP header */
			}
			src_in6->sin6_port = tcp_header->source;
			dest_in6->sin6_port = tcp_header->dest;
		} else if (ipv6_header->nexthdr == IPPROTO_UDP) {
			udp_header = udp_hdr(skb);
			if (!udp_header) {
				return -1; /* Failed to get UDP header */
			}
			src_in6->sin6_port = udp_header->source;
			dest_in6->sin6_port = udp_header->dest;
		} else {
			return -1; /* Unsupported protocol */
		}
	}
#endif

	else {
		return -1; /* Unsupported packet type */
	}

	return 0; /* Success */
}

void print_peer_socket_info(struct wg_peer *peer);

static void wg_receive_handshake_packet(struct wg_device *wg,
					struct sk_buff *skb)
{
	wg_dbg("Entering wg_receive_handshake_packet: wg=%px, skb=%px\n", wg, skb);
	enum cookie_mac_state mac_state;
	struct wg_peer *peer = NULL;
	/* This is global, so that our load calculation applies to the whole
	 * system. We don't care about races with it at all.
	 */
	static u64 last_under_load;
	bool packet_needs_cookie;
	bool under_load;
	enum cookie_validation_action cookie_action;

	wg_dbg("Validating handshake packet with len=%u\n", skb->len);
	wg_dbg("Received Handshake Packet: %*ph\n", (int)skb->len, skb->data);

	if(wg->transport == WG_TRANSPORT_TCP) {
		/* For TCP, skip cookie check */
		packet_needs_cookie = false;
		goto nocookie;
	}

	/* Handle handshake cookie response */
	if (SKB_TYPE_LE32(skb) == cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE)) {
		net_dbg_skb_ratelimited("%s: Receiving cookie response from %pISpfsc\n", wg->dev->name, skb);
		wg_cookie_message_consume((struct message_handshake_cookie *)skb->data, wg);
		wg_dbg("Exiting wg_receive_handshake_packet\n");
		return;
	}

	/* Load calculation to decide if system is under load */
	under_load = atomic_read(&wg->handshake_queue_len) >= MAX_QUEUED_INCOMING_HANDSHAKES / 8;
	if (under_load) {
		last_under_load = ktime_get_coarse_boottime_ns();
		wg_dbg("System under load: last_under_load set to %llu\n", last_under_load);
	} else if (last_under_load) {
		under_load = !wg_birthdate_has_expired(last_under_load, 1);
		if (!under_load) {
			last_under_load = 0;
			wg_dbg("System load normalized: last_under_load reset\n");
		}
	}

	/* Validate packet's MAC and set packet_needs_cookie flag */
	mac_state = wg_cookie_validate_packet(&wg->cookie_checker, skb, under_load);
	wg_dbg("MAC validation result: %d\n", mac_state);
	cookie_action = wg_cookie_validation_action(under_load, mac_state);
	if (cookie_action == WG_COOKIE_ACCEPT) {
		packet_needs_cookie = false;
	} else if (cookie_action == WG_COOKIE_CHALLENGE) {
		packet_needs_cookie = true;
	} else {
		net_dbg_skb_ratelimited("%s: Invalid MAC of handshake, dropping packet from %pISpfsc\n", wg->dev->name, skb);
		wg_dbg("Exiting wg_receive_handshake_packet\n");
		return;
	}

nocookie:
	/* Process handshake packets */
	switch (SKB_TYPE_LE32(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION): {
		struct message_handshake_initiation *message = (struct message_handshake_initiation *)skb->data;

		wg_dbg("Processing handshake initiation packet\n");
		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb, message->sender_index);
			wg_dbg("Exiting wg_receive_handshake_packet: Cookie sent for initiation\n");
			return;
		}

		/* Handle handshake initiation */
		peer = wg_noise_handshake_consume_initiation(message, wg);
		if (unlikely(!peer)) {
			net_dbg_skb_ratelimited("%s: Invalid handshake initiation from %pISpfsc\n", wg->dev->name, skb);
			wg_dbg("Exiting wg_receive_handshake_packet\n");
			return;
		}
		print_peer_socket_info(peer);
		if (wg->transport == WG_TRANSPORT_UDP)
			wg_socket_set_peer_endpoint_from_skb(peer, skb);
		else if (PACKET_CB(skb)->outer_ipproto == IPPROTO_TCP)
			wg_socket_set_peer_endpoint_authenticated_from_skb(peer, skb);
		net_dbg_ratelimited("%s: Receiving handshake initiation from peer %llu (%pISpfsc)\n", wg->dev->name, peer->internal_id, &peer->endpoint.addr);
		wg_packet_send_handshake_response(peer);
		break;
	}
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE): {
		struct message_handshake_response *message = (struct message_handshake_response *)skb->data;

		wg_dbg("Processing handshake response packet\n");
		if (packet_needs_cookie) {
			wg_packet_send_handshake_cookie(wg, skb, message->sender_index);
			wg_dbg("Exiting wg_receive_handshake_packet: Cookie sent for response\n");
			return;
		}

		/* Handle handshake response */
		peer = wg_noise_handshake_consume_response(message, wg);
		if (unlikely(!peer)) {
			wg_dbg("Peer object is NULL. Dropping packet.\n");
			net_dbg_skb_ratelimited("%s: Invalid handshake response from %pISpfsc\n", wg->dev->name, skb);
			wg_dbg("Exiting wg_receive_handshake_packet\n");
			return;
		}

		print_peer_socket_info(peer);
		if (peer->device->transport == WG_TRANSPORT_UDP) {
			wg_socket_set_peer_endpoint_from_skb(peer, skb);
		} else if (PACKET_CB(skb)->outer_ipproto == IPPROTO_TCP) {
			wg_socket_set_peer_endpoint_authenticated_from_skb(peer, skb);
		}
		net_dbg_ratelimited("%s: Receiving handshake response from peer %llu (%pISpfsc)\n", wg->dev->name, peer->internal_id, &peer->endpoint.addr);

		if (wg_noise_handshake_begin_session(&peer->handshake, &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_handshake_complete(peer);
			wg_packet_send_keepalive(peer);
		}
		break;
	}

	default:
		wg_dbg("Unknown packet type received in handshake processing: %u\n",
		       SKB_TYPE_LE32(skb));
		break;
	}

	/* Final check to ensure peer is valid */
	if (unlikely(!peer)) {
		WARN(1, "Unexpected state: No valid peer found after handshake processing\n");
		wg_dbg("Exiting wg_receive_handshake_packet\n");
		return;
	}

	/* Update statistics and state */
	local_bh_disable();
	update_rx_stats(peer, skb->len);
	local_bh_enable();

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);
	wg_peer_put(peer);
	wg_dbg("Exiting wg_receive_handshake_packet\n");
}


void wg_packet_handshake_receive_worker(struct work_struct *work)
{
	wg_dbg("Entering wg_packet_handshake_receive_worker: work=%px\n", work);
	struct crypt_queue *queue = container_of(work, struct multicore_worker, work)->ptr;
	struct wg_device *wg = container_of(queue, struct wg_device, handshake_queue);
	struct sk_buff *skb;

	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		wg_receive_handshake_packet(wg, skb);
		dev_kfree_skb(skb);
		atomic_dec(&wg->handshake_queue_len);
		cond_resched();
	}
	wg_dbg("Exiting wg_packet_handshake_receive_worker\n");
}

static void keep_key_fresh(struct wg_peer *peer)
{
	wg_dbg("Entering keep_key_fresh: peer=%px\n", peer);
	struct noise_keypair *keypair;
	bool send;

	if (peer->sent_lastminute_handshake)
		return;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       keypair->i_am_the_initiator &&
	       wg_birthdate_has_expired(keypair->sending.birthdate,
			REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT);
	rcu_read_unlock_bh();

	if (unlikely(send)) {
		peer->sent_lastminute_handshake = true;
		wg_packet_send_queued_handshake_initiation(peer, false);
	}
	wg_dbg("Exiting keep_key_fresh\n");
}

#ifdef ORIGINAL
static bool decrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
	wg_dbg("Entering decrypt_packet: skb=%px, keypair=%px\n", skb, keypair);
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	if (unlikely(!keypair)) {
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	if (unlikely(!READ_ONCE(keypair->receiving.is_valid) ||
		  wg_birthdate_has_expired(keypair->receiving.birthdate, REJECT_AFTER_TIME) ||
		  READ_ONCE(keypair->receiving_counter.counter) >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->receiving.is_valid, false);
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	PACKET_CB(skb)->nonce =
		le64_to_cpu(((struct message_data *)skb->data)->counter);

	/* We ensure that the network header is part of the packet before we
	 * call skb_cow_data, so that there's no chance that data is removed
	 * from the skb, so that later we can extract the original endpoint.
	 */
	offset = skb->data - skb_network_header(skb);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg))) {
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0) {
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	if (!chacha20poly1305_decrypt_sg_inplace(sg, skb->len, NULL, 0,
					         PACKET_CB(skb)->nonce,
						 keypair->receiving.key)) {
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	/* Another ugly situation of pushing and pulling the header so as to
	 * keep endpoint information intact.
	 */
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0))) {
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}
	skb_pull(skb, offset);

	wg_dbg("Exiting decrypt_packet with true\n");
	return true;
}
#endif /* ORIGINAL */

void decode_and_print_packet(const struct sk_buff *skb, const char *prefix);

static bool decrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
	struct scatterlist sg[MAX_SKB_FRAGS + 8];
	struct sk_buff *trailer;
	unsigned int offset;
	int num_frags;

	wg_dbg("Entering decrypt_packet: skb=%px, keypair=%px\n", skb, keypair);
	wg_dbg("skb->len = %u, skb->data_len = %u, skb->network_header = %px\n",
	       skb->len, skb->data_len, skb_network_header(skb));

	if (unlikely(!keypair)) {
		wg_dbg("Keypair is NULL\n");
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	if (unlikely(!READ_ONCE(keypair->receiving.is_valid) ||
			wg_birthdate_has_expired(keypair->receiving.birthdate, REJECT_AFTER_TIME) ||
			READ_ONCE(keypair->receiving_counter.counter) >= REJECT_AFTER_MESSAGES)) {
		WRITE_ONCE(keypair->receiving.is_valid, false);
		wg_dbg("Keypair is invalid or expired: is_valid=%d, counter=%llu\n",
		keypair->receiving.is_valid, keypair->receiving_counter.counter);
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	PACKET_CB(skb)->nonce = le64_to_cpu(((struct message_data *)skb->data)->counter);
	wg_dbg("Extracted nonce from skb: nonce=%llu\n", PACKET_CB(skb)->nonce);
	wg_dbg("skb->data (before decryption): %*ph\n", skb->len, skb->data);

	/* Ensure network header is part of the packet */
	offset = skb->data - skb_network_header(skb);
	wg_dbg("Pushing skb to preserve network header, offset=%u\n", offset);
	skb_push(skb, offset);
	num_frags = skb_cow_data(skb, 0, &trailer);
	wg_dbg("num_frags after skb_cow_data: %d\n", num_frags);
	offset += sizeof(struct message_data);
	skb_pull(skb, offset);
	wg_dbg("Pulled skb to offset: %u, skb->len=%u, skb->data=%px\n", offset, skb->len, skb->data);
	if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg))) {
		wg_dbg("skb->data (after decryption failed): %*ph\n", skb->len, skb->data);
		wg_dbg("Failed skb_cow_data: num_frags=%d, skb->len=%u\n", num_frags, skb->len);
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	sg_init_table(sg, num_frags);
	if (skb_to_sgvec(skb, sg, 0, skb->len) <= 0) {
		wg_dbg("Failed skb_to_sgvec, skb->len=%u\n", skb->len);
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}

	wg_dbg("Scattergather segments prepared, starting decryption\n");
#define NOISE_KEY_LEN	32
	wg_dbg("Decryption key: %*ph\n", NOISE_KEY_LEN, keypair->receiving.key);

	if (!chacha20poly1305_decrypt_sg_inplace(sg, skb->len, NULL, 0,
                                             PACKET_CB(skb)->nonce,
                                             keypair->receiving.key)) {
		wg_dbg("skb->data (after decryption failed): %*ph\n",
		       skb->len, skb->data);
		wg_dbg("Decryption failed\n");
		wg_dbg("Exiting decrypt_packet with false\n");
        return false;
	}
#ifdef WG_TCP_VERBOSE
	decode_and_print_packet(skb, "[decrypt]");
#endif

	/* Ensure endpoint information remains intact */
	wg_dbg("Pushing skb to preserve endpoint information\n");
	skb_push(skb, offset);
	if (pskb_trim(skb, skb->len - noise_encrypted_len(0))) {
		wg_dbg("skb->data (after decryption failed): %*ph\n", skb->len, skb->data);
		wg_dbg("Failed pskb_trim, skb->len=%u\n", skb->len);
		wg_dbg("Exiting decrypt_packet with false\n");
		return false;
	}
	skb_pull(skb, offset);
	wg_dbg("skb->data (after decryption succeeded): %*ph\n",
	       skb->len, skb->data);
	wg_dbg("Pulled skb to offset: %u, skb->len=%u, skb->data=%px\n",
	       offset, skb->len, skb->data);


	wg_dbg("Exiting decrypt_packet with true, skb->len=%u\n", skb->len);
	return true;
}

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
static bool counter_validate(struct noise_replay_counter *counter, u64 their_counter)
{
	wg_dbg("Entering counter_validate: counter=%px, their_counter=%llu\n", counter, their_counter);
	unsigned long index, index_current, top, i;
	bool ret = false;

	spin_lock_bh(&counter->lock);

	if (unlikely(counter->counter >= REJECT_AFTER_MESSAGES + 1 ||
		     their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) <
		     counter->counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->counter)) {
		index_current = counter->counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current,
			    COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->backtrack[(i + index_current) &
				((COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1)] = 0;
		WRITE_ONCE(counter->counter, their_counter);
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1),
				&counter->backtrack[index]);

out:
	spin_unlock_bh(&counter->lock);
	wg_dbg("Exiting counter_validate with %d\n", ret);
	return ret;
}

#include "selftest/counter.c"
#include "selftest/cookie.c"

static void wg_packet_consume_data_done(struct wg_peer *peer,
					struct sk_buff *skb,
					struct endpoint *endpoint,
					bool authenticated_over_tcp)
{
	wg_dbg("Entering wg_packet_consume_data_done: peer=%px, skb=%px, endpoint=%px\n",
	       peer, skb, endpoint);
	struct net_device *dev = peer->device->dev;
	unsigned int len, len_before_trim;
	struct wg_peer *routed_peer;

	if (unlikely(!endpoint)) {
		wg_dbg("Endpoint object is NULL. Cannot set peer endpoint.\n");
    		return;
	}


	if (peer->device->transport == WG_TRANSPORT_TCP &&
	    authenticated_over_tcp)
		wg_socket_set_peer_endpoint_authenticated(
			peer, endpoint, PACKET_CB(skb)->tcp_connection_id);
	else
		wg_socket_set_peer_endpoint(peer, endpoint);

	if (unlikely(wg_noise_received_with_keypair(&peer->keypairs,
						    PACKET_CB(skb)->keypair))) {
		wg_timers_handshake_complete(peer);
		wg_packet_send_staged_packets(peer);
	}

	keep_key_fresh(peer);

	wg_timers_any_authenticated_packet_received(peer);
	wg_timers_any_authenticated_packet_traversal(peer);

	/* A packet with length 0 is a keepalive packet */
	if (unlikely(!skb->len)) {
		update_rx_stats(peer, message_data_len(0));
		net_dbg_ratelimited("%s: Receiving keepalive packet from peer %llu (%pISpfsc)\n",
				    dev->name, peer->internal_id,
				    &peer->endpoint.addr);
		goto packet_processed;
	}

	wg_timers_data_received(peer);

	if (unlikely(skb_network_header(skb) < skb->head))
		goto dishonest_packet_size;
	if (unlikely(!(pskb_network_may_pull(skb, sizeof(struct iphdr)) &&
		       (ip_hdr(skb)->version == 4 ||
			(ip_hdr(skb)->version == 6 &&
			 pskb_network_may_pull(skb, sizeof(struct ipv6hdr)))))))
		goto dishonest_packet_type;

	skb->dev = dev;
	/* We've already verified the Poly1305 auth tag, which means this packet
	 * was not modified in transit. We can therefore tell the networking
	 * stack that all checksums of every layer of encapsulation have already
	 * been checked "by the hardware" and therefore is unnecessary to check
	 * again in software.
	 */
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->csum_level = ~0; /* All levels */
	skb->protocol = ip_tunnel_parse_protocol(skb);
	if (skb->protocol == htons(ETH_P_IP)) {
		len = ntohs(ip_hdr(skb)->tot_len);
		if (unlikely(len < sizeof(struct iphdr)))
			goto dishonest_packet_size;
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ip_hdr(skb)->tos);
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		len = ntohs(ipv6_hdr(skb)->payload_len) +
		      sizeof(struct ipv6hdr);
		INET_ECN_decapsulate(skb, PACKET_CB(skb)->ds, ipv6_get_dsfield(ipv6_hdr(skb)));
	} else {
		goto dishonest_packet_type;
	}

	if (unlikely(len > skb->len))
		goto dishonest_packet_size;
	len_before_trim = skb->len;


	if (unlikely(len == 0 || len_before_trim == 0)) {
		wg_dbg("Invalid packet length detected: len=%u, len_before_trim=%u\n",
		       len, len_before_trim);
    		return;
	}


	if (unlikely(pskb_trim(skb, len)))
		goto packet_processed;

	routed_peer = wg_allowedips_lookup_src(&peer->device->peer_allowedips,
					       skb);
	wg_peer_put(routed_peer); /* We don't need the extra reference. */

	if (unlikely(routed_peer != peer))
		goto dishonest_packet_peer;

	napi_gro_receive(&peer->napi, skb);
	update_rx_stats(peer, message_data_len(len_before_trim));
	wg_dbg("Exiting wg_packet_consume_data_done\n");
	return;

dishonest_packet_peer:
	net_dbg_skb_ratelimited("%s: Packet has unallowed src IP (%pISc) from peer %llu (%pISpfsc)\n",
				dev->name, skb, peer->internal_id,
				&peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_frame_errors);
	goto packet_processed;
dishonest_packet_type:
	net_dbg_ratelimited("%s: Packet is neither ipv4 nor ipv6 from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_frame_errors);
	goto packet_processed;
dishonest_packet_size:
	net_dbg_ratelimited("%s: Packet has incorrect size from peer %llu (%pISpfsc)\n",
			    dev->name, peer->internal_id, &peer->endpoint.addr);
	DEV_STATS_INC(dev, rx_errors);
	DEV_STATS_INC(dev, rx_length_errors);
	goto packet_processed;
packet_processed:
	dev_kfree_skb(skb);
	wg_dbg("Exiting wg_packet_consume_data_done\n");
}

int wg_packet_rx_poll(struct napi_struct *napi, int budget)
{
	wg_dbg("Entering wg_packet_rx_poll: napi=%px, budget=%d\n", napi, budget);
	struct wg_peer *peer = container_of(napi, struct wg_peer, napi);
	struct noise_keypair *keypair;
	struct endpoint endpoint;
	enum packet_state state;
	struct sk_buff *skb;
	int work_done = 0;
	bool free;
	bool authenticated_over_tcp;

	if (unlikely(budget <= 0)) {
		wg_dbg("Exiting wg_packet_rx_poll with 0\n");
		return 0;
	}

	while ((skb = wg_prev_queue_peek(&peer->rx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(skb)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		wg_prev_queue_drop_peeked(&peer->rx_queue);
		keypair = PACKET_CB(skb)->keypair;
		free = true;

		if (unlikely(state != PACKET_STATE_CRYPTED))
			goto next;

		if (unlikely(!counter_validate(&keypair->receiving_counter,
					       PACKET_CB(skb)->nonce))) {
			net_dbg_ratelimited("%s: Packet has invalid nonce %llu (max %llu)\n",
					    peer->device->dev->name,
					    PACKET_CB(skb)->nonce,
					    READ_ONCE(keypair->receiving_counter.counter));
			goto next;
		}

		if (unlikely(wg_socket_endpoint_from_skb(&endpoint, skb)))
			goto next;

		authenticated_over_tcp =
			PACKET_CB(skb)->outer_ipproto == IPPROTO_TCP;
		wg_reset_packet(skb, false);
		wg_packet_consume_data_done(peer, skb, &endpoint,
					    authenticated_over_tcp);
		free = false;

next:
		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		if (unlikely(free))
			dev_kfree_skb(skb);

		if (++work_done >= budget)
			break;
	}

	if (work_done < budget)
		napi_complete_done(napi, work_done);

	wg_dbg("Exiting wg_packet_rx_poll with %d\n", work_done);
	return work_done;
}

void wg_packet_decrypt_worker(struct work_struct *work)
{
	wg_dbg("Entering wg_packet_decrypt_worker: work=%px\n", work);
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	struct sk_buff *skb;

	while ((skb = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state =
			likely(decrypt_packet(skb, PACKET_CB(skb)->keypair)) ?
				PACKET_STATE_CRYPTED : PACKET_STATE_DEAD;
		wg_queue_enqueue_per_peer_rx(skb, state);
		if (need_resched())
			cond_resched();
	}
	wg_dbg("Exiting wg_packet_decrypt_worker\n");
}

static void wg_packet_consume_data(struct wg_device *wg, struct sk_buff *skb)
{
	wg_dbg("Entering wg_packet_consume_data: wg=%px, skb=%px\n", wg, skb);
	__le32 idx = ((struct message_data *)skb->data)->key_idx;
	struct wg_peer *peer = NULL;
	int ret;

	wg_dbg("Consuming data packet with key_idx=%u\n", idx);
	wg_dbg("Data Packet Contents: %*ph\n", (int)skb->len, skb->data);

	rcu_read_lock_bh();
	PACKET_CB(skb)->keypair =
		(struct noise_keypair *)wg_index_hashtable_lookup(
			wg->index_hashtable, INDEX_HASHTABLE_KEYPAIR, idx,
			&peer);
	if (unlikely(!wg_noise_keypair_get(PACKET_CB(skb)->keypair)))
		goto err_keypair;

	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	ret = wg_queue_enqueue_per_device_and_peer(&wg->decrypt_queue, &peer->rx_queue, skb,
						   wg->packet_crypt_wq);
	if (unlikely(ret == -EPIPE))
		wg_queue_enqueue_per_peer_rx(skb, PACKET_STATE_DEAD);
	if (likely(!ret || ret == -EPIPE)) {
		rcu_read_unlock_bh();
		wg_dbg("Exiting wg_packet_consume_data\n");
		return;
	}
err:
	wg_noise_keypair_put(PACKET_CB(skb)->keypair, false);
err_keypair:
	rcu_read_unlock_bh();
	wg_peer_put(peer);
	dev_kfree_skb(skb);
	wg_dbg("Exiting wg_packet_consume_data\n");
}

#ifdef ORIGINAL
void wg_packet_receive(struct wg_device *wg, struct sk_buff *skb)
{
	wg_dbg("Entering wg_packet_receive: wg=%px, skb=%px\n", wg, skb);
	if (unlikely(prepare_skb_header(skb, wg) < 0))
		goto err;
	switch (SKB_TYPE_LE32(skb)) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):
	case cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE): {
		int cpu, ret = -EBUSY;

		if (unlikely(!rng_is_initialized()))
			goto drop;
		if (atomic_read(&wg->handshake_queue_len) > MAX_QUEUED_INCOMING_HANDSHAKES / 2) {
			if (spin_trylock_bh(&wg->handshake_queue.ring.producer_lock)) {
				ret = __ptr_ring_produce(&wg->handshake_queue.ring, skb);
				spin_unlock_bh(&wg->handshake_queue.ring.producer_lock);
			}
		} else
			ret = ptr_ring_produce_bh(&wg->handshake_queue.ring, skb);
		if (ret) {
	drop:
			net_dbg_skb_ratelimited("%s: Dropping handshake packet from %pISpfsc\n",
						wg->dev->name, skb);
			goto err;
		}
		atomic_inc(&wg->handshake_queue_len);
		cpu = wg_cpumask_next_online(&wg->handshake_queue.last_cpu);
		/* Queues up a call to packet_process_queued_handshake_packets(skb): */
		queue_work_on(cpu, wg->handshake_receive_wq,
			      &per_cpu_ptr(wg->handshake_queue.worker, cpu)->work);
		break;
	}
	case cpu_to_le32(MESSAGE_DATA):
		PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		wg_packet_consume_data(wg, skb);
		break;
	default:
		WARN(1, "Non-exhaustive parsing of packet header lead to unknown packet type!\n");
		goto err;
	}
	wg_dbg("Exiting wg_packet_receive\n");
	return;

err:
	dev_kfree_skb(skb);
	wg_dbg("Exiting wg_packet_receive\n");
}
#endif /* ORIGINAL */

void wg_packet_receive(struct wg_device *wg, struct sk_buff *skb)
{
	wg_dbg("Entering wg_packet_receive: wg=%px, skb=%px\n", wg, skb);

	if (unlikely(prepare_skb_header(skb, wg) < 0)) {
		wg_dbg("prepare_skb_header failed\n");
		goto err;
	}

	/* Determine packet type */
	uint32_t skb_type = SKB_TYPE_LE32(skb);
	wg_dbg("Packet type: %u\n", skb_type);

	switch (skb_type) {
	case cpu_to_le32(MESSAGE_HANDSHAKE_INITIATION):
	case cpu_to_le32(MESSAGE_HANDSHAKE_RESPONSE):
	case cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE): {
		int cpu, ret = -EBUSY;
		wg_dbg("Received handshake packet\n");

		if (unlikely(!rng_is_initialized())) {
			wg_dbg("RNG is not initialized, dropping packet\n");
			goto drop;
		}

		int queue_len = atomic_read(&wg->handshake_queue_len);
		wg_dbg("Current handshake queue length: %d\n", queue_len);

		if (queue_len > MAX_QUEUED_INCOMING_HANDSHAKES / 2) {
			wg_dbg("Queue length exceeds threshold, trying spinlock\n");
			if (spin_trylock_bh(&wg->handshake_queue.ring.producer_lock)) {
				ret = __ptr_ring_produce(&wg->handshake_queue.ring, skb);
				wg_dbg("__ptr_ring_produce returned: %d\n", ret);
				spin_unlock_bh(&wg->handshake_queue.ring.producer_lock);
			} else {
				wg_dbg("Failed to acquire spinlock\n");
			}
		} else {
			ret = ptr_ring_produce_bh(&wg->handshake_queue.ring, skb);
			wg_dbg("ptr_ring_produce_bh returned: %d\n", ret);
		}

		if (ret) {
			wg_dbg("Failed to queue handshake packet, dropping\n");
		drop:
			net_dbg_skb_ratelimited("%s: Dropping handshake packet from %pISpfsc\n",
						wg->dev->name, skb);
			goto err;
		}

		atomic_inc(&wg->handshake_queue_len);
		wg_dbg("Handshake queue length incremented\n");

		cpu = wg_cpumask_next_online(&wg->handshake_queue.last_cpu);
		wg_dbg("Selected CPU for work queue: %d\n", cpu);

		/* Queues up a call to packet_process_queued_handshake_packets(skb): */
		queue_work_on(cpu, wg->handshake_receive_wq,
			      &per_cpu_ptr(wg->handshake_queue.worker, cpu)->work);
		break;
	}
	case cpu_to_le32(MESSAGE_DATA):
		wg_dbg("Received data packet\n");
		PACKET_CB(skb)->ds = ip_tunnel_get_dsfield(ip_hdr(skb), skb);
		wg_dbg("DS field set to: %u\n", PACKET_CB(skb)->ds);
		wg_packet_consume_data(wg, skb);
		break;
	default:
		WARN(1, "Non-exhaustive parsing of packet header lead to unknown packet type!\n");
		wg_dbg("Unknown packet type: %u, dropping\n", skb_type);
		goto err;
	}

	wg_dbg("Exiting wg_packet_receive normally\n");
	return;

err:
	dev_kfree_skb(skb);
	wg_dbg("Exiting wg_packet_receive with error\n");
}

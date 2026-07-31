// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "queueing.h"
#include "timers.h"
#include "device.h"
#include "peer.h"
#include "socket.h"
#include "messages.h"
#include "cookie.h"

#include <linux/uio.h>
#include <linux/inetdevice.h>
#include <linux/socket.h>
#include <linux/wireguard.h>
#include <net/ip_tunnels.h>
#include <net/udp.h>
#include <net/sock.h>

#define WG_PACKET_TYPE_HANDSHAKE_INIT 1
#define WG_PACKET_TYPE_HANDSHAKE_RESP 2
#define WG_PACKET_TYPE_COOKIE_REPLY 3
#define WG_PACKET_TYPE_TRANSPORT_DATA 4





#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/printk.h>
#include <linux/in.h>
#include <linux/netdevice.h>
#include <linux/inet.h>

#include <linux/types.h>
#include <linux/byteorder/generic.h>
#include <linux/etherdevice.h>
#include <net/inet_ecn.h>
#include <net/route.h>
#include <linux/netdevice.h>
#include "wg_tcp_debug.h"

/*
 * Enhanced SKB diagnostic and debugging function with focus on fragmentation,
 * GSO/TSO, IP/TCP header analysis, PMTUD, and TCP options.
 */
static void debug_skb(const struct sk_buff *askb)
{
        const struct iphdr  *iph   = NULL;
        const struct tcphdr *tcph  = NULL;
        struct net_device   *dev;
        unsigned int         frag_off_val;
        bool                 more_frags;
        int                  mtu     = 0;
        int                  i;
        unsigned char       *net_hdr;
        unsigned char       *end;

        if (!askb) {
                printk(KERN_ERR "debug_skb: askb is NULL\n");
                return;
        }

        dev     = askb->dev;
        net_hdr = skb_network_header(askb);
        end     = skb_end_pointer(askb);

        wg_dbg("==== Enhanced SKB Dump Start ====\n");
        wg_dbg("skb=%px\n", askb);
        wg_dbg("head=%px, data=%px, tail=%px, end=%px\n",
               askb->head, askb->data,
               skb_tail_pointer(askb), end);
        wg_dbg("len=%u, data_len=%u, truesize=%u\n",
               askb->len, askb->data_len, askb->truesize);
        wg_dbg("headroom=%u, tailroom=%u\n",
               skb_headroom(askb), skb_tailroom(askb));
        wg_dbg("protocol=0x%04x, priority=%u, queue_mapping=%u\n",
               ntohs(askb->protocol), askb->priority, askb->queue_mapping);
        wg_dbg("pkt_type=%u, ip_summed=%u, csum_unnecessary=%u\n",
               askb->pkt_type, askb->ip_summed, skb_csum_unnecessary(askb));

        /* Device MTU */
        if (dev) {
                mtu = dev->mtu;
                wg_dbg("Device: %s, MTU: %d\n", dev->name, mtu);
        } else {
                wg_dbg("debug_skb: device not set\n");
        }

        /* GSO/TSO info */
        wg_dbg("---- Segmentation Info ----\n");
        if (skb_is_gso(askb)) {
                wg_dbg("GSO enabled: size=%u, segs=%u, type=0x%x\n",
                       skb_shinfo(askb)->gso_size,
                       skb_shinfo(askb)->gso_segs,
                       skb_shinfo(askb)->gso_type);
                if (skb_shinfo(askb)->gso_type & SKB_GSO_TCPV4)
                        wg_dbg("        includes TCP/IPv4\n");
                if (skb_shinfo(askb)->gso_type & SKB_GSO_TCPV6)
                        wg_dbg("        includes TCP/IPv6\n");
                if (skb_shinfo(askb)->gso_type & SKB_GSO_UDP)
                        wg_dbg("        includes UDP\n");
        } else {
                wg_dbg("GSO not enabled\n");
        }

        /* Fragmentation Analysis */
        wg_dbg("---- Fragmentation Analysis ----\n");
        if (askb->data_len > 0) {
                wg_dbg("Nonlinear SKB: linear=%u, paged=%u, nr_frags=%u\n",
                       askb->len - askb->data_len,
                       askb->data_len,
                       skb_shinfo(askb)->nr_frags);
                for (i = 0; i < skb_shinfo(askb)->nr_frags; i++) {
                        const skb_frag_t *frag = &skb_shinfo(askb)->frags[i];
                        wg_dbg("  frag %d: size=%u, offset=%u\n",
                               i, skb_frag_size(frag), frag->bv_offset);
                }
        } else {
                wg_dbg("Linear SKB: all data contiguous\n");
        }

        /* IP fragment list */
        if (skb_has_frag_list(askb)) {
                struct sk_buff *iter;
                int frag_count = 0;
                wg_dbg("SKB fragment list present\n");
                skb_walk_frags(askb, iter) {
                        wg_dbg("  fraglist %d: len=%u, data_len=%u\n",
                               frag_count++, iter->len, iter->data_len);
                }
        }

        /* IP header diagnostics */
        if (net_hdr >= askb->head && net_hdr + sizeof(*iph) <= end) {
                iph          = ip_hdr(askb);
                frag_off_val = ntohs(iph->frag_off);
                more_frags   = !!(frag_off_val & IP_MF);

                wg_dbg("---- IP Header ----\n");
                wg_dbg("version=%u, ihl=%u, tos=0x%x, tot_len=%u\n",
                       iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len));
                wg_dbg("id=%u, frag_offset=%u, MF=%u\n",
                       ntohs(iph->id),
                       (frag_off_val & IP_OFFSET) << 3,
                       more_frags);
                if (frag_off_val & IP_DF) {
                        wg_dbg("DF flag set\n");
                        if (mtu && ntohs(iph->tot_len) > mtu)
                                printk(KERN_WARNING "pkt len %u > MTU %d (DF)\n",
                                       ntohs(iph->tot_len), mtu);
                } else {
                        wg_dbg("DF flag not set\n");
                }
                wg_dbg("ttl=%u, proto=%u, src=%pI4, dst=%pI4\n",
                       iph->ttl, iph->protocol,
                       &iph->saddr, &iph->daddr);
                if ((frag_off_val & IP_OFFSET) || more_frags)
                        wg_dbg("IP fragment (offset=%u bytes)\n",
                               (frag_off_val & IP_OFFSET) << 3);
                else
                        wg_dbg("Complete IP packet\n");
        } else {
                wg_dbg("Invalid or missing IP header\n");
        }

        /* TCP header diagnostics */
        if (iph && iph->protocol == IPPROTO_TCP &&
            skb_transport_header(askb) >= askb->head &&
            skb_transport_header(askb) + sizeof(*tcph) <= end) {
                tcph = tcp_hdr(askb);

                wg_dbg("---- TCP Header ----\n");
                wg_dbg("sport=%u, dport=%u, seq=%u, ack=%u\n",
                       ntohs(tcph->source),
                       ntohs(tcph->dest),
                       ntohl(tcph->seq),
                       ntohl(tcph->ack_seq));

                {
                        int total    = ntohs(iph->tot_len);
                        int ip_hlen  = iph->ihl * 4;
                        int tcp_hlen = tcph->doff * 4;
                        int payload  = total - ip_hlen - tcp_hlen;
                        wg_dbg("headers: ip=%u tcp=%u payload=%u\n",
                               ip_hlen, tcp_hlen, payload);
                }

                wg_dbg("flags=[%c%c%c%c%c%c]\n",
                       tcph->fin ? 'F' : '.',
                       tcph->syn ? 'S' : '.',
                       tcph->rst ? 'R' : '.',
                       tcph->psh ? 'P' : '.',
                       tcph->ack ? 'A' : '.',
                       tcph->urg ? 'U' : '.');

                wg_dbg("win=%u, csum=0x%x, urg_ptr=%u\n",
                       ntohs(tcph->window),
                       ntohs(tcph->check),
                       ntohs(tcph->urg_ptr));

                /* TCP options */
                if (tcph->doff > 5) {
                        const unsigned char *opt    = (const unsigned char *)(tcph + 1);
                        int                   optlen = (tcph->doff - 5) * 4;
                        int                   j      = 0;

                        wg_dbg("---- TCP Options (%u bytes) ----\n", optlen);
                        while (j < optlen) {
                                unsigned char kind = opt[j];

                                if (kind == 0) {
                                        wg_dbg("  EOL\n");
                                        break;
                                } else if (kind == 1) {
                                        wg_dbg("  NOP\n");
                                        j++;
                                        continue;
                                }

                                if (j + 1 >= optlen)
                                        break;

                                unsigned char length = opt[j + 1];
                                if (length < 2 || j + length > optlen)
                                        break;

                                switch (kind) {
                                case 2: /* MSS */
                                        if (length == 4) {
                                                unsigned short mss =
                                                        ntohs(*((unsigned short *)(opt + j + 2)));
                                                wg_dbg("  MSS=%u\n", mss);
                                                if (mtu && mss > mtu - 40)
                                                        printk(KERN_WARNING "  MSS %u > PMTU %d\n",
                                                               mss, mtu - 40);
                                        }
                                        break;
                                case 3: /* Window Scale */
                                        if (length == 3)
                                                wg_dbg("  WSCALE=%u\n", opt[j + 2]);
                                        break;
                                case 4: /* SACK Permitted */
                                        wg_dbg("  SACK_PERMITTED\n");
                                        break;
                                case 5: /* SACK Blocks */
                                        wg_dbg("  SACK_BLOCKS\n");
                                        break;
                                case 8: /* Timestamp */
                                        if (length == 10) {
                                                u32 tsval = ntohl(*((u32 *)(opt + j + 2)));
                                                u32 tsecr = ntohl(*((u32 *)(opt + j + 6)));
                                                wg_dbg("  TSVAL=%u, TSecr=%u\n",
                                                       tsval, tsecr);
                                        }
                                        break;
                                default:
                                        wg_dbg("  OPT %u LEN %u\n", kind, length);
                                        break;
                                }

                                j += length;
                        }
                }
        } else if (iph) {
                wg_dbg("Non-TCP protocol: %u\n", iph->protocol);
        } else {
                wg_dbg("Invalid or missing transport header\n");
        }

        wg_dbg("==== Enhanced SKB Dump End ====\n");
}

/* FIX: -Wmissing-prototypes — made static (file-local only) */
static void wg_print_wireguard_packet(const unsigned char *data, size_t payload_len)
{
        size_t i, len;

        if (payload_len < sizeof(u32)) {
                wg_dbg("WireGuard packet too short\n");
                return;
        }

        wg_dbg("WireGuard packet payload (%zu bytes):\n", payload_len);
        for (i = 0; i < payload_len; i += 32) {
                len = min((size_t)32, payload_len - i);
                wg_dbg("%*ph\n", (int)len, data + i);
        }
}

/*
 * Dump the contents of an SKB—including a full raw-hex dump,
 * an IP header dump, then hand off to debug_skb(), and finally
 * the WireGuard payload.
 */
/* FIX: -Wmissing-prototypes — added declaration to socket.h (used cross-file) */
void wg_print_wireguard_skb(const struct sk_buff *skb)
{
        if (!skb) {
                printk(KERN_ERR "wg_print_wireguard_skb: skb is NULL\n");
                return;
        }

        /* 1) Full raw buffer dump (head→end) */
        {
                const unsigned char *buf    = skb->head;
                int                   buf_len = skb_end_pointer(skb) - skb->head;
                int                   off;

                wg_dbg("==== Full raw SKB buffer dump head->end (%d bytes) ====\n",
                       buf_len);
                for (off = 0; off < buf_len; off += 16) {
                        int chunk = min(16, buf_len - off);
                        /* Use %*phN to get a proper hex dump of 'chunk' bytes */
                        wg_dbg("%04x: %*phN\n", off, chunk, buf + off);
                }
        }

        /* 2) Raw IP header dump (IPv4 only) */
        {
        /* FIX: -Wdistinct-pointer-types — use unsigned char* to match
         * skb->head and skb_end_pointer() types
         */
                unsigned char *net_hdr = skb_network_header(skb);
                if (net_hdr >= skb->head &&
                    net_hdr + sizeof(struct iphdr) <= skb_end_pointer(skb)) {
                        const struct iphdr *iph     = ip_hdr(skb);
                        int                  ihl     = iph->ihl * 4;
                        const unsigned char *ip_ptr = net_hdr;

                        wg_dbg("==== Raw IP header dump (%d bytes) ====\n", ihl);
                        wg_dbg("%*phN\n", ihl, ip_ptr);
                } else {
                        printk(KERN_WARNING "wg_print_wireguard_skb: invalid IP header pointers\n");
                }
        }

        /* 3) Enhanced SKB diagnostics */
        debug_skb(skb);

        /* 4) WireGuard payload dump */
        if (skb->data && skb->len > 0) {
                wg_print_wireguard_packet(skb->data, skb->len);
        } else {
                wg_dbg("wg_print_wireguard_skb: skb data invalid (data=%p, len=%u)\n",
                       skb->data, skb->len);
        }
}


/* New helper function to track and debug MTU issues */
/* FIX: -Wunused-function — marked __maybe_unused (debug helper) */
static void __maybe_unused debug_wireguard_tcp_mtu(struct sk_buff *skb, const char *location)
{
        const struct iphdr *iph;
        int actual_size, dev_mtu = 0;

        if (!skb || !location)
                return;

        if (skb->dev)
                dev_mtu = skb->dev->mtu;

        actual_size = skb->len;

        wg_dbg("=== WG-TCP MTU Check at %s ===\n", location);
        wg_dbg("Packet size: %d bytes", actual_size);

        if (dev_mtu > 0) {
                wg_dbg("Device MTU: %d bytes", dev_mtu);
                if (actual_size > dev_mtu)
                        printk(KERN_WARNING "WARNING: Packet exceeds MTU by %d bytes\n",
                               actual_size - dev_mtu);
        }

        if (skb_network_header_len(skb) >= sizeof(struct iphdr)) {
                iph = ip_hdr(skb);
                if (iph && (ntohs(iph->frag_off) & IP_DF)) {
                        wg_dbg("DF flag is set - PMTUD expected to handle oversized packets\n");

                        /* Check if socket has valid route with correct PMTU */
                        if (skb->sk) {
                                struct dst_entry *dst = skb_dst(skb);
                                if (dst) {
                                        int pmtu = dst_mtu(dst);
                                        wg_dbg("Path MTU from route: %d bytes\n", pmtu);
                                        if (actual_size > pmtu)
                                                printk(KERN_WARNING "WARNING: Packet exceeds path MTU by %d bytes!\n",
                                                       actual_size - pmtu);
                                } else {
                                        wg_dbg("No destination cache entry (no PMTU info)\n");
                                }
                        }
                }
        }

        wg_dbg("GSO: %s (segs=%u, size=%u)\n",
               skb_is_gso(skb) ? "enabled" : "disabled",
               skb_is_gso(skb) ? skb_shinfo(skb)->gso_segs : 0,
               skb_is_gso(skb) ? skb_shinfo(skb)->gso_size : 0);

        wg_dbg("=== WG-TCP MTU Check End ===\n");
}

#ifdef OLD
static void wg_packet_send_handshake_initiation(struct wg_peer *peer)
{
	wg_dbg("Entering wg_packet_send_handshake_initiation with peer=%px\n", peer);
	struct message_handshake_initiation packet;

	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT)) {
		wg_dbg("Exiting wg_packet_send_handshake_initiation\n");
		return; /* This function is rate limited. */
	}

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	if (wg_noise_handshake_create_initiation(&packet, &peer->handshake)) {
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);

		wg_dbg("MAC added to handshake initiation packet\n");
		wg_dbg("Handshake Initiation Packet: %*ph\n",
			(int)sizeof(packet), &packet);
		wg_dbg("Peer Cookie Parameters: peer=%px, handshake=%px, index=%u\n",
			peer, &peer->handshake, packet.sender_index);

		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);
		atomic64_set(&peer->last_sent_handshake,
			     ktime_get_coarse_boottime_ns());
		wg_socket_send_buffer_to_peer(peer, &packet, sizeof(packet),
					      HANDSHAKE_DSCP);
		wg_timers_handshake_initiated(peer);
	}
	wg_dbg("Exiting wg_packet_send_handshake_initiation\n");
}
#endif

static void wg_packet_send_handshake_initiation(struct wg_peer *peer)
{
	struct message_handshake_initiation packet;

	/* Enter function with peer information */
	wg_dbg("Entering wg_packet_send_handshake_initiation with peer=%px\n", peer);

	/* Check rate limiting */
	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake), REKEY_TIMEOUT)) {
		wg_dbg("wg_packet_send_handshake_initiation: Handshake rate limit not expired for peer=%px\n", peer);
		wg_dbg("Exiting wg_packet_send_handshake_initiation\n");
		return;
	}

	/* Update last sent handshake time */
	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());

	/* Log handshake initiation attempt */
	wg_dbg("%s: Sending handshake initiation to peer %llu (%pISpfsc)\n",
	       peer->device->dev->name, peer->internal_id,
	       &peer->endpoint.addr);

	/* Create handshake initiation */
	if (wg_noise_handshake_create_initiation(&packet, &peer->handshake)) {
		wg_dbg("wg_packet_send_handshake_initiation: Handshake initiation created successfully for peer=%px\n", peer);

		/* Print out the contents of the handshake initiation packet */
		wg_dbg("wg_packet_send_handshake_initiation: Handshake packet contents: %*ph\n",
		       (int)sizeof(packet), &packet);

		/* Add MAC to packet */
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);
		wg_dbg("wg_packet_send_handshake_initiation: MAC added to handshake packet for peer=%px\n", peer);

		/* Timers and sending operations */
		wg_timers_any_authenticated_packet_traversal(peer);
		wg_timers_any_authenticated_packet_sent(peer);

		/* Update last sent handshake time again */
		atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());

		/* Send the handshake packet */
		wg_socket_send_buffer_to_peer(peer, &packet, sizeof(packet), HANDSHAKE_DSCP);
		wg_dbg("wg_packet_send_handshake_initiation: Handshake packet sent to peer=%px\n", peer);

		/* Mark handshake initiation complete */
		wg_timers_handshake_initiated(peer);
	} else {
		/* Log failure to create handshake initiation */
		wg_dbg("wg_packet_send_handshake_initiation: Failed to create handshake initiation for peer=%px\n", peer);
	}

	/* Exit function */
	wg_dbg("Exiting wg_packet_send_handshake_initiation\n");
}

void wg_packet_handshake_send_worker(struct work_struct *work)
{
	wg_dbg("Entering wg_packet_handshake_send_worker with work=%px\n", work);
	struct wg_peer *peer = container_of(work, struct wg_peer,
					    transmit_handshake_work);

	wg_packet_send_handshake_initiation(peer);
	wg_peer_put(peer);
	wg_dbg("Exiting wg_packet_handshake_send_worker\n");
}

void wg_packet_send_queued_handshake_initiation(struct wg_peer *peer,
						bool is_retry)
{
	wg_dbg("Entering wg_packet_send_queued_handshake_initiation with peer=%px, is_retry=%d\n", peer, is_retry);
	if (!is_retry)
		peer->timer_handshake_attempts = 0;

	rcu_read_lock_bh();
	/* We check last_sent_handshake here in addition to the actual function
	 * we're queueing up, so that we don't queue things if not strictly
	 * necessary:
	 */
	if (!wg_birthdate_has_expired(atomic64_read(&peer->last_sent_handshake),
				      REKEY_TIMEOUT) ||
			unlikely(READ_ONCE(peer->is_dead)))
		goto out;

	wg_peer_get(peer);
	/* Queues up calling packet_send_queued_handshakes(peer), where we do a
	 * peer_put(peer) after:
	 */
	if (!queue_work(peer->device->handshake_send_wq,
			&peer->transmit_handshake_work))
		/* If the work was already queued, we want to drop the
		 * extra reference:
		 */
		wg_peer_put(peer);
out:
	rcu_read_unlock_bh();
	wg_dbg("Exiting wg_packet_send_queued_handshake_initiation\n");
}

void wg_packet_send_handshake_response(struct wg_peer *peer)
{
	wg_dbg("Entering wg_packet_send_handshake_response with peer=%px\n", peer);
	struct message_handshake_response packet;

	atomic64_set(&peer->last_sent_handshake, ktime_get_coarse_boottime_ns());
	net_dbg_ratelimited("%s: Sending handshake response to peer %llu (%pISpfsc)\n",
			    peer->device->dev->name, peer->internal_id,
			    &peer->endpoint.addr);

	if (wg_noise_handshake_create_response(&packet, &peer->handshake)) {
		wg_cookie_add_mac_to_packet(&packet, sizeof(packet), peer);

		wg_dbg("MAC added to handshake response packet\n");
		wg_dbg("Handshake Response Packet: %*ph\n",
			(int)sizeof(packet), &packet);
		wg_dbg("Peer Cookie Parameters: peer=%px, handshake=%px, index=%u\n",
			peer, &peer->handshake, packet.sender_index);


		if (wg_noise_handshake_begin_session(&peer->handshake,
						     &peer->keypairs)) {
			wg_timers_session_derived(peer);
			wg_timers_any_authenticated_packet_traversal(peer);
			wg_timers_any_authenticated_packet_sent(peer);
			atomic64_set(&peer->last_sent_handshake,
				     ktime_get_coarse_boottime_ns());
			wg_socket_send_buffer_to_peer(peer, &packet,
						      sizeof(packet),
						      HANDSHAKE_DSCP);
		}
	}
	wg_dbg("Exiting wg_packet_send_handshake_response\n");
}

void wg_packet_send_handshake_cookie(struct wg_device *wg,
				     struct sk_buff *initiating_skb,
				     __le32 sender_index)
{
	wg_dbg("Entering wg_packet_send_handshake_cookie with wg=%px, initiating_skb=%px, sender_index=%u\n", wg, initiating_skb, sender_index);
	struct message_handshake_cookie packet;

	wg_dbg("Creating handshake cookie\n");
	wg_dbg("initiating_skb len=%u\n", initiating_skb->len);
	wg_dbg("Initiating SKB Data: %*ph\n",
	(int)initiating_skb->len, initiating_skb->data);

	wg_dbg("Cookie Checker: %px\n", &wg->cookie_checker);


	net_dbg_skb_ratelimited("%s: Sending cookie response for denied handshake message for %pISpfsc\n",
				wg->dev->name, initiating_skb);
	wg_cookie_message_create(&packet, initiating_skb, sender_index,
				 &wg->cookie_checker);

	wg_dbg("Handshake Cookie Packet: %*ph\n",
		(int)sizeof(packet), &packet);

	wg_socket_send_buffer_as_reply_to_skb(wg, initiating_skb, &packet,
					      sizeof(packet));

	wg_dbg("Exiting wg_packet_send_handshake_cookie\n");
}

static void keep_key_fresh(struct wg_peer *peer)
{
	wg_dbg("Entering keep_key_fresh with peer=%px\n", peer);
	struct noise_keypair *keypair;
	bool send;

	rcu_read_lock_bh();
	keypair = rcu_dereference_bh(peer->keypairs.current_keypair);
	send = keypair && READ_ONCE(keypair->sending.is_valid) &&
	       (atomic64_read(&keypair->sending_counter) > REKEY_AFTER_MESSAGES ||
		(keypair->i_am_the_initiator &&
		 wg_birthdate_has_expired(keypair->sending.birthdate, REKEY_AFTER_TIME)));
	rcu_read_unlock_bh();

	if (unlikely(send))
		wg_packet_send_queued_handshake_initiation(peer, false);
	wg_dbg("Exiting keep_key_fresh\n");
}

static unsigned int calculate_skb_padding(struct sk_buff *skb)
{
	wg_dbg("Entering calculate_skb_padding with skb=%px\n", skb);
	unsigned int padded_size, last_unit = skb->len;

	if (unlikely(!PACKET_CB(skb)->mtu)) {
		wg_dbg("Exiting calculate_skb_padding\n");
		return ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE) - last_unit;
	}

	/* We do this modulo business with the MTU, just in case the networking
	 * layer gives us a packet that's bigger than the MTU. In that case, we
	 * wouldn't want the final subtraction to overflow in the case of the
	 * padded_size being clamped. Fortunately, that's very rarely the case,
	 * so we optimize for that not happening.
	 */
	if (unlikely(last_unit > PACKET_CB(skb)->mtu))
		last_unit %= PACKET_CB(skb)->mtu;

	padded_size = min(PACKET_CB(skb)->mtu,
			  ALIGN(last_unit, MESSAGE_PADDING_MULTIPLE));
	wg_dbg("Exiting calculate_skb_padding\n");
	return padded_size - last_unit;
}

static bool encrypt_packet(struct sk_buff *skb, struct noise_keypair *keypair)
{
    unsigned int padding_len, plaintext_len, trailer_len;
    struct scatterlist sg[MAX_SKB_FRAGS + 8];
    struct message_data *header;
    struct sk_buff *trailer;
    int num_frags;

    wg_dbg("Entering encrypt_packet with skb=%px, keypair=%px\n", skb, keypair);
    wg_dbg("skb->len = %u, skb->data_len = %u, skb->network_header = %px\n", skb->len, skb->data_len, skb_network_header(skb));
    wg_dbg("keypair->remote_index = %u\n", keypair->remote_index);
    wg_dbg("skb->data (before encryption): %*ph\n", skb->len, skb->data);
#ifdef WG_TCP_VERBOSE
    decode_and_print_packet(skb, "[encrypt]");
#endif

    /* Force hash calculation before encryption */
    skb_get_hash(skb);
    wg_dbg("Hash calculated for skb.\n");

    /* Calculate lengths */
    padding_len = calculate_skb_padding(skb);
    trailer_len = padding_len + noise_encrypted_len(0);
    plaintext_len = skb->len + padding_len;
    wg_dbg("Calculated lengths: padding_len=%u, trailer_len=%u, plaintext_len=%u\n", padding_len, trailer_len, plaintext_len);

    /* Expand data section */
    num_frags = skb_cow_data(skb, trailer_len, &trailer);
    if (unlikely(num_frags < 0 || num_frags > ARRAY_SIZE(sg))) {
        wg_dbg("Failed skb_cow_data: num_frags=%d, skb->len=%u\n", num_frags, skb->len);
        wg_dbg("Exiting encrypt_packet with false\n");
        return false;
    }

    /* Set the padding to zeros */
    memset(skb_tail_pointer(trailer), 0, padding_len);
    wg_dbg("Padding set to zeros: padding_len=%u, skb->len=%u\n", padding_len, skb->len);

    /* Expand head section */
    if (unlikely(skb_cow_head(skb, DATA_PACKET_HEAD_ROOM) < 0)) {
        wg_dbg("Failed skb_cow_head, skb->len=%u, skb->head=%px\n", skb->len, skb->head);
        wg_dbg("Exiting encrypt_packet with false\n");
        return false;
    }
    wg_dbg("Expanded head section, skb->len=%u, skb->head=%px\n", skb->len, skb->head);

    /* Finalize checksum calculation */
    if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL && skb_checksum_help(skb))) {
        wg_dbg("Failed skb_checksum_help, skb->len=%u\n", skb->len);
        wg_dbg("Exiting encrypt_packet with false\n");
        return false;
    }
    wg_dbg("Checksum finalized, skb->len=%u\n", skb->len);

    /* Add padding and header */
    skb_set_inner_network_header(skb, 0);
    header = (struct message_data *)skb_push(skb, sizeof(*header));
    header->header.type = cpu_to_le32(MESSAGE_DATA);
    header->key_idx = keypair->remote_index;
    header->counter = cpu_to_le64(PACKET_CB(skb)->nonce);
    wg_dbg("Nonce for encryption: %llu\n", PACKET_CB(skb)->nonce);
#define NOISE_KEY_LEN 32
    wg_dbg("Encryption key: %*ph\n", NOISE_KEY_LEN, keypair->sending.key);
    pskb_put(skb, trailer, trailer_len);
    wg_dbg("Header and padding added: type=%u, key_idx=%u, counter=%llu\n",
           MESSAGE_DATA, keypair->remote_index, PACKET_CB(skb)->nonce);
    wg_dbg("Network header set: skb_network_header=%px, skb->len=%u\n", skb_network_header(skb), skb->len);

    /* Encrypt the scattergather segments */
    sg_init_table(sg, num_frags);
    if (skb_to_sgvec(skb, sg, sizeof(struct message_data), noise_encrypted_len(plaintext_len)) <= 0) {
        wg_dbg("Failed skb_to_sgvec, skb->len=%u\n", skb->len);
        wg_dbg("Exiting encrypt_packet with false\n");
        return false;
    }

    wg_dbg("Scattergather segments prepared, starting encryption\n");

    bool success = chacha20poly1305_encrypt_sg_inplace(sg, plaintext_len, NULL, 0,
                                                       PACKET_CB(skb)->nonce,
                                                       keypair->sending.key);
    wg_dbg("skb->data (after encryption): %*ph\n", skb->len, skb->data);
    wg_dbg("Exiting encrypt_packet with %s, skb->len=%u\n", success ? "true" : "false", skb->len);
    return success;
}

/* Helper function to extract IPv4 fragmentation info */
static inline bool wg_ipv4_get_fraginfo(const struct sk_buff *skb,
					__be16 *id, __be16 *frag_off)
{
	const struct iphdr *iph;

	if (skb->protocol != htons(ETH_P_IP))
		return false;

	if (!pskb_may_pull((struct sk_buff *)skb, sizeof(struct iphdr)))
		return false;

	iph = ip_hdr(skb);
	if (!(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		return false; /* not fragmented */

	*id = iph->id;
	*frag_off = iph->frag_off;
	return true;
}

void wg_packet_send_keepalive(struct wg_peer *peer)
{
	wg_dbg("Entering wg_packet_send_keepalive with peer=%px\n", peer);
	struct sk_buff *skb;

	if (skb_queue_empty(&peer->staged_packet_queue)) {
		skb = alloc_skb(DATA_PACKET_HEAD_ROOM + MESSAGE_MINIMUM_LENGTH,
				GFP_ATOMIC);
		if (unlikely(!skb)) {
			wg_dbg("Exiting wg_packet_send_keepalive\n");
			return;
		}
		skb_reserve(skb, DATA_PACKET_HEAD_ROOM);
		skb->dev = peer->device->dev;
		PACKET_CB(skb)->mtu = skb->dev->mtu;
		skb_queue_tail(&peer->staged_packet_queue, skb);
		net_dbg_ratelimited("%s: Sending keepalive packet to peer %llu (%pISpfsc)\n",
				    peer->device->dev->name, peer->internal_id,
				    &peer->endpoint.addr);
	}

	wg_packet_send_staged_packets(peer);
	wg_dbg("Exiting wg_packet_send_keepalive\n");
}

static void wg_packet_create_data_done(struct wg_peer *peer, struct sk_buff *first)
{
	wg_dbg("Entering wg_packet_create_data_done with peer=%px, first=%px\n", peer, first);
	struct sk_buff *skb, *next;
	bool is_keepalive, data_sent = false;

	wg_timers_any_authenticated_packet_traversal(peer);
	wg_timers_any_authenticated_packet_sent(peer);
	skb_list_walk_safe(first, skb, next) {
		is_keepalive = skb->len == message_data_len(0);
		if (likely(!wg_socket_send_skb_to_peer(peer, skb,
				PACKET_CB(skb)->ds) && !is_keepalive))
			data_sent = true;
	}

	if (likely(data_sent))
		wg_timers_data_sent(peer);

	keep_key_fresh(peer);
	wg_dbg("Exiting wg_packet_create_data_done\n");
}

void wg_packet_tx_worker(struct work_struct *work)
{
	wg_dbg("Entering wg_packet_tx_worker with work=%px\n", work);
	struct wg_peer *peer = container_of(work, struct wg_peer, transmit_packet_work);
	struct noise_keypair *keypair;
	enum packet_state state;
	struct sk_buff *first;

	while ((first = wg_prev_queue_peek(&peer->tx_queue)) != NULL &&
	       (state = atomic_read_acquire(&PACKET_CB(first)->state)) !=
		       PACKET_STATE_UNCRYPTED) {
		wg_prev_queue_drop_peeked(&peer->tx_queue);
		keypair = PACKET_CB(first)->keypair;

		if (likely(state == PACKET_STATE_CRYPTED))
			wg_packet_create_data_done(peer, first);
		else
			kfree_skb_list(first);

		wg_noise_keypair_put(keypair, false);
		wg_peer_put(peer);
		if (need_resched())
			cond_resched();
	}
	wg_dbg("Exiting wg_packet_tx_worker\n");
}

void wg_packet_encrypt_worker(struct work_struct *work)
{
	wg_dbg("Entering wg_packet_encrypt_worker with work=%px\n", work);
	struct crypt_queue *queue = container_of(work, struct multicore_worker,
						 work)->ptr;
	struct sk_buff *first, *skb, *next;

	while ((first = ptr_ring_consume_bh(&queue->ring)) != NULL) {
		enum packet_state state = PACKET_STATE_CRYPTED;

		skb_list_walk_safe(first, skb, next) {
			if (likely(encrypt_packet(skb,
					PACKET_CB(first)->keypair))) {
				wg_reset_packet(skb, true);
			} else {
				state = PACKET_STATE_DEAD;
				break;
			}
		}
		wg_queue_enqueue_per_peer_tx(first, state);
		if (need_resched())
			cond_resched();
	}
	wg_dbg("Exiting wg_packet_encrypt_worker\n");
}



static void wg_packet_create_data(struct wg_peer *peer, struct sk_buff *first)
{
	wg_dbg("Entering wg_packet_create_data with peer=%px, first=%px\n", peer, first);
	struct wg_device *wg = peer->device;
	int ret = -EINVAL;

	rcu_read_lock_bh();
	if (unlikely(READ_ONCE(peer->is_dead)))
		goto err;

	wg_dbg("wg_packet_create_data sending: %*ph\n", first->len, first->data);

	ret = wg_queue_enqueue_per_device_and_peer(&wg->encrypt_queue, &peer->tx_queue, first,
						   wg->packet_crypt_wq);
	if (unlikely(ret == -EPIPE))
		wg_queue_enqueue_per_peer_tx(first, PACKET_STATE_DEAD);

err:
	rcu_read_unlock_bh();
	if (likely(!ret || ret == -EPIPE)) {
		wg_dbg("Exiting wg_packet_create_data\n");
		return;
	}
	wg_noise_keypair_put(PACKET_CB(first)->keypair, false);
	wg_peer_put(peer);
	kfree_skb_list(first);
	wg_dbg("Exiting wg_packet_create_data with error.\n");
}

void wg_packet_purge_staged_packets(struct wg_peer *peer)
{
	wg_dbg("Entering wg_packet_purge_staged_packets with peer=%px\n", peer);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	DEV_STATS_ADD(peer->device->dev, tx_dropped,
		      peer->staged_packet_queue.qlen);
	__skb_queue_purge(&peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	wg_dbg("Exiting wg_packet_purge_staged_packets\n");
}

void wg_packet_send_staged_packets(struct wg_peer *peer)
{
	wg_dbg("Entering wg_packet_send_staged_packets with peer=%px\n", peer);
	struct noise_keypair *keypair;
	struct sk_buff_head packets;
	struct sk_buff *skb;
	/* FIX: -Wunused-variable — removed unused __be16 frag_id, frag_off */
	/* Steal the current queue into our local one. */
	__skb_queue_head_init(&packets);
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice_init(&peer->staged_packet_queue, &packets);
	spin_unlock_bh(&peer->staged_packet_queue.lock);
	if (unlikely(skb_queue_empty(&packets))) {
		wg_dbg("Exiting wg_packet_send_staged_packets\n");
		return;
	}

	/* First we make sure we have a valid reference to a valid key. */
	rcu_read_lock_bh();
	keypair = wg_noise_keypair_get(
		rcu_dereference_bh(peer->keypairs.current_keypair));
	rcu_read_unlock_bh();
	if (unlikely(!keypair))
		goto out_nokey;
	if (unlikely(!READ_ONCE(keypair->sending.is_valid)))
		goto out_nokey;
	if (unlikely(wg_birthdate_has_expired(keypair->sending.birthdate,
					      REJECT_AFTER_TIME)))
		goto out_invalid;

	/* After we know we have a somewhat valid key, we now try to assign
	 * nonces to all of the packets in the queue. If we can't assign nonces
	 * for all of them, we just consider it a failure and wait for the next
	 * handshake.
	 */
	skb_queue_walk(&packets, skb) {
		/* 0 for no outer TOS: no leak. TODO: at some later point, we
		 * might consider using flowi->tos as outer instead.
		 */
		PACKET_CB(skb)->ds = ip_tunnel_ecn_encap(0, ip_hdr(skb), skb);
		PACKET_CB(skb)->nonce =
				atomic64_inc_return(&keypair->sending_counter) - 1;
		if (unlikely(PACKET_CB(skb)->nonce >= REJECT_AFTER_MESSAGES))
			goto out_invalid;

		/* XXX - Jeff:
		 *  This codepath is only executed for for keepalives,
		 *  when an interface comes up, or when set_peer is called.
		 *  This is likely unnecessary and we'll revisit it
		 *  for removal
		 */
		/* Extract fragmentation info if this is IPv4 and fragmented */
		if (peer->device->transport == WG_TRANSPORT_TCP &&
		    skb->protocol == htons(ETH_P_IP)) {
			__be16 id = 0, frag_off = 0;
			if (wg_ipv4_get_fraginfo(skb, &id, &frag_off)) {
				PACKET_CB(skb)->frag_id = id;
				PACKET_CB(skb)->frag_off = frag_off;
				wg_dbg("Fragmentation detected: id=%u, frag_off=0x%x\n",
				       ntohs(id), ntohs(frag_off));
			} else {
				PACKET_CB(skb)->frag_id = 0;
				PACKET_CB(skb)->frag_off = 0;
			}
		} else {
			/* Non-IPv4 packets don't have fragmentation info */
			PACKET_CB(skb)->frag_id = 0;
			PACKET_CB(skb)->frag_off = 0;
		}
	}

	packets.prev->next = NULL;
	wg_peer_get(keypair->entry.peer);
	PACKET_CB(packets.next)->keypair = keypair;
	wg_packet_create_data(peer, packets.next);
	wg_dbg("Exiting wg_packet_send_staged_packets\n");
	return;

out_invalid:
	WRITE_ONCE(keypair->sending.is_valid, false);
out_nokey:
	wg_noise_keypair_put(keypair, false);

	/* We orphan the packets if we're waiting on a handshake, so that they
	 * don't block a socket's pool.
	 */
	skb_queue_walk(&packets, skb)
		skb_orphan(skb);
	/* Then we put them back on the top of the queue. We're not too
	 * concerned about accidentally getting things a little out of order if
	 * packets are being added really fast, because this queue is for before
	 * packets can even be sent and it's small anyway.
	 */
	spin_lock_bh(&peer->staged_packet_queue.lock);
	skb_queue_splice(&packets, &peer->staged_packet_queue);
	spin_unlock_bh(&peer->staged_packet_queue.lock);

	/* If we're exiting because there's something wrong with the key, it
	 * means we should initiate a new handshake.
	 */
	wg_packet_send_queued_handshake_initiation(peer, false);
	wg_dbg("Exiting wg_packet_send_staged_packets\n");
}

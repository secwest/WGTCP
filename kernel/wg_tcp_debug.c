// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * TCP Support Copyright (c) 2024-2026 Jeff Nathan and Dragos Ruiu. All Rights Reserved.
 */

#include <linux/icmp.h>

#include "device.h"
#include "messages.h"
#include "peer.h"
#include "queueing.h"
#include "wg_tcp.h"
#include "wg_tcp_debug.h"

#include <asm/byteorder.h>
#include <linux/atomic.h>
#include <linux/err.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/printk.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <net/dst.h>
#include <net/inet_connection_sock.h>
#include <net/inet_sock.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/tcp.h>

/*
 * Enhanced SKB diagnostic and debugging function with focus on fragmentation,
 * GSO/TSO, IP/TCP header analysis, PMTUD, and TCP options.
 */
void debug_skb(const struct sk_buff *askb)
{
	const struct iphdr *iph = NULL;
	const struct tcphdr *tcph = NULL;
	struct net_device *dev;
	unsigned int frag_off_val;
	bool more_frags;
	int mtu = 0;
	int i;
	unsigned char *net_hdr;
	unsigned char *end;

	if (!askb) {
		printk(KERN_ERR "debug_skb: askb is NULL\n");
		return;
	}

	dev = askb->dev;
	net_hdr = skb_network_header(askb);
	end = skb_end_pointer(askb);

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
	if (askb->data_len > 0)
	{
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
		iph = ip_hdr(askb);
		frag_off_val = ntohs(iph->frag_off);
		more_frags = !!(frag_off_val & IP_MF);

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
			int total = ntohs(iph->tot_len);
			int ip_hlen = iph->ihl * 4;
			int tcp_hlen = tcph->doff * 4;
			int payload = total - ip_hlen - tcp_hlen;
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
			const unsigned char *opt = (const unsigned char *)(tcph + 1);
			int optlen = (tcph->doff - 5) * 4;
			int j = 0;

			wg_dbg("---- TCP Options (%u bytes) ----\n", optlen);
			while (j < optlen)
			{
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
					if (length == 4)
					{
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

void debug_wireguard_packet(const unsigned char *data, size_t payload_len)
{
	size_t i, len;

	if (payload_len < sizeof(u32))
	{
		wg_dbg("WireGuard packet too short\n");
		return;
	}

	wg_dbg("WireGuard packet payload (%zu bytes):\n", payload_len);
	for (i = 0; i < payload_len; i += 32)
	{
		len = min((size_t)32, payload_len - i);
		wg_dbg("%*ph\n", (int)len, data + i);
	}
}

/*
 * Dump the contents of an SKB—including a full raw-hex dump,
 * an IP header dump, then hand off to debug_skb(), and finally
 * the WireGuard payload.
 */
void debug_wireguard_skb(const struct sk_buff *skb)
{
	if (!skb)
	{
		printk(KERN_ERR "debug_wireguard_skb: skb is NULL\n");
		return;
	}

	/* 1) Full raw buffer dump (head→end) */
	{
		const unsigned char *buf = skb->head;
		int buf_len = skb_end_pointer(skb) - skb->head;
		int off;

		wg_dbg("==== Full raw SKB buffer dump head->end (%d bytes) ====\n",
		       buf_len);
		for (off = 0; off < buf_len; off += 16)
		{
			int chunk = min(16, buf_len - off);
			/* Use %*phN to get a proper hex dump of 'chunk' bytes */
			wg_dbg("%04x: %*phN\n", off, chunk, buf + off);
		}
	}

	/* 2) Raw IP header dump (IPv4 only) */
	{
		unsigned char *net_hdr = skb_network_header(skb);
		if (net_hdr >= skb->head &&
		    net_hdr + sizeof(struct iphdr) <= skb_end_pointer(skb))
		{
			const struct iphdr *iph = ip_hdr(skb);
			int ihl = iph->ihl * 4;
			const unsigned char *ip_ptr = net_hdr;

			wg_dbg("==== Raw IP header dump (%d bytes) ====\n", ihl);
			wg_dbg("%*phN\n", ihl, ip_ptr);
		}
		else
		{
			printk(KERN_WARNING "debug_wireguard_skb: invalid IP header pointers\n");
		}
	}

	/* 3) Enhanced SKB diagnostics */
        debug_skb(skb);

        /* 4) WireGuard payload dump */
        if (skb->data && skb->len > 0) {
                debug_wireguard_packet(skb->data, skb->len);
        } else {
                wg_dbg("debug_wireguard_skb: skb data invalid (data=%p, len=%u)\n",
                       skb->data, skb->len);
        }
}

/* New helper function to track and debug MTU issues */
void debug_wireguard_tcp_mtu(struct sk_buff *skb, const char *location)
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

	if (skb_network_header_len(skb) >= sizeof(struct iphdr))
	{
		iph = ip_hdr(skb);
		if (iph && (ntohs(iph->frag_off) & IP_DF)) {
			wg_dbg("DF flag is set - PMTUD expected to handle oversized packets\n");

			/* Check if socket has valid route with correct PMTU */
			if (skb->sk) {
				struct dst_entry *dst = skb_dst(skb);
				if (dst)
				{
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

/* Helper function implementations */
void decode_icmp_echo(const struct icmphdr *icmp_header)
{
	struct icmp_echo {
		struct icmphdr hdr;
		__be16 id;
		__be16 sequence;
	} __attribute__((packed));

	const struct icmp_echo *echo = (const struct icmp_echo *)icmp_header;

	wg_dbg("    Identifier: %u\n", ntohs(echo->id));
	wg_dbg("    Sequence Number: %u\n", ntohs(echo->sequence));
}

void decode_icmp_dest_unreachable(const struct icmphdr *icmp_header)
{
	wg_dbg("    Gateway Address: %pI4\n", &icmp_header->un.gateway);

	switch (icmp_header->code) {
	case ICMP_NET_UNREACH:
		wg_dbg("    Code: Network Unreachable\n");
		break;
	case ICMP_HOST_UNREACH:
		wg_dbg("    Code: Host Unreachable\n");
		break;
	case ICMP_PROT_UNREACH:
		wg_dbg("    Code: Protocol Unreachable\n");
		break;
	case ICMP_PORT_UNREACH:
		wg_dbg("    Code: Port Unreachable\n");
		break;
	/* Add more cases as needed */
	default:
		wg_dbg("    Code: %u\n", icmp_header->code);
		break;
	}
}

void decode_icmp_time_exceeded(const struct icmphdr *icmp_header)
{
	wg_dbg("    Unused Field: %u\n", ntohl(icmp_header->un.gateway));

	switch (icmp_header->code) {
        case ICMP_EXC_TTL:
		wg_dbg("    Code: Time To Live Exceeded\n");
		break;
        case ICMP_EXC_FRAGTIME:
		wg_dbg("    Code: Fragment Reassembly Time Exceeded\n");
		break;
        default:
		wg_dbg("    Code: %u\n", icmp_header->code);
		break;
	}
}

void decode_icmp_other(const struct icmphdr *icmp_header)
{
	wg_dbg("    Rest of Header (Raw Data): %u\n", ntohl(icmp_header->un.gateway));
}

/*
 * Function to decode and print TCP, UDP, and ICMP parameters
 * Now accepts 'const char *prefix' and conditionally linearizes fragmented packets
 */
void decode_and_print_packet(const struct sk_buff *skb, const char *prefix)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	struct udphdr *udp_header;
	struct icmphdr *icmp_header;
	unsigned int ip_header_length;
	unsigned int tcp_header_length;

	/* Retrieve the IP header using helper function */
	ip_header = ip_hdr(skb);

	/* Ensure the skb contains enough data for IP header */
	if (skb->len < sizeof(struct iphdr)) {
		wg_dbg("%sPacket too short for IP header\n", prefix);
		return;
	}

	ip_header_length = ip_header->ihl * 4;

	/* Verify that the IP header length is valid */
	if (ip_header_length < sizeof(struct iphdr)) {
		wg_dbg("%sInvalid IP header length: %u bytes\n", prefix, ip_header_length);
		return;
	}

	/* Ensure the skb has the complete IP header */
	if (skb->len < ip_header_length) {
		wg_dbg("%sIncomplete IP header in skb\n", prefix);
		return;
	}

    /*
     * Check if the packet is fragmented
     * ip_header->frag_off is in network byte order; convert to host byte order
     */
	if (ntohs(ip_header->frag_off) & (IP_MF | IP_OFFSET)) {
		/* Packet is fragmented; attempt to linearize */
		if (skb_linearize((struct sk_buff *)skb) < 0) {
			wg_dbg("%sFailed to linearize skb for fragmented packet\n", prefix);
			return;
		}

		/* After linearization, re-fetch the IP header as skb data may have changed */
		ip_header = ip_hdr(skb);
		ip_header_length = ip_header->ihl * 4;

		/* Re-validate IP header after linearization */
		if (ip_header_length < sizeof(struct iphdr)) {
			wg_dbg("%sInvalid IP header length after linearization: %u bytes\n", prefix, ip_header_length);
			return;
		}

		if (skb->len < ip_header_length) {
			wg_dbg("%sIncomplete IP header in skb after linearization\n", prefix);
			return;
		}
	}

	/* Determine the protocol and handle accordingly */
	switch (ip_header->protocol) {
	case IPPROTO_TCP:
            /* Ensure the skb has enough data for the TCP header */
		if (skb->len < ip_header_length + sizeof(struct tcphdr)) {
			wg_dbg("%sPacket too short for TCP header\n", prefix);
			return;
		}

		/* Retrieve the TCP header using helper function */
		tcp_header = tcp_hdr(skb);
		if (!tcp_header) {
			wg_dbg("%sFailed to retrieve TCP header\n", prefix);
			return;
		}

		tcp_header_length = tcp_header->doff * 4;

		/* Validate TCP header length */
		if (tcp_header_length < sizeof(struct tcphdr)) {
			wg_dbg("%sInvalid TCP header length: %u bytes\n", prefix, tcp_header_length);
			return;
		}

		/* Ensure the skb has the complete TCP header */
		if (skb->len < ip_header_length + tcp_header_length) {
			wg_dbg("%sPacket too short for complete TCP header\n", prefix);
			return;
		}

		/* Define a buffer to hold the TCP flags string */
		char tcp_flags[64];
		tcp_flags[0] = '\0'; /* Initialize the string */

		/* Append each TCP flag if it is set */
		if (tcp_header->fin)
			strlcat(tcp_flags, "FIN ", sizeof(tcp_flags));
		if (tcp_header->syn)
			strlcat(tcp_flags, "SYN ", sizeof(tcp_flags));
		if (tcp_header->rst)
			strlcat(tcp_flags, "RST ", sizeof(tcp_flags));
		if (tcp_header->psh)
			strlcat(tcp_flags, "PSH ", sizeof(tcp_flags));
		if (tcp_header->ack)
			strlcat(tcp_flags, "ACK ", sizeof(tcp_flags));
		if (tcp_header->urg)
			strlcat(tcp_flags, "URG ", sizeof(tcp_flags));
		if (tcp_header->ece)
			strlcat(tcp_flags, "ECE ", sizeof(tcp_flags));
		if (tcp_header->cwr)
			strlcat(tcp_flags, "CWR ", sizeof(tcp_flags));

		/* Print TCP parameters with prefix */
		wg_dbg("%s#### TCP Packet: "
		       "S: %pI4 "
		       "D: %pI4 "
		       "SP: %u "
		       "DP: %u "
		       "SN: %u "
		       "AN: %u "
		       "DO: %u bytes "
		       "F: %s "
		       "WS: %u "
		       "C: 0x%04x "
		       "U: %u "
		       "skb: %px len: %u\n",
		       prefix,
		       &ip_header->saddr,
		       &ip_header->daddr,
		       ntohs(tcp_header->source),
		       ntohs(tcp_header->dest),
		       ntohl(tcp_header->seq),
		       ntohl(tcp_header->ack_seq),
		       tcp_header_length,
		       tcp_flags,
		       ntohs(tcp_header->window),
		       ntohs(tcp_header->check),
		       ntohs(tcp_header->urg_ptr),
		       skb, skb->len);
		break;

        case IPPROTO_UDP:
		/* Ensure the skb has enough data for the UDP header */
		if (skb->len < ip_header_length + sizeof(struct udphdr)) {
			wg_dbg("%sPacket too short for UDP header\n", prefix);
			return;
		}

		/* Retrieve the UDP header using helper function */
		udp_header = udp_hdr(skb);
		if (!udp_header) {
			wg_dbg("%sFailed to retrieve UDP header\n", prefix);
			return;
		}

		/* Print UDP parameters with prefix */
		wg_dbg("%s#### UDP Packet: "
		       "S: %pI4 "
		       "D: %pI4 "
		       "SP: %u "
		       "DP: %u "
		       "L: %u "
		       "C: 0x%04x "
		       "skb: %px len: %u\n",
		       prefix,
		       &ip_header->saddr,
		       &ip_header->daddr,
		       ntohs(udp_header->source),
		       ntohs(udp_header->dest),
		       ntohs(udp_header->len),
		       ntohs(udp_header->check),
		       skb, skb->len);

		/* Print skb address and length */
		wg_dbg("%sskb address: %px, skb length: %u\n", prefix, skb, skb->len);
		break;

        case IPPROTO_ICMP:
		/* Ensure the skb has enough data for the ICMP header */
		if (skb->len < ip_header_length + sizeof(struct icmphdr)) {
			wg_dbg("%sPacket too short for ICMP header\n", prefix);
			return;
		}

		/* Retrieve the ICMP header using helper function */
		icmp_header = icmp_hdr(skb);
		if (!icmp_header) {
			wg_dbg("%sFailed to retrieve ICMP header\n", prefix);
			return;
		}

		/* Print basic ICMP parameters with prefix */
		wg_dbg("%s#### ICMP Packet: "
		       "S: %pI4 "
		       "D: %pI4 "
		       "Type: %u "
		       "Code: %u "
		       "C: 0x%04x "
		       "skb: %px len: %u\n",
		       prefix,
		       &ip_header->saddr,
		       &ip_header->daddr,
		       icmp_header->type,
		       icmp_header->code,
		       ntohs(icmp_header->checksum),
		       skb, skb->len);

		/* Decode the "Rest of the Header" based on Type */
		switch (icmp_header->type) {
			case ICMP_ECHO:
			case ICMP_ECHOREPLY:
				decode_icmp_echo(icmp_header);
				break;

                case ICMP_DEST_UNREACH:
			decode_icmp_dest_unreachable(icmp_header);
			break;

                case ICMP_TIME_EXCEEDED:
			decode_icmp_time_exceeded(icmp_header);
			break;

                default:
			decode_icmp_other(icmp_header);
			break;
		}

		/* Print skb address and length */
		wg_dbg("%sskb address: %px, skb length: %u\n", prefix, skb, skb->len);
		break;

        default:
		/* Handle unsupported protocols */
		/* BUG FIX: format string was split by comma after D: %pI4\n —
		* "skb: %px len: %u\n" was passed as %s arg, shifting all args (UB/crash)
		*/
		wg_dbg("%s#### Unsupported Protocol: %u "
		       "S: %pI4 "
		       "D: %pI4 "
		       "skb: %px len: %u\n",
		       prefix,
		       ip_header->protocol,
		       &ip_header->saddr,
		       &ip_header->daddr,
		       skb, skb->len);

		/* Print skb address and length */
		wg_dbg("%sskb address: %px, skb length: %u\n", prefix, skb, skb->len);
		break;
	}
}

void print_skbuff_head_info(const char *label, struct sk_buff_head *queue)
{
	const struct sk_buff *skb;
	unsigned long flags;

	wg_dbg("%s:\n", label);
	if (!queue) {
		wg_dbg("Queue is NULL\n");
		return;
	}

	spin_lock_irqsave(&queue->lock, flags);
	skb_queue_walk(queue, skb) {
		wg_dbg("Packet: len=%u, data_len=%u, users=%d\n",
		        skb->len, skb->data_len, refcount_read(&skb->users));
	}
	spin_unlock_irqrestore(&queue->lock, flags);
}

void print_wg_peer(struct wg_peer *peer)
{
	if (!peer || IS_ERR(peer)) {
		printk(KERN_ERR "NULL wg_peer provided\n");
		return;
	}

	wg_dbg("WG Peer Complete Diagnostic Info:\n");
	wg_dbg("Device Pointer: %px, Serial Work CPU: %d, "
	       "Is Dead: %d, (Device) Transport Mode: %u\n",
	       peer->device, peer->serial_work_cpu, peer->is_dead,
	       peer->device->transport);
	wg_dbg("RX Bytes: %llu, TX Bytes: %llu, Internal ID: %llu\n",
	       peer->rx_bytes, peer->tx_bytes, peer->internal_id);
	wg_dbg("Last Sent Handshake: %llu\n",
	       atomic64_read(&peer->last_sent_handshake));

	/* Endpoint info */
	wg_dbg("Endpoint Address Family: %u\n",
	       peer->endpoint.addr.sa_family);
	if (peer->endpoint.addr.sa_family == AF_INET) {
		wg_dbg("IPv4 Address: %pI4, IPv4 Source: %pI4, "
		       "Interface: %d\n",
		       &peer->endpoint.addr4.sin_addr, &peer->endpoint.src4,
		       peer->endpoint.src_if4);
	} else if (peer->endpoint.addr.sa_family == AF_INET6) {
		wg_dbg("IPv6 Address: %pI6c, IPv6 Source: %pI6c\n",
		       &peer->endpoint.addr6.sin6_addr, &peer->endpoint.src6);
	}

	/* Correctly accessing sk_buff_head queues */
	if (!skb_queue_empty(&peer->staged_packet_queue)) {
		print_skbuff_head_info("Staged Packet Queue",
				       &peer->staged_packet_queue);
	} else {
		wg_dbg("Staged Packet Queue: NULL\n");
	}

	/* Additional diagnostics and corrections for TCP */
	if (peer->peer_socket) {
		wg_dbg("TCP Socket: %px, Established: %d\n",
		       peer->peer_socket, peer->tcp_established);
		if (!skb_queue_empty(&peer->send_queue)) {
			print_skbuff_head_info("TCP Packet Queue",
					       &peer->send_queue);
		} else {
			wg_dbg("TCP Packet Queue: NULL\n");
		}
	} else {
		wg_dbg("TCP Socket: NULL\n");
	}

	/* Timer diagnostics */
	wg_dbg("Timer for Retransmit Handshake Expires: %ld\n",
	       peer->timer_retransmit_handshake.expires);
	wg_dbg("Timer for Sending Keepalive Expires: %ld\n",
	       peer->timer_send_keepalive.expires);
	wg_dbg("Timer for New Handshake Expires: %ld\n",
	       peer->timer_new_handshake.expires);
	wg_dbg("Timer for Zero Key Material Expires: %ld\n",
	       peer->timer_zero_key_material.expires);
	wg_dbg("Timer for Persistent Keepalive Expires: %ld\n",
	       peer->timer_persistent_keepalive.expires);

	/* RCU and reference count */
	wg_dbg("RCU Head Address: %px, Reference Count: %d\n",
	       &peer->rcu, kref_read(&peer->refcount));
}

void print_crypt_queue(const char *label, struct crypt_queue *queue)
{
	if (!queue) {
		wg_dbg("%s: NULL\n", label);
		return;
	}

	wg_dbg("%s:\n", label);
	wg_dbg("  Last CPU used: %d\n", queue->last_cpu);
	if (queue->worker)
		wg_dbg("  Worker pointer: %px\n", queue->worker);
	else
		wg_dbg("  Worker: NULL\n");
}

void print_wg_device(struct wg_device *device)
{
	if (!device) {
		printk(KERN_ERR "NULL wg_device provided\n");
		return;
	}

	wg_dbg("WG Device Diagnostic Info:\n");

	if (device->dev)
		wg_dbg("Net device: %s\n", device->dev->name);
	else
		wg_dbg("Net device: NULL\n");

	print_crypt_queue("Encrypt Queue", &(device->encrypt_queue));
	print_crypt_queue("Decrypt Queue", &(device->decrypt_queue));
	print_crypt_queue("Handshake Queue", &(device->handshake_queue));

	if (rcu_access_pointer(device->tcp_listen_socket4))
		wg_dbg("IPv4 Socket: %px\n", device->tcp_listen_socket4);
	else
		wg_dbg("IPv4 Socket: NULL\n");

	if (rcu_access_pointer(device->tcp_listen_socket6))
		wg_dbg("IPv6 Socket: %px\n", device->tcp_listen_socket6);
	else
		wg_dbg("IPv6 Socket: NULL\n");

	if (rcu_access_pointer(device->tcp_listen_socket4))
		wg_dbg("TCP Listener IPv4 Socket: %px\n",
				device->tcp_listen_socket4);
	else
		wg_dbg("TCP Listener IPv4 Socket: NULL\n");

	if (rcu_access_pointer(device->tcp_listen_socket6))
		wg_dbg("TCP Listener IPv6 Socket: %px\n",
				device->tcp_listen_socket6);
	else
		wg_dbg("TCP Listener IPv6 Socket: NULL\n");

	if (device->creating_net)
		wg_dbg("Creating net namespace: %px\n",
				device->creating_net);
	else
		wg_dbg("Creating net namespace: NULL\n");

	wg_dbg("Static Identity: (printing details not implemented)\n");
	wg_dbg("Workqueues and other components would similarly have their details printed based on available data.\n");

	wg_dbg("FW Mark: %u, Incoming Port: %u, Transport: %u\n", device->fwmark, device->incoming_port, device->transport);
	wg_dbg("Handshake queue length: %d\n", atomic_read(&device->handshake_queue_len));
	wg_dbg("Number of Peers: %u, Device Update Generation: %u\n", device->num_peers, device->device_update_gen);
}

void print_tcp_socket_info(struct socket *sock, const char *label) {
	struct sock *sk;
	struct wg_socket_data *user_data;
	int tcp_state = -1;

	if (sock && sock->sk) {
		sk = sock->sk;
		user_data = (struct wg_socket_data *)sk->sk_user_data;
		tcp_state = (sk->sk_protocol == IPPROTO_TCP) ? sk->sk_state : -1;
		if (user_data) {
		wg_dbg("%s: socket=%px, sk_user_data=%px (device=%px, peer=%px, inbound=%d), TCP state=%d\n",
		       label, sock, user_data, user_data->device, user_data->peer, user_data->inbound, tcp_state);
		} else {
			wg_dbg("%s: socket=%px, sk_user_data=NULL, TCP state=%d\n",
			label, sock, tcp_state);
		}
	} else {
		wg_dbg("%s: Socket or sk is NULL\n", label);
	}
}

/* Function to print compact diagnostic information for all sockets in a peer */
void print_peer_socket_info(struct wg_peer *peer) {
        if (!peer) {
                wg_dbg("print_peer_socket_info: peer is NULL\n");
                return;
        }

        /* Print the pointers to the main sockets in the peer */
	wg_dbg("Peer: %px, peer_socket=%px, inbound_socket=%px, outbound_socket=%px\n",
	       peer, peer->peer_socket, peer->inbound_socket, peer->outbound_socket);

	/* Print inbound timestamp */
	wg_dbg("Inbound timestamp: %llu ns\n", ktime_to_ns(peer->inbound_timestamp));

	/* Print outbound timestamp */
	wg_dbg("Outbound timestamp: %llu ns\n", ktime_to_ns(peer->outbound_timestamp));

	/* Print combined information for inbound socket */
	if (peer->inbound_socket) {
		print_tcp_socket_info(peer->inbound_socket, "Inbound Socket");
	} else {
		wg_dbg("Inbound Socket is NULL\n");
	}

	/* Print combined information for outbound socket */
	if (peer->outbound_socket) {
		print_tcp_socket_info(peer->outbound_socket, "Outbound Socket");
	} else {
		wg_dbg("Outbound Socket is NULL\n");
	}

	/* Additional validation check */
	if (peer->peer_socket == peer->inbound_socket) {
		wg_dbg("peer_socket matches inbound_socket\n");
	} else if (peer->peer_socket == peer->outbound_socket) {
		wg_dbg("peer_socket matches outbound_socket\n");
	} else {
		printk(KERN_WARNING "peer_socket does not match inbound_socket or outbound_socket\n");
	}
}

/* ============================================================================
 * WireGuard-over-TCP Diagnostic Framework
 *
 * Comprehensive printk diagnostics for troubleshooting TCP-mode inefficiencies:
 * - Excessive loss/retransmits
 * - Window/cwnd issues
 * - Short writes
 * - Receive-side head-of-line stalls
 *
 * View logs with: dmesg | grep "wg-tcp-diag\|tcpdiag"
 * NOTE: Rate limiting disabled for complete diagnostics
 * ============================================================================
 */

/* Aggregate statistics counters */
static atomic64_t wg_tcp_stats_tx_bytes = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_rx_bytes = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_tx_packets = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_rx_packets = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_tx_eagain = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_tx_errors = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_rx_errors = ATOMIC64_INIT(0);
static atomic64_t wg_tcp_stats_short_writes = ATOMIC64_INIT(0);
/* Note: retransmits counter shows tp->total_retrans from dump_sock, not incremented here */
static atomic64_t wg_tcp_stats_retransmits = ATOMIC64_INIT(0);

/* Portable congestion window accessor */
static inline u32 wg_tcp_get_cwnd(const struct tcp_sock *tp)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
	return tcp_snd_cwnd(tp);
#else
	return tp->snd_cwnd;
#endif
}

/* TCP state name lookup */
static const char *wg_tcp_diag_state_name(u8 state)
{
	switch (state) {
	case TCP_ESTABLISHED: return "ESTABLISHED";
	case TCP_SYN_SENT:    return "SYN_SENT";
	case TCP_SYN_RECV:    return "SYN_RECV";
	case TCP_FIN_WAIT1:   return "FIN_WAIT1";
	case TCP_FIN_WAIT2:   return "FIN_WAIT2";
	case TCP_TIME_WAIT:   return "TIME_WAIT";
	case TCP_CLOSE:       return "CLOSE";
	case TCP_CLOSE_WAIT:  return "CLOSE_WAIT";
	case TCP_LAST_ACK:    return "LAST_ACK";
	case TCP_LISTEN:      return "LISTEN";
	case TCP_CLOSING:     return "CLOSING";
	case TCP_NEW_SYN_RECV:return "NEW_SYN_RECV";
	default:              return "UNKNOWN";
	}
}

/* Format endpoint addresses for logging */
static void wg_tcp_diag_format_endpoints(struct sock *sk,
					 char *lbuf, size_t lbuf_len,
					 char *rbuf, size_t rbuf_len)
{
	struct inet_sock *inet;

	if (!sk) {
		snprintf(lbuf, lbuf_len, "sk=null");
		snprintf(rbuf, rbuf_len, "sk=null");
		return;
	}

	inet = inet_sk(sk);

	if (sk->sk_family == AF_INET) {
		snprintf(lbuf, lbuf_len, "%pI4:%u",
			 &inet->inet_rcv_saddr, ntohs(inet->inet_sport));
		snprintf(rbuf, rbuf_len, "%pI4:%u",
			 &inet->inet_daddr, ntohs(inet->inet_dport));
		return;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (sk->sk_family == AF_INET6) {
		snprintf(lbuf, lbuf_len, "[%pI6c]:%u",
			 &sk->sk_v6_rcv_saddr, ntohs(inet->inet_sport));
		snprintf(rbuf, rbuf_len, "[%pI6c]:%u",
			 &sk->sk_v6_daddr, ntohs(inet->inet_dport));
		return;
	}
#endif
	snprintf(lbuf, lbuf_len, "fam=%u", sk->sk_family);
	snprintf(rbuf, rbuf_len, "fam=%u", sk->sk_family);
}

/* Peek at WireGuard message type from skb */
static u32 wg_tcp_diag_peek_msg_type(const struct sk_buff *skb)
{
	const struct message_header *h;

	if (!skb || skb->len < sizeof(*h))
		return 0;

	h = (const struct message_header *)skb->data;
	return le32_to_cpu(h->type);
}

/* Comprehensive socket dump - includes all TCP metrics */
void wg_tcp_diag_dump_sock(struct sock *sk, const char *where,
				  ssize_t io_bytes, size_t io_wanted)
{
	struct wg_socket_data *sd;
	struct wg_peer *peer = NULL;
	struct wg_device *wg = NULL;
	bool inbound = false;
	const char *devname = "wireguard";
	u64 peer_id = 0;
	char laddr[80], raddr[80];
	struct tcp_sock *tp;
	struct inet_connection_sock *icsk;
	u32 srtt_us, rto_ms, cwnd;
	u32 wmem, rmem;
	u32 writeq_len, recvq_len;

	if (!sk || IS_ERR(sk))
		return;
	if (sk->sk_protocol != IPPROTO_TCP)
		return;

	sd = READ_ONCE(sk->sk_user_data);
	if (sd && !IS_ERR(sd)) {
		peer = sd->peer;
		wg = sd->device;
		inbound = sd->inbound;
		if (wg && wg->dev)
			devname = wg->dev->name;
		if (peer && !IS_ERR(peer))
			peer_id = peer->internal_id;
	}

	wg_tcp_diag_format_endpoints(sk, laddr, sizeof(laddr), raddr, sizeof(raddr));

	tp = tcp_sk(sk);
	icsk = inet_csk(sk);
	cwnd = wg_tcp_get_cwnd(tp);

	/* tp->srtt_us is scaled by 8 (<< 3) */
	srtt_us = tp->srtt_us >> 3;
	rto_ms = jiffies_to_msecs(icsk->icsk_rto);

	wmem = sk_wmem_alloc_get(sk);
	rmem = sk_rmem_alloc_get(sk);
	writeq_len = skb_queue_len(&sk->sk_write_queue);
	recvq_len  = skb_queue_len(&sk->sk_receive_queue);

	wg_diag(
		"%s: tcpdiag[%s] peer=%llu inbound=%d sk=%px state=%s(%u) err=%d shut=%u io=%zd/%zu "
		"lcl=%s rmt=%s "
		"snd_wnd=%u rcv_wnd=%u cwnd=%u ssthresh=%u "
		"snd_una=%u snd_nxt=%u rcv_nxt=%u inflight=%u "
		"sndbuf=%u rcvbuf=%u wmem=%u rmem=%u wmemq=%u "
		"writeq=%u recvq=%u "
		"mss=%u advmss=%u wscale(snd=%u rcv=%u) nonagle=%u "
		"rto=%ums srtt=%uus rttvar=%uus "
		"pkts_out=%u retrans_out=%u lost_out=%u sacked_out=%u total_retrans=%u "
		"segs_in=%u segs_out=%u bytes_sent=%llu bytes_acked=%llu bytes_received=%llu cc=%s ca_state=%u\n",
		devname, where ? where : "?",
		peer_id, inbound, sk,
		wg_tcp_diag_state_name(sk->sk_state), sk->sk_state,
		sk->sk_err, sk->sk_shutdown,
		io_bytes, io_wanted,
		laddr, raddr,
		tp->snd_wnd, tp->rcv_wnd, cwnd, tp->snd_ssthresh,
		tp->snd_una, tp->snd_nxt, tp->rcv_nxt, tp->snd_nxt - tp->snd_una,
		sk->sk_sndbuf, sk->sk_rcvbuf,
		wmem, rmem, sk->sk_wmem_queued,
		writeq_len, recvq_len,
		tp->mss_cache, tp->advmss,
		tp->rx_opt.snd_wscale, tp->rx_opt.rcv_wscale, tp->nonagle,
		rto_ms, srtt_us, tp->rttvar_us,
		tp->packets_out, tp->retrans_out, tp->lost_out, tp->sacked_out,
		tp->total_retrans,
		tp->segs_in, tp->segs_out,
		(unsigned long long)tp->bytes_sent,
		(unsigned long long)tp->bytes_acked,
		(unsigned long long)tp->bytes_received,
		icsk->icsk_ca_ops ? icsk->icsk_ca_ops->name : "?",
		icsk->icsk_ca_state);
}

/* Check and log TCP pressure indicators */
static void wg_tcp_diag_pressure(struct sock *sk, u64 peer_id)
{
	struct tcp_sock *tp;
	struct inet_connection_sock *icsk;
	u32 cwnd;
	bool pressure = false;
	char reasons[128] = "";
	int pos = 0;

	if (!sk)
		return;

	tp = tcp_sk(sk);
	icsk = inet_csk(sk);
	cwnd = wg_tcp_get_cwnd(tp);

	if (tp->snd_wnd < tp->mss_cache * 2) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "small_wnd ");
	}
	if (cwnd < 4) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "cwnd_low ");
	}
	if (tp->retrans_out > 0) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "retrans ");
	}
	if (tp->lost_out > 0) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "lost ");
	}
	if (sk->sk_wmem_queued > (sk->sk_sndbuf * 4 / 5)) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "wmem_full ");
	}
	if (tp->snd_wnd == 0) {
		pressure = true;
		pos += snprintf(reasons + pos, sizeof(reasons) - pos, "ZERO_WND ");
	}

	if (pressure) {
		printk(KERN_WARNING
			"wg-tcp-diag [PRESSURE] peer=%llu: %s| "
			"snd_wnd=%u cwnd=%u ssthresh=%u mss=%u | "
			"retrans=%u lost=%u rto=%ums | "
			"wmem=%d/%d\n",
			peer_id, reasons,
			tp->snd_wnd, cwnd, tp->snd_ssthresh, tp->mss_cache,
			tp->retrans_out, tp->lost_out, jiffies_to_msecs(icsk->icsk_rto),
			sk->sk_wmem_queued, sk->sk_sndbuf);
	}
}

/* Log aggregate statistics */
static void wg_tcp_diag_aggregate(void)
{
	wg_diag("wg-tcp-diag [STATS]: "
		"tx=%lld bytes/%lld pkts rx=%lld bytes/%lld pkts | "
		"eagain=%lld short=%lld tx_err=%lld rx_err=%lld retrans=%lld\n",
			atomic64_read(&wg_tcp_stats_tx_bytes),
			atomic64_read(&wg_tcp_stats_tx_packets),
			atomic64_read(&wg_tcp_stats_rx_bytes),
			atomic64_read(&wg_tcp_stats_rx_packets),
			atomic64_read(&wg_tcp_stats_tx_eagain),
			atomic64_read(&wg_tcp_stats_short_writes),
			atomic64_read(&wg_tcp_stats_tx_errors),
			atomic64_read(&wg_tcp_stats_rx_errors),
			atomic64_read(&wg_tcp_stats_retransmits));
}

/* ============================================================================
 * End of TCP Diagnostic Framework
 * ============================================================================
 */

// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "cookie.h"
#include "peer.h"
#include "device.h"
#include "messages.h"
#include "ratelimiter.h"
#include "timers.h"

#include <crypto/blake2s.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/utils.h>

#include <net/ipv6.h>
#include "wg_tcp_debug.h"

void wg_cookie_checker_init(struct cookie_checker *checker,
			    struct wg_device *wg)
{
	wg_dbg("Entering: wg_cookie_checker_init with checker=%p, wg=%p\n", checker, wg);
	init_rwsem(&checker->secret_lock);
	checker->secret_birthdate = ktime_get_coarse_boottime_ns();
	get_random_bytes(checker->secret, NOISE_HASH_LEN);
	checker->device = wg;
	wg_dbg("Exiting: wg_cookie_checker_init\n");
}

enum { COOKIE_KEY_LABEL_LEN = 8 };
static const u8 mac1_key_label[COOKIE_KEY_LABEL_LEN] = "mac1----";
static const u8 cookie_key_label[COOKIE_KEY_LABEL_LEN] = "cookie--";

static void precompute_key(u8 key[NOISE_SYMMETRIC_KEY_LEN],
			   const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 label[COOKIE_KEY_LABEL_LEN])
{
	wg_dbg("Entering: precompute_key with key=%p, pubkey=%p, label=%p\n", key, pubkey, label);
	struct blake2s_state blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&blake, label, COOKIE_KEY_LABEL_LEN);
	blake2s_update(&blake, pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, key);
	wg_dbg("Exiting: precompute_key\n");
}

/* Must hold peer->handshake.static_identity->lock */
void wg_cookie_checker_precompute_device_keys(struct cookie_checker *checker)
{
	wg_dbg("Entering: wg_cookie_checker_precompute_device_keys with checker=%p\n", checker);
	if (likely(checker->device->static_identity.has_identity)) {
		precompute_key(checker->cookie_encryption_key,
			       checker->device->static_identity.static_public,
			       cookie_key_label);
		precompute_key(checker->message_mac1_key,
			       checker->device->static_identity.static_public,
			       mac1_key_label);
	} else {
		memset(checker->cookie_encryption_key, 0,
		       NOISE_SYMMETRIC_KEY_LEN);
		memset(checker->message_mac1_key, 0, NOISE_SYMMETRIC_KEY_LEN);
	}
	wg_dbg("Exiting: wg_cookie_checker_precompute_device_keys\n");
}

void wg_cookie_checker_precompute_peer_keys(struct wg_peer *peer)
{
	wg_dbg("Entering: wg_cookie_checker_precompute_peer_keys with peer=%p\n", peer);
	precompute_key(peer->latest_cookie.cookie_decryption_key,
		       peer->handshake.remote_static, cookie_key_label);
	precompute_key(peer->latest_cookie.message_mac1_key,
		       peer->handshake.remote_static, mac1_key_label);
	wg_dbg("Exiting: wg_cookie_checker_precompute_peer_keys\n");
}

void wg_cookie_init(struct cookie *cookie)
{
	wg_dbg("Entering: wg_cookie_init with cookie=%p\n", cookie);
	memset(cookie, 0, sizeof(*cookie));
	init_rwsem(&cookie->lock);
	wg_dbg("Exiting: wg_cookie_init\n");
}

#ifdef ORIGINAL
static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len,
			 const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
	wg_dbg("Entering: compute_mac1 with mac1=%p, message=%p, len=%zu, key=%p\n", mac1, message, len, key);
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac1);
	blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);
	wg_dbg("Exiting: compute_mac1\n");
}
#endif

static void compute_mac1(u8 mac1[COOKIE_LEN], const void *message, size_t len,
                         const u8 key[NOISE_SYMMETRIC_KEY_LEN])
{
    wg_dbg("Entering: compute_mac1 with mac1=%p, message=%p, len=%zu, key=%p\n", mac1, message, len, key);

    // Adjust the length as per the original logic
    len = len - sizeof(struct message_macs) +
          offsetof(struct message_macs, mac1);

    // Perform the MAC computation
    blake2s(mac1, message, key, COOKIE_LEN, len, NOISE_SYMMETRIC_KEY_LEN);

    // Print out diagnostics
    wg_dbg("WG: Key used for MAC1 computation: %*phN\n",
           NOISE_SYMMETRIC_KEY_LEN, key);
    wg_dbg("WG: Message used for MAC1 computation (first 32 bytes): %*phN\n",
           (int)min(len, 32UL), message);
    wg_dbg("WG: Computed MAC1: %*phN\n",
           COOKIE_LEN, mac1);

    wg_dbg("Exiting: compute_mac1\n");
}

static void compute_mac2(u8 mac2[COOKIE_LEN], const void *message, size_t len,
			 const u8 cookie[COOKIE_LEN])
{
	wg_dbg("Entering: compute_mac2 with mac2=%p, message=%p, len=%zu, cookie=%p\n", mac2, message, len, cookie);
	len = len - sizeof(struct message_macs) +
	      offsetof(struct message_macs, mac2);
	blake2s(mac2, message, cookie, COOKIE_LEN, len, COOKIE_LEN);
	wg_dbg("Exiting: compute_mac2\n");
}

static void make_cookie(u8 cookie[COOKIE_LEN], struct sk_buff *skb,
			struct cookie_checker *checker)
{
	wg_dbg("Entering: make_cookie with cookie=%p, skb=%p, checker=%p\n", cookie, skb, checker);
	struct blake2s_state state;

	if (wg_birthdate_has_expired(checker->secret_birthdate,
				     COOKIE_SECRET_MAX_AGE)) {
		down_write(&checker->secret_lock);
		checker->secret_birthdate = ktime_get_coarse_boottime_ns();
		get_random_bytes(checker->secret, NOISE_HASH_LEN);
		up_write(&checker->secret_lock);
	}

	down_read(&checker->secret_lock);

	blake2s_init_key(&state, COOKIE_LEN, checker->secret, NOISE_HASH_LEN);
	if (skb->protocol == htons(ETH_P_IP))
		blake2s_update(&state, (u8 *)&ip_hdr(skb)->saddr,
			       sizeof(struct in_addr));
	else if (skb->protocol == htons(ETH_P_IPV6))
		blake2s_update(&state, (u8 *)&ipv6_hdr(skb)->saddr,
			       sizeof(struct in6_addr));
	blake2s_update(&state, (u8 *)&udp_hdr(skb)->source, sizeof(__be16));
	blake2s_final(&state, cookie);

	up_read(&checker->secret_lock);
	wg_dbg("Exiting: make_cookie\n");
}

enum cookie_mac_state wg_cookie_validate_packet(struct cookie_checker *checker,
						struct sk_buff *skb,
						bool check_cookie)
{
	wg_dbg("Entering: wg_cookie_validate_packet with checker=%p, skb=%p, check_cookie=%d\n", checker, skb, check_cookie);

	struct message_macs *macs = (struct message_macs *)(skb->data + skb->len - sizeof(*macs));
	enum cookie_mac_state ret;
	u8 computed_mac[COOKIE_LEN];
	u8 cookie[COOKIE_LEN];

	wg_dbg("Initial packet length: %u, MACs location: %p\n", skb->len, macs);
	wg_dbg("MAC1 from packet: %*phN\n", COOKIE_LEN, macs->mac1);
	wg_dbg("MAC2 from packet: %*phN\n", COOKIE_LEN, macs->mac2);

	ret = INVALID_MAC;

	// Compute MAC1 and compare
	compute_mac1(computed_mac, skb->data, skb->len, checker->message_mac1_key);
	wg_dbg("Computed MAC1: %*phN\n", COOKIE_LEN, computed_mac);

	if (crypto_memneq(computed_mac, macs->mac1, COOKIE_LEN)) {
		printk(KERN_ERR "MAC1 validation failed.\n");
		goto out;
	}

	ret = VALID_MAC_BUT_NO_COOKIE;
	wg_dbg("MAC1 validated successfully.\n");

	if (!check_cookie)
		goto out;

	// Generate cookie and compute MAC2
	make_cookie(cookie, skb, checker);
	wg_dbg("Generated cookie: %*phN\n", COOKIE_LEN, cookie);

	compute_mac2(computed_mac, skb->data, skb->len, cookie);
	wg_dbg("Computed MAC2: %*phN\n", COOKIE_LEN, computed_mac);

	if (crypto_memneq(computed_mac, macs->mac2, COOKIE_LEN)) {
		printk(KERN_ERR "MAC2 validation failed.\n");
		goto out;
	}

	ret = VALID_MAC_WITH_COOKIE_BUT_RATELIMITED;
	wg_dbg("MAC2 validated successfully.\n");

	// Rate limiting check
	if (!wg_ratelimiter_allow(skb, dev_net(checker->device->dev))) {
		wg_dbg("Packet rate-limited.\n");
		goto out;
	}

	ret = VALID_MAC_WITH_COOKIE;
	wg_dbg("Packet passed all validations.\n");

out:
	wg_dbg("Exiting: wg_cookie_validate_packet with state=%d\n", ret);
	return ret;
}

void wg_cookie_add_mac_to_packet(void *message, size_t len,
				 struct wg_peer *peer)
{
	wg_dbg("Entering: wg_cookie_add_mac_to_packet with message=%p, len=%zu, peer=%p\n", message, len, peer);
	struct message_macs *macs = (struct message_macs *)
		((u8 *)message + len - sizeof(*macs));

	down_write(&peer->latest_cookie.lock);
	compute_mac1(macs->mac1, message, len,
		     peer->latest_cookie.message_mac1_key);
	memcpy(peer->latest_cookie.last_mac1_sent, macs->mac1, COOKIE_LEN);
	peer->latest_cookie.have_sent_mac1 = true;
	up_write(&peer->latest_cookie.lock);

	down_read(&peer->latest_cookie.lock);
	if (peer->latest_cookie.is_valid &&
	    !wg_birthdate_has_expired(peer->latest_cookie.birthdate,
				COOKIE_SECRET_MAX_AGE - COOKIE_SECRET_LATENCY))
		compute_mac2(macs->mac2, message, len,
			     peer->latest_cookie.cookie);
	else
		memset(macs->mac2, 0, COOKIE_LEN);
	up_read(&peer->latest_cookie.lock);
	wg_dbg("Exiting: wg_cookie_add_mac_to_packet\n");
}

void wg_cookie_message_create(struct message_handshake_cookie *dst,
			      struct sk_buff *skb, __le32 index,
			      struct cookie_checker *checker)
{
	wg_dbg("Entering: wg_cookie_message_create with dst=%p, skb=%p, index=%u, checker=%p\n", dst, skb, index, checker);
	struct message_macs *macs = (struct message_macs *)
		((u8 *)skb->data + skb->len - sizeof(*macs));
	u8 cookie[COOKIE_LEN];

	dst->header.type = cpu_to_le32(MESSAGE_HANDSHAKE_COOKIE);
	dst->receiver_index = index;
	get_random_bytes_wait(dst->nonce, COOKIE_NONCE_LEN);

	make_cookie(cookie, skb, checker);
	xchacha20poly1305_encrypt(dst->encrypted_cookie, cookie, COOKIE_LEN,
				  macs->mac1, COOKIE_LEN, dst->nonce,
				  checker->cookie_encryption_key);
	wg_dbg("Exiting: wg_cookie_message_create\n");
}

void wg_cookie_message_consume(struct message_handshake_cookie *src,
			       struct wg_device *wg)
{
	wg_dbg("Entering: wg_cookie_message_consume with src=%p, wg=%p\n", src, wg);
	struct wg_peer *peer = NULL;
	u8 cookie[COOKIE_LEN];
	bool ret;

	if (unlikely(!wg_index_hashtable_lookup(wg->index_hashtable,
						INDEX_HASHTABLE_HANDSHAKE |
						INDEX_HASHTABLE_KEYPAIR,
						src->receiver_index, &peer)))
		return;

	down_read(&peer->latest_cookie.lock);
	if (unlikely(!peer->latest_cookie.have_sent_mac1)) {
		up_read(&peer->latest_cookie.lock);
		goto out;
	}
	ret = xchacha20poly1305_decrypt(
		cookie, src->encrypted_cookie, sizeof(src->encrypted_cookie),
		peer->latest_cookie.last_mac1_sent, COOKIE_LEN, src->nonce,
		peer->latest_cookie.cookie_decryption_key);
	up_read(&peer->latest_cookie.lock);

	if (ret) {
		down_write(&peer->latest_cookie.lock);
		memcpy(peer->latest_cookie.cookie, cookie, COOKIE_LEN);
		peer->latest_cookie.birthdate = ktime_get_coarse_boottime_ns();
		peer->latest_cookie.is_valid = true;
		peer->latest_cookie.have_sent_mac1 = false;
		up_write(&peer->latest_cookie.lock);
	} else {
		net_dbg_ratelimited("%s: Could not decrypt invalid cookie response\n",
				    wg->dev->name);
	}

out:
	wg_peer_put(peer);
	wg_dbg("Exiting: wg_cookie_message_consume\n");
}

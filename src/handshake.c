/*
    This file is part of ImpXproto Library.

    ImpXproto Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    ImpXproto Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with ImpXproto Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2026 Impergram & ImpergramX & GuA development team
              2026 oxxximif || oxxx1Dev || oxxx1mif || tg: t.me/oxxximif || Obitocjkiy Gleb
*/

#include "../include/imp_xproto.h"
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int imp_xproto_handshake_client(int sock, const uint8_t *master_key, uint8_t *session_key) {
    printf("[CLIENT] Starting handshake...\n");

    if (imp_xproto_fake_tls_clienthello(sock, IMPX_FAKE_SNI) != 0) {
        fprintf(stderr, "[CLIENT] Fake TLS failed\n");
        return -1;
    }
    printf("[CLIENT] Fake TLS passed\n");

    uint8_t nonce[IMPX_NONCE_LEN];
    if (RAND_bytes(nonce, IMPX_NONCE_LEN) != 1) {
        fprintf(stderr, "[CLIENT] RAND_bytes nonce failed\n");
        return -1;
    }
    printf("[CLIENT] Nonce generated\n");

    uint8_t uuid[IMPX_UUID_LEN];
    memcpy(uuid, master_key, IMPX_UUID_LEN);

    uint8_t hmac[32];
    printf("[CLIENT] Starting HMAC computation...\n");
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "[CLIENT] EVP_MAC_fetch failed\n");
        return -1;
    }
    printf("[CLIENT] EVP_MAC_fetch OK\n");

    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx) {
        EVP_MAC_free(mac);
        fprintf(stderr, "[CLIENT] EVP_MAC_CTX_new failed\n");
        return -1;
    }
    printf("[CLIENT] EVP_MAC_CTX_new OK\n");

    OSSL_PARAM params[3] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA3-256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(mac_ctx, master_key, STRONG_KEY_BYTES, params) != 1) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        fprintf(stderr, "[CLIENT] EVP_MAC_init failed\n");
        return -1;
    }
    printf("[CLIENT] EVP_MAC_init OK\n");

    if (EVP_MAC_update(mac_ctx, uuid, IMPX_UUID_LEN) != 1) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        fprintf(stderr, "[CLIENT] EVP_MAC_update failed\n");
        return -1;
    }
    printf("[CLIENT] EVP_MAC_update OK\n");

    size_t hmac_len = sizeof(hmac);
    if (EVP_MAC_final(mac_ctx, hmac, &hmac_len, sizeof(hmac)) != 1) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        fprintf(stderr, "[CLIENT] EVP_MAC_final failed\n");
        return -1;
    }
    printf("[CLIENT] HMAC computed (%zu bytes)\n", hmac_len);

    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);

    uint8_t send_buf[IMPX_NONCE_LEN + 32 + IMPX_MIN_PADDING];
    memcpy(send_buf, nonce, IMPX_NONCE_LEN);
    memcpy(send_buf + IMPX_NONCE_LEN, hmac, 32);
    RAND_bytes(send_buf + IMPX_NONCE_LEN + 32, IMPX_MIN_PADDING);

    printf("[CLIENT] Sending nonce + HMAC + padding (%zu bytes)...\n", sizeof(send_buf));
    if (send(sock, send_buf, sizeof(send_buf), 0) < 0) {
        perror("[CLIENT] send nonce+hmac failed");
        return -1;
    }
    printf("[CLIENT] nonce + HMAC sent\n");

    printf("[CLIENT] Waiting for server ephemeral pubkey...\n");
    uint8_t server_pub[IMPX_EPHEM_KEY_LEN + IMPX_MIN_PADDING];
    ssize_t r = recv(sock, server_pub, sizeof(server_pub), 0);
    if (r <= 0) {
        if (r == 0) fprintf(stderr, "[CLIENT] Server closed connection\n");
        else perror("[CLIENT] recv server_pub failed");
        return -1;
    }
    printf("[CLIENT] Received %zd bytes from server\n", r);

    uint8_t client_priv[IMPX_EPHEM_KEY_LEN];
    uint8_t client_pub[IMPX_EPHEM_KEY_LEN];
    if (RAND_bytes(client_priv, IMPX_EPHEM_KEY_LEN) != 1) {
        fprintf(stderr, "[CLIENT] RAND_bytes client priv failed\n");
        return -1;
    }

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, client_priv, IMPX_EPHEM_KEY_LEN);
    if (!pkey) {
        fprintf(stderr, "[CLIENT] EVP_PKEY_new_raw_private_key failed\n");
        return -1;
    }

    size_t pub_len = IMPX_EPHEM_KEY_LEN;
    if (EVP_PKEY_get_raw_public_key(pkey, client_pub, &pub_len) != 1) {
        EVP_PKEY_free(pkey);
        fprintf(stderr, "[CLIENT] EVP_PKEY_get_raw_public_key failed\n");
        return -1;
    }

    uint8_t send_buf2[IMPX_EPHEM_KEY_LEN + IMPX_MIN_PADDING];
    memcpy(send_buf2, client_pub, IMPX_EPHEM_KEY_LEN);
    RAND_bytes(send_buf2 + IMPX_EPHEM_KEY_LEN, IMPX_MIN_PADDING);

    printf("[CLIENT] Sending own ephemeral pubkey + padding...\n");
    if (send(sock, send_buf2, sizeof(send_buf2), 0) < 0) {
        perror("[CLIENT] send client_pub failed");
        EVP_PKEY_free(pkey);
        return -1;
    }
    printf("[CLIENT] client pub sent\n");

    uint8_t shared[IMPX_EPHEM_KEY_LEN];
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, server_pub, IMPX_EPHEM_KEY_LEN);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pkey);
    size_t shared_len = sizeof(shared);
    if (EVP_PKEY_derive(ctx, shared, &shared_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer_pkey);
        fprintf(stderr, "[CLIENT] EVP_PKEY_derive failed\n");
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx ||
        EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL) != 1 ||
        EVP_DigestUpdate(mdctx, shared, shared_len) != 1 ||
        EVP_DigestUpdate(mdctx, nonce, IMPX_NONCE_LEN) != 1 ||
        EVP_DigestFinal_ex(mdctx, session_key, NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        EVP_PKEY_free(peer_pkey);
        fprintf(stderr, "[CLIENT] Session key derivation failed\n");
        explicit_bzero(shared, sizeof(shared));
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_pkey);
    explicit_bzero(shared, sizeof(shared));

    printf("[CLIENT] Handshake completed successfully\n");
    return 0;
}

int imp_xproto_handshake_server(int sock, const uint8_t *master_key, uint8_t *session_key) {
    printf("[SERVER] New client connected\n");

    uint8_t buf[4096];
    ssize_t r = recv(sock, buf, sizeof(buf), 0);
    if (r <= 0) {
        if (r == 0) fprintf(stderr, "[SERVER] Client closed early\n");
        else perror("[SERVER] recv initial data failed");
        return -1;
    }
    printf("[SERVER] Received %zd bytes initial data (expecting ClientHello)\n", r);

    if (imp_xproto_fake_tls_serverhello(sock) != 0) {
        fprintf(stderr, "[SERVER] Fake ServerHello failed\n");
        return -1;
    }
    printf("[SERVER] Fake ServerHello sent\n");

    uint8_t nonce_buf[IMPX_NONCE_LEN + 32 + IMPX_MIN_PADDING];
    r = recv(sock, nonce_buf, sizeof(nonce_buf), 0);
    if (r <= 0) {
        if (r == 0) fprintf(stderr, "[SERVER] Client closed after TLS\n");
        else perror("[SERVER] recv nonce+hmac failed");
        return -1;
    }
    printf("[SERVER] Received %zd bytes for auth (nonce + HMAC + padding)\n", r);

    uint8_t nonce[IMPX_NONCE_LEN];
    uint8_t received_hmac[32];
    memcpy(nonce, nonce_buf, IMPX_NONCE_LEN);
    memcpy(received_hmac, nonce_buf + IMPX_NONCE_LEN, 32);

    uint8_t uuid[IMPX_UUID_LEN];
    memcpy(uuid, master_key, IMPX_UUID_LEN);

    uint8_t calc_hmac[32];
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL);
    if (!mac) {
        fprintf(stderr, "[SERVER] EVP_MAC_fetch failed\n");
        return -1;
    }

    EVP_MAC_CTX *mac_ctx = EVP_MAC_CTX_new(mac);
    if (!mac_ctx) {
        EVP_MAC_free(mac);
        fprintf(stderr, "[SERVER] EVP_MAC_CTX_new failed\n");
        return -1;
    }

    OSSL_PARAM params[3] = {
        OSSL_PARAM_construct_utf8_string("digest", "SHA3-256", 0),
        OSSL_PARAM_construct_end()
    };

    if (EVP_MAC_init(mac_ctx, master_key, STRONG_KEY_BYTES, params) != 1 ||
        EVP_MAC_update(mac_ctx, uuid, IMPX_UUID_LEN) != 1 ||
        EVP_MAC_final(mac_ctx, calc_hmac, NULL, sizeof(calc_hmac)) != 1) {
        EVP_MAC_CTX_free(mac_ctx);
        EVP_MAC_free(mac);
        fprintf(stderr, "[SERVER] HMAC computation failed\n");
        return -1;
    }

    EVP_MAC_CTX_free(mac_ctx);
    EVP_MAC_free(mac);

    printf("[SERVER] Calculated HMAC: ");
    for (int i = 0; i < 32; i++) printf("%02x", calc_hmac[i]);
    printf("\n");

    printf("[SERVER] Received HMAC: ");
    for (int i = 0; i < 32; i++) printf("%02x", received_hmac[i]);
    printf("\n");

    if (memcmp(calc_hmac, received_hmac, 32) != 0) {
        fprintf(stderr, "[SERVER] HMAC mismatch - auth failed\n");
        return -1;
    }
    printf("[SERVER] Client authenticated\n");

    uint8_t server_priv[IMPX_EPHEM_KEY_LEN];
    uint8_t server_pub[IMPX_EPHEM_KEY_LEN];
    RAND_bytes(server_priv, IMPX_EPHEM_KEY_LEN);

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, server_priv, IMPX_EPHEM_KEY_LEN);
    size_t pub_len = IMPX_EPHEM_KEY_LEN;
    EVP_PKEY_get_raw_public_key(pkey, server_pub, &pub_len);

    uint8_t send_buf[IMPX_EPHEM_KEY_LEN + IMPX_MIN_PADDING];
    memcpy(send_buf, server_pub, IMPX_EPHEM_KEY_LEN);
    RAND_bytes(send_buf + IMPX_EPHEM_KEY_LEN, IMPX_MIN_PADDING);

    printf("[SERVER] Sending ephemeral pubkey...\n");
    if (send(sock, send_buf, sizeof(send_buf), 0) < 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    uint8_t client_pub[IMPX_EPHEM_KEY_LEN];
    r = recv(sock, client_pub, IMPX_EPHEM_KEY_LEN, 0);
    if (r <= 0) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    uint8_t shared[IMPX_EPHEM_KEY_LEN];
    EVP_PKEY *peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, client_pub, IMPX_EPHEM_KEY_LEN);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pkey);
    size_t shared_len = sizeof(shared);
    EVP_PKEY_derive(ctx, shared, &shared_len);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL);
    EVP_DigestUpdate(mdctx, shared, shared_len);
    EVP_DigestUpdate(mdctx, nonce, IMPX_NONCE_LEN);
    EVP_DigestFinal_ex(mdctx, session_key, NULL);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peer_pkey);
    explicit_bzero(shared, sizeof(shared));

    printf("[SERVER] Handshake completed\n");
    return 0;
}

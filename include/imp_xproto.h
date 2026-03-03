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

#ifndef IMP_XPROTO_H
#define IMP_XPROTO_H

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stddef.h>
#include "../crypto/keygen.h"

#define IMPX_UUID_LEN 16
#define IMPX_NONCE_LEN 32
#define IMPX_EPHEM_KEY_LEN 32
#define IMPX_SESSION_KEY_LEN STRONG_KEY_BYTES
#define IMPX_FRAME_HEADER_LEN 31
#define IMPX_MAX_PADDING 512
#define IMPX_MIN_PADDING 32
#define IMPX_FAKE_SNI "ru.wikipedia.org"

typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint8_t  flags;
    uint32_t total_len;
    uint8_t  nonce[8];
    uint8_t  tag[16];
    uint8_t  data[];
} ImpXFrame;

typedef struct {
    char *domain;
    char *ip;
    char *protocol;
    char *outbound_tag;
} ImpXRule;

typedef struct {
    ImpXRule *rules;
    size_t num_rules;
} ImpXRouting;

int imp_xproto_fake_tls_clienthello(int sock, const char *sni);
int imp_xproto_fake_tls_serverhello(int sock);
int imp_xproto_handshake_client(int sock, const uint8_t *master_key, uint8_t *session_key);
int imp_xproto_handshake_server(int sock, const uint8_t *master_key, uint8_t *session_key);
int imp_xproto_ws_handshake_client(int sock);
int imp_xproto_ws_handshake_server(int sock);
int imp_xproto_encrypt(const uint8_t *session_key, const uint8_t *plaintext, size_t plen, uint8_t *ciphertext, size_t *clen, int use_ws);
int imp_xproto_decrypt(const uint8_t *session_key, const uint8_t *ciphertext, size_t clen, uint8_t *plaintext, size_t *plen, int use_ws);
int imp_xproto_tunnel_forward(int client_sock, int remote_sock, const uint8_t *session_key, ImpXRouting *routing);
int imp_xproto_apply_routing(const uint8_t *data, size_t len, ImpXRouting *routing, char **next_outbound);

extern ImpXRouting global_routing;

#define IMPX_ED25519_KEY_LEN 32

extern const uint8_t SERVER_PUBLIC_ED25519[IMPX_ED25519_KEY_LEN];
extern const uint8_t CLIENT_PRIVATE_ED25519[IMPX_ED25519_KEY_LEN];

#endif

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
#include <stdint.h>
#include <stddef.h>
#include "../crypto/keygen.h"

#define IMPX_UUID_LEN 16
#define IMPX_NONCE_LEN 32
#define IMPX_EPHEM_KEY_LEN  32
#define IMPX_SESSION_KEY_LEN STRONG_KEY_BYTES
#define IMPX_FRAME_HEADER_LEN 16
#define IMPX_MAX_PADDING 256
#define IMPX_MIN_PADDING 16

typedef struct {
    uint32_t payload_len;
    uint8_t tag[12];
    uint8_t data[];
} ImpXFrame;

int imp_xproto_handshake_client(int sock, const uint8_t *master_key, uint8_t *session_key);
int imp_xproto_handshake_server(int sock, const uint8_t *master_key, uint8_t *session_key);
int imp_xproto_encrypt(const uint8_t *session_key, const uint8_t *plaintext, size_t plen, uint8_t *ciphertext, size_t *clen);
int imp_xproto_decrypt(const uint8_t *session_key, const uint8_t *ciphertext, size_t clen, uint8_t *plaintext, size_t *plen);
int imp_xproto_tunnel_forward(int client_sock, int remote_sock, const uint8_t *session_key);

#endif

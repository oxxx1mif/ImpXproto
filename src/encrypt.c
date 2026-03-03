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
#include <stdlib.h>

int imp_xproto_encrypt(const uint8_t *session_key, const uint8_t *plaintext, size_t plen, uint8_t *ciphertext, size_t *clen, int use_ws) {
    uint8_t nonce[12];
    RAND_bytes(nonce, sizeof(nonce));

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *chacha = EVP_chacha20_poly1305();
    if (!ctx || !EVP_EncryptInit_ex(ctx, chacha, NULL, session_key, nonce)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    uint8_t *encrypted = malloc(plen + 16);
    if (!encrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int final_len = 0;
    if (!EVP_EncryptUpdate(ctx, encrypted, &len, plaintext, plen) ||
        !EVP_EncryptFinal_ex(ctx, encrypted + len, &final_len)) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    len += final_len;

    uint8_t tag[16];
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    size_t pad_len = IMPX_MIN_PADDING + (rand() % (IMPX_MAX_PADDING - IMPX_MIN_PADDING + 1));
    uint8_t *padded = malloc(plen + pad_len);
    if (!padded) {
        free(encrypted);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    size_t split = plen / 2 + (rand() % 65);
    memcpy(padded, encrypted, split);
    RAND_bytes(padded + split, pad_len);
    memcpy(padded + split + pad_len, encrypted + split, plen - split);

    free(encrypted);

    ImpXFrame frame;
    frame.version = 0x01;
    frame.type = 0x00;
    frame.flags = 0x01;
    frame.total_len = plen + pad_len + 16;
    memcpy(frame.nonce, nonce, 8);
    memcpy(frame.tag, tag, 16);

    memcpy(ciphertext, &frame, IMPX_FRAME_HEADER_LEN);
    memcpy(ciphertext + IMPX_FRAME_HEADER_LEN, padded, plen + pad_len);
    *clen = IMPX_FRAME_HEADER_LEN + plen + pad_len;

    free(padded);

    if (use_ws) {
        uint8_t ws_header[10] = {0x82};
        size_t ws_header_len = 2;
        if (*clen < 126) {
            ws_header[1] = *clen;
        } else {
            ws_header[1] = 126;
            ws_header[2] = (*clen >> 8) & 0xFF;
            ws_header[3] = *clen & 0xFF;
            ws_header_len = 4;
        }

        uint8_t mask[4];
        RAND_bytes(mask, 4);
        memcpy(ws_header + ws_header_len, mask, 4);
        ws_header_len += 4;

        for (size_t i = 0; i < *clen; i++) {
            ciphertext[i] ^= mask[i % 4];
        }

        memmove(ciphertext + ws_header_len, ciphertext, *clen);
        memcpy(ciphertext, ws_header, ws_header_len);
        *clen += ws_header_len;
    }

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int imp_xproto_decrypt(const uint8_t *session_key, const uint8_t *ciphertext, size_t clen, uint8_t *plaintext, size_t *plen, int use_ws) {
    size_t offset = 0;

    if (use_ws) {
        if (clen < 2 || (ciphertext[0] & 0x80) == 0) return -1;
        uint8_t opcode = ciphertext[0] & 0x0F;
        if (opcode != 0x02) return -1;

        uint8_t len_byte = ciphertext[1];
        uint8_t masked = len_byte & 0x80;
        size_t ws_len = len_byte & 0x7F;

        offset = 2;
        if (ws_len == 126) {
            if (clen < 4) return -1;
            ws_len = (ciphertext[2] << 8) | ciphertext[3];
            offset = 4;
        } else if (ws_len == 127) {
            return -1;
        }

        if (clen < offset + 4 + ws_len) return -1;

        uint8_t mask[4];
        memcpy(mask, ciphertext + offset, 4);
        offset += 4;

        for (size_t i = 0; i < ws_len; i++) {
            ((uint8_t*)ciphertext)[offset + i] ^= mask[i % 4];
        }

        clen = ws_len;
    }

    if (clen < IMPX_FRAME_HEADER_LEN) return -1;

    ImpXFrame frame;
    memcpy(&frame, ciphertext, IMPX_FRAME_HEADER_LEN);

    if (frame.version != 0x01 || frame.total_len + IMPX_FRAME_HEADER_LEN > clen) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *chacha = EVP_chacha20_poly1305();
    if (!ctx || !EVP_DecryptInit_ex(ctx, chacha, NULL, session_key, frame.nonce)) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    uint8_t *decrypted = malloc(frame.total_len);
    if (!decrypted) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int len = 0;
    int final_len = 0;
    if (!EVP_DecryptUpdate(ctx, decrypted, &len, ciphertext + IMPX_FRAME_HEADER_LEN, frame.total_len - 16) ||
        !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)frame.tag) ||
        !EVP_DecryptFinal_ex(ctx, decrypted + len, &final_len)) {
        free(decrypted);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    len += final_len;
    *plen = len;

    memcpy(plaintext, decrypted, len);
    free(decrypted);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

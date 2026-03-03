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

int imp_xproto_fake_tls_clienthello(int sock, const char *sni) {
    printf("[CLIENT] Generating fake TLS ClientHello for SNI: %s\n", sni);

    uint8_t buf[2048] = {0};
    size_t pos = 0;

    uint8_t record_header[] = {0x16, 0x03, 0x01, 0x02, 0x00};
    memcpy(buf + pos, record_header, sizeof(record_header));
    pos += sizeof(record_header);

    uint8_t handshake_header[] = {0x01, 0x00, 0x01, 0xfc};
    memcpy(buf + pos, handshake_header, sizeof(handshake_header));
    pos += sizeof(handshake_header);

    uint8_t legacy_version[] = {0x03, 0x03};
    memcpy(buf + pos, legacy_version, sizeof(legacy_version));
    pos += sizeof(legacy_version);

    uint8_t random[32];
    RAND_bytes(random, 32);
    memcpy(buf + pos, random, 32);
    pos += 32;

    buf[pos++] = 0x00;

    uint8_t cipher_suites[] = {
        0x00, 0x20,
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
        0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x33, 0x00, 0x2f, 0x00, 0x35
    };
    memcpy(buf + pos, cipher_suites, sizeof(cipher_suites));
    pos += sizeof(cipher_suites);

    buf[pos++] = 0x01;
    buf[pos++] = 0x00;

    size_t ext_len_pos = pos;
    pos += 2;

    uint8_t sni_ext_header[] = {0x00, 0x00, 0x00, 0x21, 0x00, 0x1f, 0x00, 0x00};
    memcpy(buf + pos, sni_ext_header, sizeof(sni_ext_header));
    pos += sizeof(sni_ext_header) - 1;

    size_t sni_len = strlen(sni);
    if (sni_len > 255) {
        fprintf(stderr, "[CLIENT] SNI too long: %zu > 255\n", sni_len);
        return -1;
    }

    buf[pos++] = (uint8_t)sni_len;
    memcpy(buf + pos, sni, sni_len);
    pos += sni_len;

    uint8_t supported_versions[] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04};
    memcpy(buf + pos, supported_versions, sizeof(supported_versions));
    pos += sizeof(supported_versions);

    uint8_t key_share_header[] = {0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    memcpy(buf + pos, key_share_header, sizeof(key_share_header));
    pos += sizeof(key_share_header);

    uint8_t fake_key[32];
    RAND_bytes(fake_key, 32);
    memcpy(buf + pos, fake_key, 32);
    pos += 32;

    uint16_t ext_total_len = pos - (ext_len_pos + 2);
    buf[ext_len_pos] = (ext_total_len >> 8) & 0xFF;
    buf[ext_len_pos + 1] = ext_total_len & 0xFF;

    uint32_t handshake_len = pos - 9;
    buf[6] = (handshake_len >> 16) & 0xFF;
    buf[7] = (handshake_len >> 8) & 0xFF;
    buf[8] = handshake_len & 0xFF;

    uint16_t record_len = pos - 5;
    buf[3] = (record_len >> 8) & 0xFF;
    buf[4] = record_len & 0xFF;

    uint8_t junk[64];
    RAND_bytes(junk, sizeof(junk));
    memcpy(buf + pos, junk, sizeof(junk));
    pos += sizeof(junk);

    printf("[CLIENT] Sending fake ClientHello (%zu bytes)\n", pos);
    ssize_t sent = send(sock, buf, pos, 0);
    if (sent < 0) {
        perror("[CLIENT] send ClientHello failed");
        return -1;
    }
    if ((size_t)sent != pos) {
        fprintf(stderr, "[CLIENT] Incomplete send: %zd of %zu bytes\n", sent, pos);
        return -1;
    }

    printf("[CLIENT] Fake ClientHello sent successfully\n");
    return 0;
}

int imp_xproto_fake_tls_serverhello(int sock) {
    printf("[SERVER] Generating fake TLS ServerHello...\n");

    uint8_t server_hello[160] = {
        0x16, 0x03, 0x03, 0x00, 0x7a,
        0x02, 0x00, 0x00, 0x76,
        0x03, 0x03,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x00,
        0x13, 0x01,
        0x00,
        0x00, 0x3e,
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t junk[64];
    RAND_bytes(junk, sizeof(junk));
    memcpy(server_hello + 95, junk, 32);

    printf("[SERVER] Sending fake ServerHello (%zu bytes)\n", sizeof(server_hello));
    ssize_t sent = send(sock, server_hello, sizeof(server_hello), 0);
    if (sent < 0) {
        perror("[SERVER] send ServerHello failed");
        return -1;
    }

    printf("[SERVER] Fake ServerHello sent\n");
    return 0;
}

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

int main(void) {
    uint8_t master_key[STRONG_KEY_BYTES];
    if (generate_strong_key(master_key) != 0) {
        fprintf(stderr, "Key generation failed\n");
        return 1;
    }
    printf("Master key generated\n");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }
    printf("Socket created\n");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        return 1;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect failed");
        close(sock);
        return 1;
    }
    printf("Connected to server\n");

    uint8_t session_key[IMPX_SESSION_KEY_LEN];
    if (imp_xproto_handshake_client(sock, master_key, session_key) != 0) {
        fprintf(stderr, "Handshake failed\n");
        close(sock);
        return 1;
    }
    printf("Handshake successful\n");

    const char *msg = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    size_t clen;
    uint8_t encrypted[2048];
    if (imp_xproto_encrypt(session_key, (const uint8_t*)msg, strlen(msg), encrypted, &clen, 1) != 0) {
        fprintf(stderr, "Encryption failed\n");
        close(sock);
        return 1;
    }
    printf("Message encrypted, sending %zu bytes\n", clen);

    if (send(sock, encrypted, clen, 0) < 0) {
        perror("send failed");
        close(sock);
        return 1;
    }
    printf("Message sent\n");

    uint8_t buf[8192];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n < 0) {
        perror("recv failed");
        close(sock);
        return 1;
    }
    if (n == 0) {
        fprintf(stderr, "Connection closed by server\n");
        close(sock);
        return 1;
    }
    printf("Received %zd bytes\n", n);

    uint8_t decrypted[8192];
    size_t dlen;
    if (imp_xproto_decrypt(session_key, buf, n, decrypted, &dlen, 1) != 0) {
        fprintf(stderr, "Decryption failed\n");
        close(sock);
        return 1;
    }

    printf("Decrypted response (%zu bytes):\n", dlen);
    write(1, decrypted, dlen);
    printf("\n");

    explicit_bzero(master_key, sizeof(master_key));
    explicit_bzero(session_key, sizeof(session_key));
    close(sock);
    return 0;
}

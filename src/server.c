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
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
    uint8_t master_key[STRONG_KEY_BYTES];
    if (generate_strong_key(master_key) != 0) return 1;

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) return 1;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
        listen(server_sock, 5) < 0) {
        close(server_sock);
        return 1;
    }

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) continue;

        uint8_t session_key[IMPX_SESSION_KEY_LEN];
        if (imp_xproto_handshake_server(client_sock, master_key, session_key) != 0) {
            close(client_sock);
            continue;
        }

        int remote_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (remote_sock < 0) { close(client_sock); continue; }

        struct sockaddr_in remote_addr;
        remote_addr.sin_family = AF_INET;
        remote_addr.sin_port = htons(80);
        inet_pton(AF_INET, "93.184.216.34", &remote_addr.sin_addr);

        if (connect(remote_sock, (struct sockaddr*)&remote_addr, sizeof(remote_addr)) < 0) {
            close(client_sock);
            close(remote_sock);
            continue;
        }

        imp_xproto_tunnel_forward(client_sock, remote_sock, session_key, &global_routing);

        close(client_sock);
        close(remote_sock);
    }

    explicit_bzero(master_key, sizeof(master_key));
    close(server_sock);
    return 0;
}

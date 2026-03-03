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
#include <unistd.h>
#include <sys/socket.h>

int imp_xproto_tunnel_forward(int client_sock, int remote_sock, const uint8_t *session_key, ImpXRouting *routing) {
    uint8_t buf[8192];
    ssize_t n;

    while (1) {
        n = recv(client_sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        size_t dlen;
        uint8_t decrypted[8192];
        if (imp_xproto_decrypt(session_key, buf, n, decrypted, &dlen, 1) != 0) return -1;

        char *next_outbound;
        imp_xproto_apply_routing(decrypted, dlen, routing, &next_outbound);

        if (strcmp(next_outbound, "direct") == 0) {
            send(remote_sock, decrypted, dlen, 0);
        }

        n = recv(remote_sock, buf, sizeof(buf), 0);
        if (n <= 0) break;

        size_t clen;
        uint8_t encrypted[8192 + IMPX_MAX_PADDING];
        if (imp_xproto_encrypt(session_key, buf, n, encrypted, &clen, 1) != 0) return -1;
        send(client_sock, encrypted, clen, 0);
    }

    return 0;
}

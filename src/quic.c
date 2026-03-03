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

int imp_xproto_quic_init_server(OSSL_QUIC_SSERVER **qserver) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) return -1;

    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        SSL_CTX_free(ctx);
        return -1;
    }

    *qserver = OSSL_QUIC_sServer_new(ctx, "0.0.0.0", 443);
    SSL_CTX_free(ctx);
    return *qserver ? 0 : -1;
}

int imp_xproto_quic_init_client(OSSL_QUIC_CLIENT **qclient, const char *host, uint16_t port) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!ctx) return -1;

    *qclient = OSSL_QUIC_client_new(ctx, host, port);
    SSL_CTX_free(ctx);
    return *qclient ? 0 : -1;
}

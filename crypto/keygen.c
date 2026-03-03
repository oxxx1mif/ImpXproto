/*
    This file is part of ImpXproto Library.

    ImpXproto Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
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

#include "keygen.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define MASTER_ENTROPY_BYTES    96
#define ARGON2_ITERATIONS       8
#define ARGON2_MEMORY_KIB       8192
#define ARGON2_PARALLELISM      4

int generate_strong_key(unsigned char *out_key)
{
    if (!out_key) {
        return -1;
    }

    unsigned char entropy[MASTER_ENTROPY_BYTES] = {0};
    unsigned char seed[128] = {0};
    unsigned char extra[32] = {0};

    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        goto cleanup;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        goto cleanup;
    }
    memcpy(extra, &ts, sizeof(ts));
    *(pid_t*)(extra + 16) = getpid();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        goto cleanup;
    }

    const EVP_MD *sha3_512 = EVP_sha3_512();

    if (!EVP_DigestInit_ex(mdctx, sha3_512, NULL) ||
        !EVP_DigestUpdate(mdctx, entropy, sizeof(entropy)) ||
        !EVP_DigestUpdate(mdctx, extra, sizeof(extra)) ||
        !EVP_DigestFinal_ex(mdctx, seed, NULL)) {
        EVP_MD_CTX_free(mdctx);
        goto cleanup;
    }

    for (int i = 0; i < 4; i++) {
        unsigned char tmp[128] = {0};
        memcpy(tmp, seed, 64);

        char domain[32];
        snprintf(domain, sizeof(domain), "anon-key-gen-v1.1-stage%d", i + 1);

        if (!EVP_DigestInit_ex(mdctx, sha3_512, NULL) ||
            !EVP_DigestUpdate(mdctx, tmp, 64) ||
            !EVP_DigestUpdate(mdctx, (unsigned char*)domain, strlen(domain)) ||
            !EVP_DigestUpdate(mdctx, entropy + (i * 17) % (sizeof(entropy) - 32), 32) ||
            !EVP_DigestFinal_ex(mdctx, seed + (i * 32) % 64, NULL)) {
            EVP_MD_CTX_free(mdctx);
            explicit_bzero(tmp, sizeof(tmp));
            goto cleanup;
        }
        explicit_bzero(tmp, sizeof(tmp));
    }

    if (EVP_PBE_scrypt((const char*)seed, 64,
                       (const char*)entropy, 32,
                       ARGON2_ITERATIONS,
                       ARGON2_MEMORY_KIB,
                       ARGON2_PARALLELISM,
                       0,
                       out_key, STRONG_KEY_BYTES) != 1) {
        EVP_MD_CTX_free(mdctx);
        goto cleanup;
    }

    EVP_MD_CTX_free(mdctx);

    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(entropy, sizeof(entropy));
    explicit_bzero(extra, sizeof(extra));
    return 0;

cleanup:
    explicit_bzero(seed, sizeof(seed));
    explicit_bzero(entropy, sizeof(entropy));
    explicit_bzero(extra, sizeof(extra));
    explicit_bzero(out_key, STRONG_KEY_BYTES);
    return -1;
}

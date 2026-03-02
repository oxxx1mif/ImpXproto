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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#define MASTER_ENTROPY_BYTES 96
#define FINAL_KEY_BYTES 64
#define ARGON2_ITERATIONS 6
#define ARGON2_MEMORY_KIB 4096
#define ARGON2_PARALLELISM 8

int main() {
    unsigned char entropy[MASTER_ENTROPY_BYTES];
    unsigned char seed[128];
    unsigned char final_key[FINAL_KEY_BYTES];

    if (RAND_bytes(entropy, sizeof(entropy)) != 1) {
        explicit_bzero(entropy, sizeof(entropy));
        exit(1);
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        explicit_bzero(entropy, sizeof(entropy));
        exit(1);
    }
    unsigned char extra[32];
    memcpy(extra, &ts, sizeof(ts));
    *(pid_t*)(extra + 16) = getpid();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        explicit_bzero(entropy, sizeof(entropy));
        explicit_bzero(extra, sizeof(extra));
        exit(1);
    }

    const EVP_MD *sha3_512 = EVP_sha3_512();
}

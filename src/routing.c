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

ImpXRouting global_routing = {
    .rules = (ImpXRule[]){
        {"geosite:cn", NULL, "http", "direct"},
        {NULL, "geoip:us", NULL, "proxy2"},
        {NULL, NULL, NULL, "block"}
    },
    .num_rules = 3
};

int imp_xproto_apply_routing(const uint8_t *data, size_t len, ImpXRouting *routing, char **next_outbound) {
    if (strstr((char*)data, "example.com")) {
        *next_outbound = "proxy1";
        return 0;
    }

    for (size_t i = 0; i < routing->num_rules; i++) {
        if (routing->rules[i].domain && strstr((char*)data, routing->rules[i].domain)) {
            *next_outbound = routing->rules[i].outbound_tag;
            return 0;
        }
    }

    *next_outbound = "direct";
    return 0;
}

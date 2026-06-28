/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef WRDPGW_CREDSSP_H
#define WRDPGW_CREDSSP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum WrdpgwErrorKind {
    WRDPGW_OK = 0,
    WRDPGW_ERR_INVALID_ARGUMENT = 1,
    WRDPGW_ERR_CREDSSP = 5,
    WRDPGW_ERR_KERBEROS_KDC_REQUIRED = 6,
    WRDPGW_ERR_AUTH_FAILED = 7,
    WRDPGW_ERR_INTERNAL = 255
} WrdpgwErrorKind;

#define WRDPGW_CREDSSP_STATE_REPLY_NEEDED 0
#define WRDPGW_CREDSSP_STATE_FINAL 1

typedef struct WrdpgwCredssp WrdpgwCredssp;

int32_t wrdpgw_credssp_new(const uint8_t *server_pubkey, size_t server_pubkey_len,
                           const uint8_t *domain, size_t domain_len,
                           const uint8_t *username, size_t username_len,
                           const uint8_t *password, size_t password_len,
                           const uint8_t *target, size_t target_len,
                           WrdpgwCredssp **out_client,
                           char **out_error);

int32_t wrdpgw_credssp_step(WrdpgwCredssp *client,
                            const uint8_t *incoming, size_t incoming_len,
                            uint8_t **out_outgoing, size_t *out_outgoing_len,
                            int32_t *out_state,
                            char **out_error);

void wrdpgw_credssp_free(WrdpgwCredssp *client);
void wrdpgw_free_bytes(uint8_t *ptr, size_t len);
void wrdpgw_free_string(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* WRDPGW_CREDSSP_H */
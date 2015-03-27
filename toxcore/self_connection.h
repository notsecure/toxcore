/* self_connection.h
 *
 * Connection to other devices who share the same public key.
 *
 *  Copyright (C) 2015 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef SELF_CONNECTION_H
#define SELF_CONNECTION_H

#include "net_crypto.h"

#define SELF_CONN_MAX 16

#define SELF_PING_INTERVAL 7
#define SELF_CONNECTION_TIMEOUT (SELF_PING_INTERVAL * 3)

enum {
    SELFCONN_STATUS_NONE,
    SELFCONN_STATUS_CONNECTING,
    SELFCONN_STATUS_CONNECTED
};

/* packet IDs */
#define PACKET_ID_SELF_ALIVE 32
#define PACKET_ID_SELF_FRIENDREQ 33
#define PACKET_ID_SELF_NEWFRIEND 34
#define PACKET_ID_SELF_DELFRIEND 35
#define PACKET_ID_SELF_FRIENDCONNECTIONSTATUS 36
#define PACKET_ID_SELF_FRIENDSTATUS 37
#define PACKET_ID_SELF_FRIENDNAME 38
#define PACKET_ID_SELF_FRIENDCHAT 39
/* .. */

typedef struct {
    uint8_t status;

    int crypt_connection_id;
    uint64_t ping_lastrecv, ping_lastsent;

    uint16_t lock_count;
} Self_Conn;

typedef struct {
    void (*friend_namechange)(void*, const uint8_t*, const uint8_t*, uint32_t);
    /* other callbacks .. */
} Self_Callbacks;

typedef struct {
    Net_Crypto *net_crypto;

    Self_Conn conns[SELF_CONN_MAX];
    uint32_t num_cons;

    Self_Callbacks cb;
    void *callback_object;
} Self_Connections;

/* sync information related to a friend */
void self_connections_sync_friend(Self_Connections *self_c, const uint8_t *pk, uint8_t packet_id,
                                  const uint8_t *data, uint32_t data_length);


/* Create new self_connections instance. */
Self_Connections* new_self_connections(Net_Crypto *net_crypto, Self_Callbacks *cb, void *callback_object);

/* main self_connections loop. */
void do_self_connections(Self_Connections *self_c);

/* Free everything related with self_c. */
void kill_self_connections(Self_Connections *self_c);

#endif

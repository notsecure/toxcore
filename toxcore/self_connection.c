/* self_connection.c
 *
 *  Connection to other devices who share the same public key.
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

/* onion client will automatically try to connect to peers sharing the same Tox ID
 * this module will handle these connections
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "self_connection.h"
#include "util.h"

static Self_Conn* new_conn(Self_Connections *self_c)
{
    int i;

    if (self_c->num_cons == SELF_CONN_MAX) {
        return NULL;
    }

    self_c->num_cons++;

    for (i = 0; ; i++) {
        if (!self_c->conns[i].status)
            return &self_c->conns[i];
    }
}

static int send_ping(Self_Connections *self_c, Self_Conn *conn)
{
    uint8_t ping = PACKET_ID_SELF_ALIVE;
    int64_t ret = write_cryptpacket(self_c->net_crypto, conn->crypt_connection_id,
                                    &ping, sizeof(ping), 0);

    if (ret != -1) {
        conn->ping_lastsent = unix_time();
        return 0;
    }

    return -1;
}

static int handle_status(void *object, int number, uint8_t status)
{
    Self_Connections *self_c = object;
    Self_Conn *conn = &self_c->conns[number];

    if (!conn->status)
        return -1;

    if (status) {  /* Went online. */
        conn->status = SELFCONN_STATUS_CONNECTED;
        conn->ping_lastrecv = unix_time();
    } else {  /* Went offline. */
        conn->status = 0;
    }

    return 0;
}

static int handle_packet(void *object, int number, uint8_t *data, uint16_t length)
{
    Self_Connections *self_c = object;
    Self_Conn *conn = &self_c->conns[number];

    if (length == 0)
        return -1;

    if (!conn->status)
        return -1;

    switch (data[0]) {
    case PACKET_ID_SELF_ALIVE:
        conn->ping_lastrecv = unix_time();
        break;
    case PACKET_ID_SELF_FRIENDREQ:
        break;
    case PACKET_ID_SELF_NEWFRIEND:
        break;
    case PACKET_ID_SELF_DELFRIEND:
        break;
    case PACKET_ID_SELF_FRIENDCONNECTIONSTATUS:
        break;
    case PACKET_ID_SELF_FRIENDSTATUS:
        break;
    case PACKET_ID_SELF_FRIENDNAME:
        if (length < 5)
            break;

        int friend_id;

        memcpy(&friend_id, &data[1], 4);
        if (self_c->cb.friend_namechange)
            self_c->cb.friend_namechange(self_c->callback_object, friend_id, data + 5, length - 5);
        break;
    case PACKET_ID_SELF_FRIENDCHAT:
        break;
    default:
        /* unknown */
        break;
    }

    return 0;
}

static int handle_lossy_packet(void *object, int number, const uint8_t *data, uint16_t length)
{
    Self_Connections *self_c = object;
    Self_Conn *conn = &self_c->conns[number];

    if (length == 0)
        return -1;

    if (!conn->status)
        return -1;

    /* unknown */

    return 0;
}

static int handle_new_connections(void *object, New_Connection *n_c)
{
    Self_Connections *self_c = object;

    /* catch connections who share our public key */
    if (memcmp(self_c->net_crypto->self_public_key, n_c->public_key, crypto_box_PUBLICKEYBYTES) == 0) {
        int id = accept_crypto_connection(self_c->net_crypto, n_c);
        Self_Conn *conn = new_conn(self_c);
        if (!conn)
            return -1;

        /* */
        conn->status = SELFCONN_STATUS_CONNECTING;
        conn->crypt_connection_id = id;

        /* set handlers */
        int conn_id = (conn - self_c->conns);
        connection_status_handler(self_c->net_crypto, id, &handle_status, self_c, conn_id);
        connection_data_handler(self_c->net_crypto, id, &handle_packet, self_c, conn_id);
        connection_lossy_data_handler(self_c->net_crypto, id, &handle_lossy_packet, self_c, conn_id);

        return 0;
    }

    return -1;
}

void self_connections_sync_friend(Self_Connections *self_c, int friend_id, uint8_t packet_id,
                                  const uint8_t *data, uint32_t data_length)
{
    uint32_t i;
    int64_t ret;
    uint8_t msg[sizeof(packet_id) + sizeof(friend_id) + data_length];

    msg[0] = packet_id;
    memcpy(msg + sizeof(packet_id), &friend_id, sizeof(friend_id));
    memcpy(msg + sizeof(packet_id) + sizeof(friend_id), data, data_length);

    for (i = 0; i < SELF_CONN_MAX; ++i) {
        Self_Conn *conn = &self_c->conns[i];
        if (!conn->status)
            continue;

        ret = write_cryptpacket(self_c->net_crypto, conn->crypt_connection_id, msg, sizeof(msg), 0);
    }

}

Self_Connections* new_self_connections(Net_Crypto *net_crypto, Self_Callbacks *cb, void *callback_object)
{
    if (!net_crypto)
        return NULL;

    Self_Connections *temp = calloc(1, sizeof(Self_Connections));

    if (temp == NULL)
        return NULL;

    temp->net_crypto = net_crypto;
    temp->cb = *cb;
    temp->callback_object = callback_object;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);

    return temp;
}

void do_self_connections(Self_Connections *self_c)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < SELF_CONN_MAX; ++i) {
        Self_Conn *conn = &self_c->conns[i];
        if (!conn->status)
            continue;

        if (conn->ping_lastsent + SELF_PING_INTERVAL < temp_time) {
            send_ping(self_c, conn);
        }

        if (conn->ping_lastrecv + SELF_CONNECTION_TIMEOUT < temp_time) {
            crypto_kill(self_c->net_crypto, conn->crypt_connection_id);
            conn->status = 0;
        }
    }
}

void kill_self_connections(Self_Connections *self_c)
{
    if (!self_c)
        return;

    uint32_t i;

    for (i = 0; i < SELF_CONN_MAX; ++i) {
        Self_Conn *conn = &self_c->conns[i];
        if (!conn->status)
            continue;

        crypto_kill(self_c->net_crypto, conn->crypt_connection_id);
    }

    free(self_c);
}

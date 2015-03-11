/*
 * Copyright 2014-2015 James Geboski <jgeboski@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <bitlbee.h>
#include <glib/gprintf.h>
#include <ssl_client.h>
#include <stdarg.h>
#include <string.h>

#include "facebook-mqtt.h"

/**
 * Gets the error domain for #fb_mqtt.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark fb_mqtt_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("fb-mqtt-error-quark");

    return q;
}

/**
 * Creates a new #fb_mqtt. The returned #fb_mqtt should be freed with
 * #fb_mqtt_free() when no longer needed.
 *
 * @param funcs The #fb_mqtt_funcs.
 * @param data  The user defined data or NULL.
 *
 * @return The #fb_mqtt or NULL on error.
 **/
fb_mqtt_t *fb_mqtt_new(const fb_mqtt_funcs_t *funcs, gpointer data)
{
    fb_mqtt_t *mqtt;

    mqtt = g_new0(fb_mqtt_t, 1);
    memcpy(&mqtt->funcs, funcs, sizeof *funcs);
    mqtt->data = data;
    mqtt->rbuf = g_byte_array_new();
    mqtt->wbuf = g_byte_array_new();

    return mqtt;
};

/**
 * Frees all memory used by a #fb_mqtt.
 *
 * @param api The #fb_mqtt.
 **/
void fb_mqtt_free(fb_mqtt_t *mqtt)
{
    if (G_UNLIKELY(mqtt == NULL))
        return;

    fb_mqtt_close(mqtt);
    g_clear_error(&mqtt->err);

    g_byte_array_free(mqtt->wbuf, TRUE);
    g_byte_array_free(mqtt->rbuf, TRUE);

    g_free(mqtt);
}

/**
 * Closes the #fb_mqtt connection.
 *
 * @param mqtt The #fb_mqtt.
 **/
void fb_mqtt_close(fb_mqtt_t *mqtt)
{
    g_return_if_fail(mqtt != NULL);

    if (mqtt->wev > 0) {
        b_event_remove(mqtt->wev);
        mqtt->wev = 0;
    }

    if (mqtt->rev > 0) {
        b_event_remove(mqtt->rev);
        mqtt->rev = 0;
    }

    if (mqtt->tev > 0) {
        b_event_remove(mqtt->tev);
        mqtt->tev = 0;
    }

    if (mqtt->ssl != NULL) {
        ssl_disconnect(mqtt->ssl);
        mqtt->ssl = NULL;
    }

#ifdef DEBUG_FACEBOOK
    if (mqtt->wbuf->len > 0)
        FB_UTIL_DEBUGLN("Closing with unwritten data");
#endif /* DEBUG_FACEBOOK */

    mqtt->connected = FALSE;
    g_clear_error(&mqtt->err);

    g_byte_array_set_size(mqtt->rbuf, 0);
    g_byte_array_set_size(mqtt->wbuf, 0);
}

/**
 * Handles an error with the #fb_mqtt. This sets #fb_mqtt->err, calls
 * the error function, and closes the connection.
 *
 * @param mqtt  The #fb_mqtt.
 * @param error The #fb_mqtt_error.
 * @param fmt   The format string.
 * @param ...   The arguments for the format string.
 **/
void fb_mqtt_error(fb_mqtt_t *mqtt, fb_mqtt_error_t err, const gchar *fmt, ...)
{
    gchar   *str;
    va_list  ap;

    g_return_if_fail(mqtt != NULL);

    if (fmt != NULL) {
        va_start(ap, fmt);
        str = g_strdup_vprintf(fmt, ap);
        va_end(ap);

        g_clear_error(&mqtt->err);
        g_set_error_literal(&mqtt->err, FB_MQTT_ERROR, err, str);
        g_free(str);
    }

    if (mqtt->err != NULL)
        FB_MQTT_FUNC(mqtt, error, mqtt->err);
}

/**
 * Implemented #b_event_handler for #fb_mqtt_timeout().
 *
 * @param data The user defined data, which is #fb_mqtt.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return FALSE to prevent continued event handling.
 **/
static gboolean fb_mqtt_cb_timeout(gpointer data, gint fd,
                                   b_input_condition cond)
{
    fb_mqtt_t *mqtt = data;

    mqtt->tev = 0;
    fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Connection timed out");
    return FALSE;
}

/**
 * Clears an enacted connection timeout.
 *
 * @param mqtt The #fb_mqtt.
 **/
static void fb_mqtt_timeout_clear(fb_mqtt_t *mqtt)
{
    g_return_if_fail(mqtt != NULL);

    if (mqtt->tev > 0) {
        b_event_remove(mqtt->tev);
        mqtt->tev = 0;
    }
}

/**
 * Enacts a timeout on the connection. This clears any timeout which
 * currently exists.
 *
 * @param mqtt The #fb_mqtt.
 **/
static void fb_mqtt_timeout(fb_mqtt_t *mqtt)
{
    g_return_if_fail(mqtt != NULL);

    fb_mqtt_timeout_clear(mqtt);
    mqtt->tev = b_timeout_add(FB_MQTT_TIMEOUT_CONN, fb_mqtt_cb_timeout, mqtt);
}

/**
 * Implemented #b_event_handler for sending a PING request.
 *
 * @param data The user defined data, which is #fb_mqtt.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return FALSE to prevent continued event handling.
 **/
static gboolean fb_mqtt_cb_ping(gpointer data, gint fd,
                                b_input_condition cond)
{
    fb_mqtt_t     *mqtt = data;
    fb_mqtt_msg_t *msg;

    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_PINGREQ, 0);
    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);

    mqtt->tev = 0;
    fb_mqtt_timeout(mqtt);
    return FALSE;
}

/**
 * Sends a PING after #FB_MQTT_KA seconds. This clears any timeout which
 * currently exists.
 *
 * @param mqtt The #fb_mqtt.
 **/
static void fb_mqtt_ping(fb_mqtt_t *mqtt)
{
    g_return_if_fail(mqtt != NULL);

    fb_mqtt_timeout_clear(mqtt);
    mqtt->tev = b_timeout_add(FB_MQTT_TIMEOUT_PING, fb_mqtt_cb_ping, mqtt);
}

/**
 * Implemented #b_event_handler for the read of #fb_mqtt->fd.
 *
 * @param data The user defined data, which is #fb_mqtt.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean fb_mqtt_cb_read(gpointer data, gint fd,
                                b_input_condition cond)
{
    fb_mqtt_t     *mqtt = data;
    fb_mqtt_msg_t *msg;
    gchar          buf[1024];
    guint8         byte;
    guint          mult;
    gssize         rize;
    gint           res;

    if (mqtt->remz < 1) {
        /* Reset the read buffer */
        g_byte_array_set_size(mqtt->rbuf, 0);

        res = ssl_read(mqtt->ssl, (gchar*) &byte, sizeof byte);
        g_byte_array_append(mqtt->rbuf, &byte, sizeof byte);

        if (res != sizeof byte)
            goto error;

        mult = 1;

        do {
            res = ssl_read(mqtt->ssl, (gchar*) &byte, sizeof byte);
            g_byte_array_append(mqtt->rbuf, &byte, sizeof byte);

            if (res != sizeof byte)
                goto error;

            mqtt->remz += (byte & 127) * mult;
            mult *= 128;
        } while ((byte & 128) != 0);
    }

    if (mqtt->remz > 0) {
        rize = ssl_read(mqtt->ssl, buf, MIN(mqtt->remz, sizeof buf));

        if (rize < 1)
            goto error;

        g_byte_array_append(mqtt->rbuf, (guint8*) buf, rize);
        mqtt->remz -= rize;
    }

    if (mqtt->remz < 1) {
        msg = fb_mqtt_msg_new_bytes(mqtt->rbuf);
        mqtt->remz = 0;

        if (G_UNLIKELY(msg == NULL))
            goto error;

        fb_mqtt_read(mqtt, msg);
        fb_mqtt_msg_free(msg);
    }

    return TRUE;

error:
    fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Short read");
    return FALSE;
}

/**
 * Read a #GByteArray to the #fb_mqtt.
 *
 * @param mqtt  The #fb_mqtt.
 * @param bytes The #GByteArray.
 **/
void fb_mqtt_read(fb_mqtt_t *mqtt, fb_mqtt_msg_t *msg)
{
    fb_mqtt_msg_t *nsg;
    GByteArray    *wytes;
    gchar         *str;
    guint8         chr;
    guint16        mid;

    g_return_if_fail(mqtt != NULL);
    g_return_if_fail(msg  != NULL);

    fb_util_hexdump(msg->bytes, 2, "Reading %d (flags: 0x%0X)",
                    msg->type, msg->flags);

    switch (msg->type) {
    case FB_MQTT_MSG_TYPE_CONNACK:
        if (!fb_mqtt_msg_read_byte(msg, NULL) ||
            !fb_mqtt_msg_read_byte(msg, &chr))
        {
            break;
        }

        if (chr != FB_MQTT_ERROR_SUCCESS) {
            fb_mqtt_error(mqtt, chr, "Connection failed (%u)", chr);
            return;
        }

        mqtt->connected = TRUE;
        fb_mqtt_ping(mqtt);
        FB_MQTT_FUNC(mqtt, connack);
        return;

    case FB_MQTT_MSG_TYPE_PUBLISH:
        if (!fb_mqtt_msg_read_str(msg, &str))
            break;

        if ((msg->flags & FB_MQTT_MSG_FLAG_QOS1) ||
            (msg->flags & FB_MQTT_MSG_FLAG_QOS2))
        {
            if (msg->flags & FB_MQTT_MSG_FLAG_QOS1)
                chr = FB_MQTT_MSG_TYPE_PUBACK;
            else
                chr = FB_MQTT_MSG_TYPE_PUBREC;

            if (!fb_mqtt_msg_read_mid(msg, &mid))
                break;

            nsg = fb_mqtt_msg_new(chr, 0);
            fb_mqtt_msg_write_u16(nsg, mid);
            fb_mqtt_write(mqtt, nsg);
            fb_mqtt_msg_free(nsg);
        }

        wytes = g_byte_array_new();
        fb_mqtt_msg_read_r(msg, wytes);
        FB_MQTT_FUNC(mqtt, publish, str, wytes);
        g_byte_array_free(wytes, TRUE);
        g_free(str);
        return;

    case FB_MQTT_MSG_TYPE_PUBREL:
        if (!fb_mqtt_msg_read_mid(msg, &mid))
            break;

        nsg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_PUBCOMP, 0);
        fb_mqtt_msg_write_u16(nsg, mid); /* Message identifier */
        fb_mqtt_write(mqtt, nsg);
        fb_mqtt_msg_free(nsg);
        return;

    case FB_MQTT_MSG_TYPE_PINGRESP:
        fb_mqtt_ping(mqtt);
        return;

    case FB_MQTT_MSG_TYPE_PUBACK:
    case FB_MQTT_MSG_TYPE_PUBCOMP:
    case FB_MQTT_MSG_TYPE_SUBACK:
    case FB_MQTT_MSG_TYPE_UNSUBACK:
        return;

    default:
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Unknown packet (%u)",
                      msg->type);
        return;
    }

    /* Since no case returned, there was a parse error. */
    fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to parse message");
}

/**
 * Implemented #b_event_handler for the writing of #fb_mqtt->fd.
 *
 * @param data The user defined data, which is #fb_mqtt.
 * @param fd   The event file descriptor.
 * @param cond The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean fb_mqtt_cb_write(gpointer data, gint fd,
                                 b_input_condition cond)
{
    fb_mqtt_t *mqtt = data;
    gssize     wize;

    wize = ssl_write(mqtt->ssl, (gchar*) mqtt->wbuf->data, mqtt->wbuf->len);

    if (wize < 0) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to write data");
        return FALSE;
    }

    if (wize > 0)
        g_byte_array_remove_range(mqtt->wbuf, 0, wize);

    if (mqtt->wbuf->len < 1) {
        mqtt->wev = 0;
        return FALSE;
    }

    return TRUE;
}

/**
 * Writes a #fb_mqtt_msg to the #fb_mqtt.
 *
 * @param mqtt The #fb_mqtt.
 * @param msg  The #fb_mqtt_msg.
 **/
void fb_mqtt_write(fb_mqtt_t *mqtt, fb_mqtt_msg_t *msg)
{
    const GByteArray *bytes;
    gint fd;

    g_return_if_fail(mqtt != NULL);

    bytes = fb_mqtt_msg_bytes(msg);

    if (G_UNLIKELY(bytes == NULL)) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to format data");
        return;
    }

    fb_util_hexdump(bytes, 2, "Writing %d (flags: 0x%0X)",
                    msg->type, msg->flags);

    fd = ssl_getfd(mqtt->ssl);
    g_byte_array_append(mqtt->wbuf, bytes->data, bytes->len);

    if ((mqtt->wev < 1) && fb_mqtt_cb_write(mqtt, fd, B_EV_IO_WRITE))
        mqtt->wev = b_input_add(fd, B_EV_IO_WRITE, fb_mqtt_cb_write, mqtt);
}

/**
 * Implemented #ssl_input_function for the connection of #fb_mqtt->ssl.
 *
 * @param data  The user defined data, which is #fb_mqtt.
 * @param error The SSL error. (0 on success)
 * @param ssl   The SSL source.
 * @param cond  The #b_input_condition.
 *
 * @return TRUE for continued event handling, otherwise FALSE.
 **/
static gboolean fb_mqtt_cb_open(gpointer data, gint error, gpointer ssl,
                                b_input_condition cond)
{
    fb_mqtt_t *mqtt = data;
    gint       fd;

    if ((ssl == NULL) || (error != SSL_OK)) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to connect");
        return FALSE;
    }

    fb_mqtt_timeout_clear(mqtt);
    fd = ssl_getfd(mqtt->ssl);
    mqtt->rev = b_input_add(fd, B_EV_IO_READ, fb_mqtt_cb_read, mqtt);

    FB_MQTT_FUNC(mqtt, open);
    return FALSE;
}

/**
 * Opens the connection to the MQTT service.
 *
 * @param mqtt The #fb_mqtt.
 **/
void fb_mqtt_open(fb_mqtt_t *mqtt, const gchar *host, gint port)
{
    g_return_if_fail(mqtt != NULL);

    fb_mqtt_close(mqtt);
    mqtt->ssl = ssl_connect((gchar*) host, port, TRUE, fb_mqtt_cb_open, mqtt);

    if (mqtt->ssl == NULL) {
        fb_mqtt_cb_open(mqtt, 1, NULL, 0);
        return;
    }

    fb_mqtt_timeout(mqtt);
}

/**
 * Connects to the MQTT service. This first establishes an SSL based
 * socket. Then it sends the initial connection packet with optional
 * arguments, which correspond to the flags provided. The arguments
 * must be passed in order: client identifier, will topic, will
 * message, username, and password (not required). The arguments must
 * be in a string format.
 *
 * @param mqtt    The #fb_mqtt.
 * @param timeout The keep-alive timeout (seconds).
 * @param flags   The #fb_mqtt_connect_flags.
 * @param cid     The client identifier.
 * @param ...     Additional arguments in order, NULL-terminated.
 **/
void fb_mqtt_connect(fb_mqtt_t *mqtt, guint8 flags, const gchar *cid, ...)
{
    fb_mqtt_msg_t *msg;
    va_list        ap;
    const gchar   *str;

    g_return_if_fail(mqtt != NULL);

    if (G_UNLIKELY(fb_mqtt_connected(mqtt, FALSE)))
        return;

    /* Facebook always sends a CONNACK, use QoS1 */
    flags |= FB_MQTT_CONNECT_FLAG_QOS1;

    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_CONNECT, 0);
    fb_mqtt_msg_write_str(msg, FB_MQTT_NAME);  /* Protocol name */
    fb_mqtt_msg_write_byte(msg, FB_MQTT_VERS); /* Protocol version */
    fb_mqtt_msg_write_byte(msg, flags);        /* Flags */
    fb_mqtt_msg_write_u16(msg, FB_MQTT_KA);    /* Keep alive */
    fb_mqtt_msg_write_str(msg, cid);           /* Client identifier */

    va_start(ap, cid);

    while ((str = va_arg(ap, const gchar*)) != NULL)
        fb_mqtt_msg_write_str(msg, str);

    va_end(ap);

    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);
    fb_mqtt_timeout(mqtt);
}

/**
 * Checks the #fb_mqtt connection.
 *
 * @param mqtt  The #fb_mqtt.
 * @param error TRUE to error upon no connection, FALSE otherwise.
 *
 * @return TRUE if the #fb_mqtt is connected, FALSE otherwise.
 **/
gboolean fb_mqtt_connected(fb_mqtt_t *mqtt, gboolean error)
{
    gboolean connected;

    g_return_val_if_fail(mqtt != NULL, FALSE);

    connected = (mqtt->ssl != NULL) && mqtt->connected;

    if (!connected && error)
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Not connected");

    return connected;
}

/**
 * Disconnects from the MQTT service. This cleanly disconnects from the
 * MQTT services, rather than killing the socket stream. This closes
 * the #fb_mqtt via #fb_mqtt_close().
 *
 * @param mqtt The #fb_mqtt.
 **/
void fb_mqtt_disconnect(fb_mqtt_t *mqtt)
{
    fb_mqtt_msg_t *msg;

    g_return_if_fail(mqtt != NULL);

    if (G_UNLIKELY(!fb_mqtt_connected(mqtt, FALSE)))
        return;

    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_DISCONNECT, 0);
    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);
    fb_mqtt_close(mqtt);
}

/**
 * Publishes a message to MQTT service.
 *
 * @param mqtt  The #fb_mqtt.
 * @param topic The message topic.
 * @param pload The #GByteArray payload or NULL.
 **/
void fb_mqtt_publish(fb_mqtt_t *mqtt, const gchar *topic,
                     const GByteArray *pload)
{
    fb_mqtt_msg_t *msg;

    g_return_if_fail(mqtt != NULL);

    if (G_UNLIKELY(!fb_mqtt_connected(mqtt, TRUE)))
        return;

    /* Message identifier not required, but for consistency use QoS1 */
    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_PUBLISH, FB_MQTT_MSG_FLAG_QOS1);

    fb_mqtt_msg_write_str(msg, topic);      /* Message topic */
    fb_mqtt_msg_write_mid(msg, &mqtt->mid); /* Message identifier */

    if (pload != NULL)
        fb_mqtt_msg_write(msg, pload->data, pload->len);

    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);
}

/**
 * Subscribes to one or more topics.
 *
 * @param mqtt   The #fb_mqtt.
 * @param topic1 The first topic name.
 * @param qos1   The first QoS value.
 * @param ...    Additional topic names and QoS values, NULL-terminated.
 **/
void fb_mqtt_subscribe(fb_mqtt_t *mqtt, const gchar *topic1, guint16 qos1, ...)
{
    fb_mqtt_msg_t *msg;
    va_list        ap;
    const gchar   *topic;
    guint16        qos;

    g_return_if_fail(mqtt != NULL);

    if (G_UNLIKELY(!fb_mqtt_connected(mqtt, TRUE)))
        return;

    /* Facebook requires a message identifier, use QoS1 */
    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_SUBSCRIBE, FB_MQTT_MSG_FLAG_QOS1);

    fb_mqtt_msg_write_mid(msg, &mqtt->mid); /* Message identifier */
    fb_mqtt_msg_write_str(msg, topic1);     /* First topics */
    fb_mqtt_msg_write_byte(msg, qos1);      /* First QoS value */

    va_start(ap, qos1);

    while ((topic = va_arg(ap, const gchar*)) != NULL) {
        qos = va_arg(ap, guint);
        fb_mqtt_msg_write_str(msg, topic); /* Remaining topics */
        fb_mqtt_msg_write_byte(msg, qos);  /* Remaining QoS values */
    }

    va_end(ap);

    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);
}

/**
 * Unsubscribes from one or more topics.
 *
 * @param mqtt   The #fb_mqtt.
 * @param topic1 The first topic name.
 * @param ...    Additional topic names, NULL-terminated.
 **/
void fb_mqtt_unsubscribe(fb_mqtt_t *mqtt, const gchar *topic1, ...)
{
    fb_mqtt_msg_t *msg;
    va_list        ap;
    const gchar   *topic;

    g_return_if_fail(mqtt != NULL);

    if (G_UNLIKELY(!fb_mqtt_connected(mqtt, TRUE)))
        return;

    /* Facebook requires a message identifier, use QoS1 */
    msg = fb_mqtt_msg_new(FB_MQTT_MSG_TYPE_UNSUBSCRIBE, FB_MQTT_MSG_FLAG_QOS1);

    fb_mqtt_msg_write_mid(msg, &mqtt->mid); /* Message identifier */
    fb_mqtt_msg_write_str(msg, topic1);     /* First topic */

    va_start(ap, topic1);

    while ((topic = va_arg(ap, const gchar*)) != NULL)
        fb_mqtt_msg_write_str(msg, topic); /* Remaining topics */

    va_end(ap);

    fb_mqtt_write(mqtt, msg);
    fb_mqtt_msg_free(msg);
}

/**
 * Creates a new #fb_mqtt_msg. The returned #fb_mqtt_msg should be
 * freed with #fb_mqtt_msg_free() when no longer needed.
 *
 * @param type  The #fb_mqtt_msg_type.
 * @param flags The #fb_mqtt_msg_flags.
 *
 * @return The #fb_mqtt_msg or NULL on error.
 **/
fb_mqtt_msg_t *fb_mqtt_msg_new(fb_mqtt_msg_type_t type,
                               fb_mqtt_msg_flags_t flags)
{
    fb_mqtt_msg_t *msg;

    msg = g_new0(fb_mqtt_msg_t, 1);
    msg->type  = type;
    msg->flags = flags;
    msg->bytes = g_byte_array_new();
    msg->local = TRUE;

    return msg;
}

/**
 * Creates a new #fb_mqtt_msg from a #GByteArray containing a raw data.
 * The returned #fb_mqtt_msg should be freed with #fb_mqtt_msg_free()
 * when no longer needed. The GByteArray passed to this function MUST
 * remain for the lifetime of the #fb_mqtt_msg.
 *
 * @param bytes  The #GByteArray.
 *
 * @return The #fb_mqtt_msg or NULL on error.
 **/
fb_mqtt_msg_t *fb_mqtt_msg_new_bytes(GByteArray *bytes)
{
    fb_mqtt_msg_t *msg;
    guint8        *byte;

    g_return_val_if_fail(bytes != NULL,   NULL);
    g_return_val_if_fail(bytes->len >= 2, NULL);

    msg = g_new0(fb_mqtt_msg_t, 1);
    msg->bytes = bytes;
    msg->local = FALSE;

    if (bytes->len > 1) {
        msg->type  = (*bytes->data & 0xF0) >> 4;
        msg->flags = *bytes->data & 0x0F;

        /* Skip the fixed header */
        for (byte = msg->bytes->data + 1; (*(byte++) & 128) != 0; );
        msg->offset = byte - bytes->data;
        msg->pos    = msg->offset;
    }

    return msg;
}

/**
 * Frees all memory used by a #fb_mqtt_msg.
 *
 * @param msg The #fb_mqtt_msg.
 **/
void fb_mqtt_msg_free(fb_mqtt_msg_t *msg)
{
    g_return_if_fail(msg != NULL);

    if (msg->local)
        g_byte_array_free(msg->bytes, TRUE);

    g_free(msg);
}

/**
 * Resets a #fb_mqtt_msg. This resets the cursor and removes any sort
 * of fixed header.
 *
 * @param msg The #fb_mqtt_msg.
 **/
void fb_mqtt_msg_reset(fb_mqtt_msg_t *msg)
{
    if (G_UNLIKELY(msg == NULL))
        return;

    if (msg->offset > 0) {
        g_byte_array_remove_range(msg->bytes, 0, msg->offset);
        msg->offset = 0;
        msg->pos    = 0;
    }
}

/**
 * Formats the internal #GByteArray of a #fb_mqtt_msg with the required
 * fixed header for sending over the wire. This set the cursor position
 * to the start of the message data.
 *
 * @param msg The #fb_mqtt_msg.
 *
 * @return The internal #GByteArray.
 **/
const GByteArray *fb_mqtt_msg_bytes(fb_mqtt_msg_t *msg)
{
    guint8  sbuf[4];
    guint8  byte;
    guint32 size;
    guint   i;

    g_return_val_if_fail(msg != NULL, NULL);

    size = msg->bytes->len - msg->offset;
    i    = 0;

    do {
        if (G_UNLIKELY(i >= G_N_ELEMENTS(sbuf)))
            return NULL;

        byte  = size % 128;
        size /= 128;

        if (size > 0)
            byte |= 128;

        sbuf[i++] = byte;
    } while (size > 0);

    fb_mqtt_msg_reset(msg);
    g_byte_array_prepend(msg->bytes, sbuf, i);

    byte = ((msg->type & 0x0F) << 4) | (msg->flags & 0x0F);
    g_byte_array_prepend(msg->bytes, &byte, sizeof byte);

    msg->pos = (i + 1) * (sizeof byte);
    return msg->bytes;
}

/**
 * Reads raw data from a #fb_mqtt_msg.
 *
 * @param msg  The #fb_mqtt_msg.
 * @param data The data buffer or NULL.
 * @param size The size of data to read.
 *
 * @return TRUE if the data was completely read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read(fb_mqtt_msg_t *msg, gpointer data, guint size)
{
    g_return_val_if_fail(msg != NULL, FALSE);

    if ((msg->pos + size) > msg->bytes->len)
        return FALSE;

    if ((data != NULL) && (size > 0))
        memcpy(data, msg->bytes->data + msg->pos, size);

    msg->pos += size;
    return TRUE;
}

/**
 * Reads the remaining bytes from a #fb_mqtt_msg into a #GByteArray.
 *
 * @param msg   The #fb_mqtt_msg.
 * @param bytes The #GByteArray.
 *
 * @return TRUE if the byte string was read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read_r(fb_mqtt_msg_t *msg, GByteArray *bytes)
{
    guint size;

    g_return_val_if_fail(bytes != NULL, FALSE);

    size = msg->bytes->len - msg->pos;

    if (G_LIKELY(size > 0))
        g_byte_array_append(bytes, msg->bytes->data + msg->pos, size);

    return TRUE;
}

/**
 * Reads a single byte from a #fb_mqtt_msg. If the return location is
 * NULL, only the cursor is advanced.
 *
 * @param msg  The #fb_mqtt_msg.
 * @param byte The return location for the byte or NULL.
 *
 * @return TRUE if the byte string was read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read_byte(fb_mqtt_msg_t *msg, guint8 *byte)
{
    if (byte != NULL)
        *byte = 0;

    return fb_mqtt_msg_read(msg, byte, sizeof *byte);
}

/**
 * Reads a message identifier from a #fb_mqtt_msg. If the return
 * location is NULL, only the cursor is advanced.
 *
 * @param msg The #fb_mqtt_msg.
 * @param mid The return location for the message identifier or NULL.
 *
 * @return TRUE if the message identifier was read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read_mid(fb_mqtt_msg_t *msg, guint16 *mid)
{
    return fb_mqtt_msg_read_u16(msg, mid);
}

/**
 * Reads an unsigned 16-bit integer from a #fb_mqtt_msg. If the return
 * location is NULL, only the cursor is advanced.
 *
 * @param msg The #fb_mqtt_msg.
 * @param u16 The return location for the integer or NULL.
 *
 * @return TRUE if the integer was read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read_u16(fb_mqtt_msg_t *msg, guint16 *u16)
{
    if (!fb_mqtt_msg_read(msg, u16, sizeof *u16)) {
        if (u16 != NULL)
            *u16 = 0;

        return FALSE;
    }

    if (u16 != NULL)
        *u16 = g_ntohs(*u16);

    return TRUE;
}

/**
 * Reads a string from a #fb_mqtt_msg. If the return location is NULL,
 * only the cursor is advanced. The returned string should be freed
 * with #g_free() when no longer needed.
 *
 * @param msg The #fb_mqtt_msg.
 * @param str The return location for the string or NULL.
 *
 * @return TRUE if the string was read, otherwise FALSE.
 **/
gboolean fb_mqtt_msg_read_str(fb_mqtt_msg_t *msg, gchar **str)
{
    guint16  size;
    guint8  *data;

    if (str != NULL)
        *str = NULL;

    if (!fb_mqtt_msg_read_u16(msg, &size))
        return FALSE;

    if (str != NULL) {
        data = g_new(guint8, size + 1);
        data[size] = 0;
    } else {
        data = NULL;
    }

    if (!fb_mqtt_msg_read(msg, data, size)) {
        g_free(data);
        return FALSE;
    }

    if (str != NULL)
        *str = (gchar*) data;

    return TRUE;
}

/**
 * Writes raw data to a #fb_mqtt_msg.
 *
 * @param msg  The #fb_mqtt_msg.
 * @param data The data.
 * @param size The size of the data.
 **/
void fb_mqtt_msg_write(fb_mqtt_msg_t *msg, gconstpointer data, guint size)
{
    g_return_if_fail(msg != NULL);

    g_byte_array_append(msg->bytes, data, size);
    msg->pos += size;
}

/**
 * Writes a single byte to a #fb_mqtt_msg.
 *
 * @param msg  The #fb_mqtt_msg.
 * @param byte The byte.
 **/
void fb_mqtt_msg_write_byte(fb_mqtt_msg_t *msg, guint8 byte)
{
    fb_mqtt_msg_write(msg, &byte, sizeof byte);
}

/**
 * Writes a 16-bit message identifier to a #fb_mqtt_msg. This advances
 * the message identifier by one before usage.
 *
 * @param msg The #fb_mqtt_msg.
 * @param mid The return location of the message identifier.
 **/
void fb_mqtt_msg_write_mid(fb_mqtt_msg_t *msg, guint16 *mid)
{
    g_return_if_fail(mid != NULL);

    fb_mqtt_msg_write_u16(msg, ++(*mid));
}

/**
 * Writes an unsigned 16-bit integer to a #fb_mqtt_msg.
 *
 * @param msg The #fb_mqtt_msg.
 * @param u16 Theinteger.
 **/
void fb_mqtt_msg_write_u16(fb_mqtt_msg_t *msg, guint16 u16)
{
    u16 = g_htons(u16);
    fb_mqtt_msg_write(msg, &u16, sizeof u16);
}

/**
 * Writes a string to a #fb_mqtt_msg.
 *
 * @param msg The #fb_mqtt_msg.
 * @param str The string.
 **/
void fb_mqtt_msg_write_str(fb_mqtt_msg_t *msg, const gchar *str)
{
    gint16 size;

    g_return_if_fail(str != NULL);

    size = strlen(str);
    fb_mqtt_msg_write_u16(msg, size);
    fb_mqtt_msg_write(msg, str, size);
}

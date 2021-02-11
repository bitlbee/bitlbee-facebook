/*
 * Copyright 2014-2016 James Geboski <jgeboski@gmail.com>
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
#include <ssl_client.h>
#include <stdarg.h>
#include <string.h>

#include "facebook-marshal.h"
#include "facebook-mqtt.h"
#include "facebook-util.h"

struct _FbMqttPrivate
{
    gpointer ssl;
    gboolean connected;
    guint16 mid;

    GByteArray *rbuf;
    GByteArray *wbuf;
    gsize remz;

    gint tev;
    gint rev;
    gint wev;
};

struct _FbMqttMessagePrivate
{
    FbMqttMessageType type;
    FbMqttMessageFlags flags;

    GByteArray *bytes;
    guint offset;
    guint pos;

    gboolean local;
};

G_DEFINE_TYPE_WITH_PRIVATE(FbMqtt, fb_mqtt, G_TYPE_OBJECT);
G_DEFINE_TYPE_WITH_PRIVATE(FbMqttMessage, fb_mqtt_message, G_TYPE_OBJECT);

static void
fb_mqtt_dispose(GObject *obj)
{
    FbMqtt *mqtt = FB_MQTT(obj);
    FbMqttPrivate *priv = mqtt->priv;

    fb_mqtt_close(mqtt);
    g_byte_array_free(priv->rbuf, TRUE);
    g_byte_array_free(priv->wbuf, TRUE);
}

static void
fb_mqtt_class_init(FbMqttClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    gklass->dispose = fb_mqtt_dispose;

    /**
     * FbMqtt::connect:
     * @mqtt: The #FbMqtt.
     *
     * Emitted upon the successful completion of the connection
     * process. This is emitted as a result of #fb_mqtt_connect().
     */
    g_signal_new("connect",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__VOID,
                 G_TYPE_NONE,
                 0);

    /**
     * FbMqtt::error:
     * @mqtt: The #FbMqtt.
     * @error: The #GError.
     *
     * Emitted whenever an error is hit within the #FbMqtt. This should
     * close the #FbMqtt with #fb_mqtt_close().
     */
    g_signal_new("error",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__OBJECT,
                 G_TYPE_NONE,
                 1, G_TYPE_ERROR);

    /**
     * FbMqtt::open:
     * @mqtt: The #FbMqtt.
     *
     * Emitted upon the successful opening of the remote socket.
     * This is emitted as a result of #fb_mqtt_open(). This should
     * call #fb_mqtt_connect().
     */
    g_signal_new("open",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__VOID,
                 G_TYPE_NONE,
                 0);

    /**
     * FbMqtt::publish:
     * @mqtt: The #FbMqtt.
     * @topic: The topic.
     * @pload: The payload.
     *
     * Emitted upon an incoming message from the steam.
     */
    g_signal_new("publish",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__STRING_BOXED,
                 G_TYPE_NONE,
                 2, G_TYPE_STRING, G_TYPE_BYTE_ARRAY);
}

static void
fb_mqtt_init(FbMqtt *mqtt)
{
    FbMqttPrivate *priv;

    priv = fb_mqtt_get_instance_private(mqtt);
    mqtt->priv = priv;

    priv->rbuf = g_byte_array_new();
    priv->wbuf = g_byte_array_new();
}

static void
fb_mqtt_message_dispose(GObject *obj)
{
    FbMqttMessagePrivate *priv = FB_MQTT_MESSAGE(obj)->priv;

    if ((priv->bytes != NULL) && priv->local) {
        g_byte_array_free(priv->bytes, TRUE);
    }
}

static void
fb_mqtt_message_class_init(FbMqttMessageClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    gklass->dispose = fb_mqtt_message_dispose;
}

static void
fb_mqtt_message_init(FbMqttMessage *msg)
{
    FbMqttMessagePrivate *priv;

    priv = fb_mqtt_message_get_instance_private(msg);
    msg->priv = priv;
}

GQuark
fb_mqtt_error_quark(void)
{
    static GQuark q = 0;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("fb-mqtt-error-quark");
    }

    return q;
}

GQuark
fb_mqtt_ssl_error_quark(void)
{
    static GQuark q = 0;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("fb-mqtt-ssl-error-quark");
    }

    return q;
}

FbMqtt *
fb_mqtt_new(void)
{
    return g_object_new(FB_TYPE_MQTT,  NULL);
};

void
fb_mqtt_close(FbMqtt *mqtt)
{
    FbMqttPrivate *priv;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    priv = mqtt->priv;

    if (priv->wev > 0) {
        b_event_remove(priv->wev);
        priv->wev = 0;
    }

    if (priv->rev > 0) {
        b_event_remove(priv->rev);
        priv->rev = 0;
    }

    if (priv->tev > 0) {
        b_event_remove(priv->tev);
        priv->tev = 0;
    }

    if (priv->ssl != NULL) {
        ssl_disconnect(priv->ssl);
        priv->ssl = NULL;
    }

    if (priv->wbuf->len > 0) {
        fb_util_debug_warn("Closing with unwritten data");
    }

    priv->connected = FALSE;
    g_byte_array_set_size(priv->rbuf, 0);
    g_byte_array_set_size(priv->wbuf, 0);
}

void
fb_mqtt_error(FbMqtt *mqtt, FbMqttError error, const gchar *format, ...)
{
    GError *err;
    va_list ap;

    g_return_if_fail(FB_IS_MQTT(mqtt));

    va_start(ap, format);
    err = g_error_new_valist(FB_MQTT_ERROR, error, format, ap);
    va_end(ap);

    g_signal_emit_by_name(mqtt, "error", err);
    g_error_free(err);
}

static gboolean
fb_mqtt_cb_timeout(gpointer data, gint fd, b_input_condition cond)
{
    FbMqtt *mqtt = data;
    FbMqttPrivate *priv = mqtt->priv;

    priv->tev = 0;
    fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Connection timed out");
    return FALSE;
}

static void
fb_mqtt_timeout_clear(FbMqtt *mqtt)
{
    FbMqttPrivate *priv = mqtt->priv;

    if (priv->tev > 0) {
        b_event_remove(priv->tev);
        priv->tev = 0;
    }
}

static void
fb_mqtt_timeout(FbMqtt *mqtt)
{
    FbMqttPrivate *priv = mqtt->priv;

    fb_mqtt_timeout_clear(mqtt);
    priv->tev = b_timeout_add(FB_MQTT_TIMEOUT_CONN, fb_mqtt_cb_timeout, mqtt);
}

static gboolean
fb_mqtt_cb_ping(gpointer data, gint fd, b_input_condition cond)
{
    FbMqtt *mqtt = data;
    FbMqttMessage *msg;
    FbMqttPrivate *priv = mqtt->priv;

    priv->tev = 0;
    fb_mqtt_timeout(mqtt);

    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PINGREQ, 0);
    fb_mqtt_write(mqtt, msg);
    g_object_unref(msg);

    return FALSE;
}

static void
fb_mqtt_ping(FbMqtt *mqtt)
{
    FbMqttPrivate *priv = mqtt->priv;

    fb_mqtt_timeout_clear(mqtt);
    priv->tev = b_timeout_add(FB_MQTT_TIMEOUT_PING, fb_mqtt_cb_ping, mqtt);
}

static gboolean
fb_mqtt_cb_read(gpointer data, gint fd, b_input_condition cond)
{
    FbMqtt *mqtt = data;
    FbMqttMessage *msg;
    FbMqttPrivate *priv = mqtt->priv;
    gint res;
    guint mult;
    guint8 buf[1024];
    guint8 byte;
    gsize size;
    gssize rize;

    if (priv->remz < 1) {
        /* Reset the read buffer */
        g_byte_array_set_size(priv->rbuf, 0);

        res = ssl_read(priv->ssl, (gchar *) &byte, sizeof byte);

        if (res < 0 && ssl_sockerr_again(priv->ssl)) {
            return TRUE;
        } else if (res != 1) {
            fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
                          "Failed to read fixed header");
            return FALSE;
        }

        g_byte_array_append(priv->rbuf, &byte, sizeof byte);

        mult = 1;

        do {
            res = ssl_read(priv->ssl, (gchar *) &byte, sizeof byte);

            /* TODO: this case isn't handled yet */
            if (0 && res < 0 && ssl_sockerr_again(priv->ssl)) {
                return TRUE;
            } else if (res != 1) {
                fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
                              "Failed to read packet size");
                return FALSE;
            }

            g_byte_array_append(priv->rbuf, &byte, sizeof byte);

            priv->remz += (byte & 127) * mult;
            mult *= 128;
        } while ((byte & 128) != 0);
    }

    if (priv->remz > 0) {
        size = MIN(priv->remz, sizeof buf);
        rize = ssl_read(priv->ssl, (gchar *) buf, size);

        if (rize < 0 && ssl_sockerr_again(priv->ssl)) {
            return TRUE;
        } else if (rize < 1) {
            fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
                          "Failed to read packet data");
            return FALSE;
        }

        g_byte_array_append(priv->rbuf, buf, rize);
        priv->remz -= rize;
    }

    if (priv->remz < 1) {
        msg = fb_mqtt_message_new_bytes(priv->rbuf);
        priv->remz = 0;

        if (G_UNLIKELY(msg == NULL)) {
            fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
                          "Failed to parse message");
            return FALSE;
        }

        fb_mqtt_read(mqtt, msg);
        g_object_unref(msg);
    }

    return TRUE;
}

void
fb_mqtt_read(FbMqtt *mqtt, FbMqttMessage *msg)
{
    FbMqttMessage *nsg;
    FbMqttPrivate *priv;
    FbMqttMessagePrivate *mriv;
    GByteArray *wytes;
    gchar *str;
    guint8 chr;
    guint16 mid;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
    priv = mqtt->priv;
    mriv = msg->priv;

    fb_util_debug_hexdump(FB_UTIL_DEBUG_LEVEL_INFO, mriv->bytes,
                          "Reading %d (flags: 0x%0X)",
                          mriv->type, mriv->flags);

    switch (mriv->type) {
    case FB_MQTT_MESSAGE_TYPE_CONNACK:
        if (!fb_mqtt_message_read_byte(msg, NULL) ||
            !fb_mqtt_message_read_byte(msg, &chr))
        {
            break;
        }

        if (chr != FB_MQTT_ERROR_SUCCESS) {
            fb_mqtt_error(mqtt, chr, "Connection failed (%u)", chr);
            return;
        }

        priv->connected = TRUE;
        fb_mqtt_ping(mqtt);
        g_signal_emit_by_name(mqtt, "connect");
        return;

    case FB_MQTT_MESSAGE_TYPE_PUBLISH:
        if (!fb_mqtt_message_read_str(msg, &str)) {
            break;
        }

        if ((mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS1) ||
            (mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS2))
        {
            if (mriv->flags & FB_MQTT_MESSAGE_FLAG_QOS1) {
                chr = FB_MQTT_MESSAGE_TYPE_PUBACK;
            } else {
                chr = FB_MQTT_MESSAGE_TYPE_PUBREC;
            }

            if (!fb_mqtt_message_read_mid(msg, &mid)) {
                g_free(str);
                break;
            }

            nsg = fb_mqtt_message_new(chr, 0);
            fb_mqtt_message_write_u16(nsg, mid);
            fb_mqtt_write(mqtt, nsg);
            g_object_unref(nsg);
        }

        wytes = g_byte_array_new();
        fb_mqtt_message_read_r(msg, wytes);
        g_signal_emit_by_name(mqtt, "publish", str, wytes);
        g_byte_array_free(wytes, TRUE);
        g_free(str);
        return;

    case FB_MQTT_MESSAGE_TYPE_PUBREL:
        if (!fb_mqtt_message_read_mid(msg, &mid)) {
            break;
        }

        nsg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PUBCOMP, 0);
        fb_mqtt_message_write_u16(nsg, mid); /* Message identifier */
        fb_mqtt_write(mqtt, nsg);
        g_object_unref(nsg);
        return;

    case FB_MQTT_MESSAGE_TYPE_PINGRESP:
        fb_mqtt_ping(mqtt);
        return;

    case FB_MQTT_MESSAGE_TYPE_PUBACK:
    case FB_MQTT_MESSAGE_TYPE_PUBCOMP:
    case FB_MQTT_MESSAGE_TYPE_SUBACK:
    case FB_MQTT_MESSAGE_TYPE_UNSUBACK:
        return;

    default:
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL,
                      "Unknown packet (%u)",
                      mriv->type);
        return;
    }

    /* Since no case returned, there was a parse error. */
    fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to parse message");
}

static gboolean
fb_mqtt_cb_write(gpointer data, gint fd, b_input_condition cond)
{
    FbMqtt *mqtt = data;
    FbMqttPrivate *priv = mqtt->priv;
    gssize wize;

    wize = ssl_write(priv->ssl, (gchar *) priv->wbuf->data, priv->wbuf->len);

    if (wize < 0) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to write data");
        return FALSE;
    }

    if (wize > 0) {
        g_byte_array_remove_range(priv->wbuf, 0, wize);
    }

    if (priv->wbuf->len < 1) {
        priv->wev = 0;
        return FALSE;
    }

    return TRUE;
}

void
fb_mqtt_write(FbMqtt *mqtt, FbMqttMessage *msg)
{
    const GByteArray *bytes;
    FbMqttMessagePrivate *mriv;
    FbMqttPrivate *priv;
    gint fd;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
    priv = mqtt->priv;
    mriv = msg->priv;

    bytes = fb_mqtt_message_bytes(msg);

    if (G_UNLIKELY(bytes == NULL)) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to format data");
        return;
    }

    fb_util_debug_hexdump(FB_UTIL_DEBUG_LEVEL_INFO, mriv->bytes,
                          "Writing %d (flags: 0x%0X)",
                          mriv->type, mriv->flags);

    fd = ssl_getfd(priv->ssl);
    g_byte_array_append(priv->wbuf, bytes->data, bytes->len);

    if (fb_mqtt_cb_write(mqtt, fd, B_EV_IO_WRITE) && (priv->wev < 1)) {
        priv->wev = b_input_add(fd, B_EV_IO_WRITE, fb_mqtt_cb_write, mqtt);
    }
}

static gboolean
fb_mqtt_cb_open(gpointer data, gint error, gpointer ssl,
                b_input_condition cond)
{
    FbMqtt *mqtt = data;
    FbMqttPrivate *priv = mqtt->priv;
    gint fd;

    if ((ssl == NULL) || (error != SSL_OK)) {
        /* Set this to null to avoid freeing it in fb_mqtt_close() */
        priv->ssl = NULL;

        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Failed to connect");
        return FALSE;
    }

    fd = ssl_getfd(priv->ssl);
    fb_mqtt_timeout_clear(mqtt);
    priv->rev = b_input_add(fd, B_EV_IO_READ, fb_mqtt_cb_read, mqtt);
    g_signal_emit_by_name(mqtt, "open");
    return FALSE;
}

void
fb_mqtt_open(FbMqtt *mqtt, const gchar *host, gint port)
{
    FbMqttPrivate *priv;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    priv = mqtt->priv;

    fb_mqtt_close(mqtt);
    priv->ssl = ssl_connect((gchar *) host, port, TRUE, fb_mqtt_cb_open, mqtt);

    if (priv->ssl == NULL) {
        fb_mqtt_cb_open(mqtt, SSL_NOHANDSHAKE, NULL, 0);
        return;
    }

    fb_mqtt_timeout(mqtt);
}

void
fb_mqtt_connect(FbMqtt *mqtt, guint8 flags, const GByteArray *pload)
{
    FbMqttMessage *msg;

    g_return_if_fail(!fb_mqtt_connected(mqtt, FALSE));
    g_return_if_fail(pload != NULL);

    /* Facebook always sends a CONNACK, use QoS1 */
    flags |= FB_MQTT_CONNECT_FLAG_QOS1;

    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_CONNECT, 0);
    fb_mqtt_message_write_str(msg, FB_MQTT_NAME);   /* Protocol name */
    fb_mqtt_message_write_byte(msg, FB_MQTT_LEVEL); /* Protocol level */
    fb_mqtt_message_write_byte(msg, flags);         /* Flags */
    fb_mqtt_message_write_u16(msg, FB_MQTT_KA);     /* Keep alive */

    fb_mqtt_message_write(msg, pload->data, pload->len);
    fb_mqtt_write(mqtt, msg);

    fb_mqtt_timeout(mqtt);
    g_object_unref(msg);
}

gboolean
fb_mqtt_connected(FbMqtt *mqtt, gboolean error)
{
    FbMqttPrivate *priv;
    gboolean connected;

    g_return_val_if_fail(FB_IS_MQTT(mqtt), FALSE);
    priv = mqtt->priv;
    connected = (priv->ssl != NULL) && priv->connected;

    if (!connected && error) {
        fb_mqtt_error(mqtt, FB_MQTT_ERROR_GENERAL, "Not connected");
    }

    return connected;
}

void
fb_mqtt_disconnect(FbMqtt *mqtt)
{
    FbMqttMessage *msg;

    if (G_UNLIKELY(!fb_mqtt_connected(mqtt, FALSE))) {
        return;
    }

    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_DISCONNECT, 0);
    fb_mqtt_write(mqtt, msg);
    g_object_unref(msg);
    fb_mqtt_close(mqtt);
}

void
fb_mqtt_publish(FbMqtt *mqtt, const gchar *topic, const GByteArray *pload)
{
    FbMqttMessage *msg;
    FbMqttPrivate *priv;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
    priv = mqtt->priv;

    /* Message identifier not required, but for consistency use QoS1 */
    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_PUBLISH,
                              FB_MQTT_MESSAGE_FLAG_QOS1);

    fb_mqtt_message_write_str(msg, topic);      /* Message topic */
    fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */

    if (pload != NULL) {
        fb_mqtt_message_write(msg, pload->data, pload->len);
    }

    fb_mqtt_write(mqtt, msg);
    g_object_unref(msg);
}

void
fb_mqtt_subscribe(FbMqtt *mqtt, const gchar *topic1, guint16 qos1, ...)
{
    const gchar *topic;
    FbMqttMessage *msg;
    FbMqttPrivate *priv;
    guint16 qos;
    va_list ap;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
    priv = mqtt->priv;

    /* Facebook requires a message identifier, use QoS1 */
    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_SUBSCRIBE,
                              FB_MQTT_MESSAGE_FLAG_QOS1);

    fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */
    fb_mqtt_message_write_str(msg, topic1);     /* First topics */
    fb_mqtt_message_write_byte(msg, qos1);      /* First QoS value */

    va_start(ap, qos1);

    while ((topic = va_arg(ap, const gchar*)) != NULL) {
        qos = va_arg(ap, guint);
        fb_mqtt_message_write_str(msg, topic); /* Remaining topics */
        fb_mqtt_message_write_byte(msg, qos);  /* Remaining QoS values */
    }

    va_end(ap);

    fb_mqtt_write(mqtt, msg);
    g_object_unref(msg);
}

void
fb_mqtt_unsubscribe(FbMqtt *mqtt, const gchar *topic1, ...)
{
    const gchar *topic;
    FbMqttMessage *msg;
    FbMqttPrivate *priv;
    va_list ap;

    g_return_if_fail(FB_IS_MQTT(mqtt));
    g_return_if_fail(fb_mqtt_connected(mqtt, FALSE));
    priv = mqtt->priv;

    /* Facebook requires a message identifier, use QoS1 */
    msg = fb_mqtt_message_new(FB_MQTT_MESSAGE_TYPE_UNSUBSCRIBE,
                              FB_MQTT_MESSAGE_FLAG_QOS1);

    fb_mqtt_message_write_mid(msg, &priv->mid); /* Message identifier */
    fb_mqtt_message_write_str(msg, topic1);     /* First topic */

    va_start(ap, topic1);

    while ((topic = va_arg(ap, const gchar*)) != NULL) {
        fb_mqtt_message_write_str(msg, topic); /* Remaining topics */
    }

    va_end(ap);

    fb_mqtt_write(mqtt, msg);
    g_object_unref(msg);
}

FbMqttMessage *
fb_mqtt_message_new(FbMqttMessageType type, FbMqttMessageFlags flags)
{
    FbMqttMessage *msg;
    FbMqttMessagePrivate *priv;

    msg = g_object_new(FB_TYPE_MQTT_MESSAGE, NULL);
    priv = msg->priv;

    priv->type = type;
    priv->flags = flags;
    priv->bytes = g_byte_array_new();
    priv->local = TRUE;

    return msg;
}

FbMqttMessage *
fb_mqtt_message_new_bytes(GByteArray *bytes)
{
    FbMqttMessage *msg;
    FbMqttMessagePrivate *priv;
    guint8 *byte;

    g_return_val_if_fail(bytes != NULL, NULL);
    g_return_val_if_fail(bytes->len >= 2, NULL);

    msg = g_object_new(FB_TYPE_MQTT_MESSAGE, NULL);
    priv = msg->priv;

    priv->bytes = bytes;
    priv->local = FALSE;
    priv->type = (*bytes->data & 0xF0) >> 4;
    priv->flags = *bytes->data & 0x0F;

    /* Skip the fixed header */
    for (byte = priv->bytes->data + 1; (*(byte++) & 128) != 0; );
    priv->offset = byte - bytes->data;
    priv->pos = priv->offset;

    return msg;
}

void
fb_mqtt_message_reset(FbMqttMessage *msg)
{
    FbMqttMessagePrivate *priv;

    g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
    priv = msg->priv;

    if (priv->offset > 0) {
        g_byte_array_remove_range(priv->bytes, 0, priv->offset);
        priv->offset = 0;
        priv->pos = 0;
    }
}

const GByteArray *
fb_mqtt_message_bytes(FbMqttMessage *msg)
{
    FbMqttMessagePrivate *priv;
    guint i;
    guint8 byte;
    guint8 sbuf[4];
    guint32 size;

    g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), NULL);
    priv = msg->priv;

    i = 0;
    size = priv->bytes->len - priv->offset;

    do {
        if (G_UNLIKELY(i >= G_N_ELEMENTS(sbuf))) {
            return NULL;
        }

        byte = size % 128;
        size /= 128;

        if (size > 0) {
            byte |= 128;
        }

        sbuf[i++] = byte;
    } while (size > 0);

    fb_mqtt_message_reset(msg);
    g_byte_array_prepend(priv->bytes, sbuf, i);

    byte = ((priv->type & 0x0F) << 4) | (priv->flags & 0x0F);
    g_byte_array_prepend(priv->bytes, &byte, sizeof byte);

    priv->pos = (i + 1) * (sizeof byte);
    return priv->bytes;
}

gboolean
fb_mqtt_message_read(FbMqttMessage *msg, gpointer data, guint size)
{
    FbMqttMessagePrivate *priv;

    g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), FALSE);
    priv = msg->priv;

    if ((priv->pos + size) > priv->bytes->len) {
        return FALSE;
    }

    if ((data != NULL) && (size > 0)) {
        memcpy(data, priv->bytes->data + priv->pos, size);
    }

    priv->pos += size;
    return TRUE;
}

gboolean
fb_mqtt_message_read_r(FbMqttMessage *msg, GByteArray *bytes)
{
    FbMqttMessagePrivate *priv;
    guint size;

    g_return_val_if_fail(FB_IS_MQTT_MESSAGE(msg), FALSE);
    priv = msg->priv;
    size = priv->bytes->len - priv->pos;

    if (G_LIKELY(size > 0)) {
        g_byte_array_append(bytes, priv->bytes->data + priv->pos,
                            size);
    }

    return TRUE;
}

gboolean
fb_mqtt_message_read_byte(FbMqttMessage *msg, guint8 *value)
{
    return fb_mqtt_message_read(msg, value, sizeof *value);
}

gboolean
fb_mqtt_message_read_mid(FbMqttMessage *msg, guint16 *value)
{
    return fb_mqtt_message_read_u16(msg, value);
}

gboolean
fb_mqtt_message_read_u16(FbMqttMessage *msg, guint16 *value)
{
    if (!fb_mqtt_message_read(msg, value, sizeof *value)) {
        return FALSE;
    }

    if (value != NULL) {
        *value = g_ntohs(*value);
    }

    return TRUE;
}

gboolean
fb_mqtt_message_read_str(FbMqttMessage *msg, gchar **value)
{
    guint8 *data;
    guint16 size;

    if (!fb_mqtt_message_read_u16(msg, &size)) {
        return FALSE;
    }

    if (value != NULL) {
        data = g_new(guint8, size + 1);
        data[size] = 0;
    } else {
        data = NULL;
    }

    if (!fb_mqtt_message_read(msg, data, size)) {
        g_free(data);
        return FALSE;
    }

    if (value != NULL) {
        *value = (gchar *) data;
    }

    return TRUE;
}

void
fb_mqtt_message_write(FbMqttMessage *msg, gconstpointer data, guint size)
{
    FbMqttMessagePrivate *priv;

    g_return_if_fail(FB_IS_MQTT_MESSAGE(msg));
    priv = msg->priv;

    g_byte_array_append(priv->bytes, data, size);
    priv->pos += size;
}

void
fb_mqtt_message_write_byte(FbMqttMessage *msg, guint8 value)
{
    fb_mqtt_message_write(msg, &value, sizeof value);
}

void
fb_mqtt_message_write_mid(FbMqttMessage *msg, guint16 *value)
{
    g_return_if_fail(value != NULL);
    fb_mqtt_message_write_u16(msg, ++(*value));
}

void
fb_mqtt_message_write_u16(FbMqttMessage *msg, guint16 value)
{
    value = g_htons(value);
    fb_mqtt_message_write(msg, &value, sizeof value);
}

void
fb_mqtt_message_write_str(FbMqttMessage *msg, const gchar *value)
{
    gint16 size;

    g_return_if_fail(value != NULL);

    size = strlen(value);
    fb_mqtt_message_write_u16(msg, size);
    fb_mqtt_message_write(msg, value, size);
}

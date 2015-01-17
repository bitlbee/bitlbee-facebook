/*
 * Copyright 2014 James Geboski <jgeboski@gmail.com>
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

/** @file **/

#ifndef _FACEBOOK_MQTT_H
#define _FACEBOOK_MQTT_H

#include <glib.h>
#include <string.h>

#include "facebook-util.h"

#define FB_MQTT_NAME "MQIsdp"
#define FB_MQTT_VERS 3
#define FB_MQTT_KA   60
#define FB_MQTT_HOST "mqtt.facebook.com"
#define FB_MQTT_PORT 443

#define FB_MQTT_TIMEOUT_CONN (FB_MQTT_KA * 1500)
#define FB_MQTT_TIMEOUT_PING (FB_MQTT_KA * 1000)

/**
 * Executes one of the #fb_mqtt_funcs.
 *
 * @param m   The #fb_mqtt.
 * @param f   The function to execute.
 * @param ... The operational function arguments.
 **/
#define FB_MQTT_FUNC(m, f, ...)                    \
    G_STMT_START {                                 \
        if (G_LIKELY(m->funcs.f != NULL)) {        \
            m->funcs.f(m, ##__VA_ARGS__, m->data); \
        }                                          \
    } G_STMT_END


/** The flags of #fb_mqtt CONNECT packets. **/
typedef enum fb_mqtt_connect_flags fb_mqtt_connect_flags_t;

/** The #GError codes of #fb_mqtt. **/
typedef enum fb_mqtt_error fb_mqtt_error_t;

/** The flags of #fb_mqtt messages. **/
typedef enum fb_mqtt_msg_flags fb_mqtt_msg_flags_t;

/** The type of #fb_mqtt messages. **/
typedef enum fb_mqtt_msg_type fb_mqtt_msg_type_t;

/** The main structure for #fb_mqtt callback functions. **/
typedef struct fb_mqtt_funcs fb_mqtt_funcs_t;

/** The structure for interacting with Facebook MQTT. **/
typedef struct fb_mqtt fb_mqtt_t;

/** The structure of a #fb_mqtt message. **/
typedef struct fb_mqtt_msg fb_mqtt_msg_t;


/**
 * The flags of #fb_mqtt CONNECT packets.
 **/
enum fb_mqtt_connect_flags
{
    FB_MQTT_CONNECT_FLAG_CLR  = 1 << 1, /** Clear session. **/
    FB_MQTT_CONNECT_FLAG_WILL = 1 << 2, /** Will flag. **/
    FB_MQTT_CONNECT_FLAG_RET  = 1 << 5, /** Will retain. **/
    FB_MQTT_CONNECT_FLAG_PASS = 1 << 6, /** Password. **/
    FB_MQTT_CONNECT_FLAG_USER = 1 << 7, /** Username. **/
    FB_MQTT_CONNECT_FLAG_QOS0 = 0 << 3, /** Fire and forget. **/
    FB_MQTT_CONNECT_FLAG_QOS1 = 1 << 3, /** Acknowledge delivery. **/
    FB_MQTT_CONNECT_FLAG_QOS2 = 2 << 3  /** Assure delivery. **/
};

/**
 * The #GError codes of #fb_mqtt.
 **/
enum fb_mqtt_error
{
    FB_MQTT_ERROR_SUCCESS      = 0, /** Success. **/
    FB_MQTT_ERROR_PRTVERS      = 1, /** Unacceptable protocol version. **/
    FB_MQTT_ERROR_IDREJECT     = 2, /** Identifier rejected. **/
    FB_MQTT_ERROR_SRVGONE      = 3, /** Server unavailable. **/
    FB_MQTT_ERROR_USERPASS     = 4, /** Bad username or password. **/
    FB_MQTT_ERROR_UNAUTHORIZED = 5, /** Not authorized. **/
    FB_MQTT_ERROR_GENERAL           /** General. **/
};

/**
 * The flags of #fb_mqtt messages.
 **/
enum fb_mqtt_msg_flags
{
    FB_MQTT_MSG_FLAG_RET  = 1 << 0, /** Retain. **/
    FB_MQTT_MSG_FLAG_DUP  = 1 << 3, /** Duplicate delivery. **/
    FB_MQTT_MSG_FLAG_QOS0 = 0 << 1, /** Fire and forget. **/
    FB_MQTT_MSG_FLAG_QOS1 = 1 << 1, /** Acknowledge delivery. **/
    FB_MQTT_MSG_FLAG_QOS2 = 2 << 1  /** Assure delivery. **/
};

/**
 * The type of #fb_mqtt messages.
 **/
enum fb_mqtt_msg_type
{
    FB_MQTT_MSG_TYPE_CONNECT     = 1,  /** Connect to Server. **/
    FB_MQTT_MSG_TYPE_CONNACK     = 2,  /** Connect Acknowledgment. **/
    FB_MQTT_MSG_TYPE_PUBLISH     = 3,  /** Publish Message. **/
    FB_MQTT_MSG_TYPE_PUBACK      = 4,  /** Publish Acknowledgment. **/
    FB_MQTT_MSG_TYPE_PUBREC      = 5,  /** Publish Received. **/
    FB_MQTT_MSG_TYPE_PUBREL      = 6,  /** Publish Release. **/
    FB_MQTT_MSG_TYPE_PUBCOMP     = 7,  /** Publish Complete. **/
    FB_MQTT_MSG_TYPE_SUBSCRIBE   = 8,  /** Client Subscribe request. **/
    FB_MQTT_MSG_TYPE_SUBACK      = 9,  /** Subscribe Acknowledgment. **/
    FB_MQTT_MSG_TYPE_UNSUBSCRIBE = 10, /** Client Unsubscribe request. **/
    FB_MQTT_MSG_TYPE_UNSUBACK    = 11, /** Unsubscribe Acknowledgment. **/
    FB_MQTT_MSG_TYPE_PINGREQ     = 12, /** PING Request. **/
    FB_MQTT_MSG_TYPE_PINGRESP    = 13, /** PING Response. **/
    FB_MQTT_MSG_TYPE_DISCONNECT  = 14  /** Client is Disconnecting. **/
};

/**
 * The main structure for #fb_mqtt callback functions.
 **/
struct fb_mqtt_funcs
{
    /**
     * The error function. This is called whenever an error occurs
     * within the #fb_mqtt.
     *
     * @param mqtt The #fb_mqtt.
     * @param err  The #GError.
     * @param data The user-defined data or NULL.
     **/
    void (*error) (fb_mqtt_t *mqtt, GError *err, gpointer data);

    /**
     * The open function. This is called when the connection to the
     * MQTT has been initialized. This is called as a result of
     * #fb_mqtt_open(). This function should call #fb_mqtt_connect().
     *
     * @param mqtt The #fb_mqtt.
     * @param data The user-defined data or NULL.
     **/
    void (*open) (fb_mqtt_t *mqtt, gpointer data);

    /**
     * The connack function. This is called when a CONNACK packet is
     * received. This is called as a result of #fb_mqtt_connect().
     *
     * @param mqtt The #fb_mqtt.
     * @param data The user-defined data or NULL.
     **/
    void (*connack) (fb_mqtt_t *mqtt, gpointer data);

    /**
     * The publish function. This is called when a PUBLISH packet is
     * received.
     *
     * @param mqtt  The #fb_mqtt.
     * @param topic The message topic.
     * @param pload The message payload.
     * @param data  The user-defined data or NULL.
     **/
    void (*publish) (fb_mqtt_t *mqtt, const gchar *topic,
                     const GByteArray *pload, gpointer data);
};

/**
 * The structure for interacting with Facebook MQTT.
 **/
struct fb_mqtt
{
    gboolean  connected;   /** TRUE if connected, otherwise FALSE. **/

    fb_mqtt_funcs_t funcs; /** The #fb_mqtt_funcs. **/
    gpointer        data;  /** The user defined data or NULL. **/

    GError   *err;         /** The #GError or NULL. **/
    gpointer  ssl;         /** The SSL connection or NULL. **/
    gint      tev;         /** The timer event identifier. **/
    gint      rev;         /** The read event identifier. **/
    gint      wev;         /** The write event identifier. **/

    GByteArray *rbuf;      /** The read buffer. **/
    GByteArray *wbuf;      /** The write buffer. **/
    gsize       remz;      /** The remaining read size. **/

    guint16 mid;           /** The message identifier. **/
};

/**
 * The structure of a #fb_mqtt message.
 **/
struct fb_mqtt_msg
{
    fb_mqtt_msg_type_t  type;  /** The #fb_mqtt_msg_type. **/
    fb_mqtt_msg_flags_t flags; /** The #fb_mqtt_msg_flags. **/

    GByteArray *bytes;         /** The #GByteArray of data. **/
    guint       offset;        /** The offset of the data. **/
    guint       pos;           /** The cursor position. **/

    gboolean local;            /** TRUE if the data is local. **/
};


#define FB_MQTT_ERROR fb_mqtt_error_quark()

GQuark fb_mqtt_error_quark(void);

fb_mqtt_t *fb_mqtt_new(const fb_mqtt_funcs_t *funcs, gpointer data);

void fb_mqtt_free(fb_mqtt_t *mqtt);

void fb_mqtt_close(fb_mqtt_t *mqtt);

void fb_mqtt_error(fb_mqtt_t *mqtt, fb_mqtt_error_t err,
                   const gchar *fmt, ...);

void fb_mqtt_read(fb_mqtt_t *mqtt, fb_mqtt_msg_t *msg);

void fb_mqtt_write(fb_mqtt_t *mqtt, fb_mqtt_msg_t *msg);

void fb_mqtt_open(fb_mqtt_t *mqtt, const gchar *host, gint port);

void fb_mqtt_connect(fb_mqtt_t *mqtt, guint8 flags, const gchar *cid, ...)
    G_GNUC_NULL_TERMINATED;

gboolean fb_mqtt_connected(fb_mqtt_t *mqtt, gboolean error);

void fb_mqtt_disconnect(fb_mqtt_t *mqtt);

void fb_mqtt_publish(fb_mqtt_t *mqtt, const gchar *topic,
                     const GByteArray *bytes);

void fb_mqtt_subscribe(fb_mqtt_t *mqtt, const gchar *topic1, guint16 qos1, ...)
    G_GNUC_NULL_TERMINATED;

void fb_mqtt_unsubscribe(fb_mqtt_t *mqtt, const gchar *topic1, ...)
    G_GNUC_NULL_TERMINATED;

fb_mqtt_msg_t *fb_mqtt_msg_new(fb_mqtt_msg_type_t type,
                               fb_mqtt_msg_flags_t flags);

fb_mqtt_msg_t *fb_mqtt_msg_new_bytes(GByteArray *bytes);

void fb_mqtt_msg_free(fb_mqtt_msg_t *msg);

void fb_mqtt_msg_reset(fb_mqtt_msg_t *msg);

const GByteArray *fb_mqtt_msg_bytes(fb_mqtt_msg_t *msg);

gboolean fb_mqtt_msg_read(fb_mqtt_msg_t *msg, gpointer data, guint size);

gboolean fb_mqtt_msg_read_r(fb_mqtt_msg_t *msg, GByteArray *bytes);

gboolean fb_mqtt_msg_read_byte(fb_mqtt_msg_t *msg, guint8 *byte);

gboolean fb_mqtt_msg_read_mid(fb_mqtt_msg_t *msg, guint16 *mid);

gboolean fb_mqtt_msg_read_u16(fb_mqtt_msg_t *msg, guint16 *u16);

gboolean fb_mqtt_msg_read_str(fb_mqtt_msg_t *msg, gchar **str);

void fb_mqtt_msg_write(fb_mqtt_msg_t *msg, gconstpointer data, guint size);

void fb_mqtt_msg_write_byte(fb_mqtt_msg_t *msg, guint8 byte);

void fb_mqtt_msg_write_mid(fb_mqtt_msg_t *msg, guint16 *mid);

void fb_mqtt_msg_write_u16(fb_mqtt_msg_t *msg, guint16 u16);

void fb_mqtt_msg_write_str(fb_mqtt_msg_t *msg, const gchar *str);

#endif /* _FACEBOOK_MQTT_H */

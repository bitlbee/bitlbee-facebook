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

#ifndef _FACEBOOK_API_H
#define _FACEBOOK_API_H

#include <bitlbee.h>

#include "facebook-http.h"
#include "facebook-id.h"
#include "facebook-json.h"
#include "facebook-mqtt.h"

#define FB_API_HOST   "api.facebook.com"
#define FB_API_BHOST  "b-api.facebook.com"
#define FB_API_GHOST  "graph.facebook.com"
#define FB_API_AGENT  "Facebook App / " PACKAGE " / " PACKAGE_VERSION
#define FB_API_KEY    "256002347743983"
#define FB_API_SECRET "374e60f8b9bb6b8cbb30f78030438895"

#define FB_API_PATH_AUTH  "/method/auth.login"
#define FB_API_PATH_FQL   "/fql"
#define FB_API_PATH_GQL   "/graphql"
#define FB_API_PATH_PARTS "/participants"
#define FB_API_PATH_THRDS "/me/threads"
#define FB_API_PATH_TOPIC "/method/messaging.setthreadname"

#define FB_API_QRYID_CONTACTS  "10153122424521729"

/**
 * Executes one of the #fb_api_funcs.
 *
 * @param a   The #fb_api.
 * @param f   The function to execute.
 * @param ... The function arguments.
 **/
#define FB_API_FUNC(m, f, ...)                         \
    G_STMT_START {                                     \
        if (G_LIKELY((m)->funcs.f != NULL)) {          \
            (m)->funcs.f(m, ##__VA_ARGS__, (m)->data); \
        }                                              \
    } G_STMT_END

/**
 * Creates a message identifier.
 *
 * @param m The time in miliseconds (UTC).
 * @param i The random integer.
 *
 * @return The 64-bit message identifier.
 **/
#define FB_API_MSGID(m, i) ((guint64) ( \
        (((guint32) i) & 0x3FFFFF) |    \
        (((guint64) m) << 22)           \
    ))


/** The #GError codes of #fb_api. **/
typedef enum fb_api_error fb_api_error_t;

/** The structure for interacting with the Facebook API. **/
typedef struct fb_api fb_api_t;

/** The main structure for #fb_api callback functions. **/
typedef struct fb_api_funcs fb_api_funcs_t;

/** The structure for representing an #fb_api message. **/
typedef struct fb_api_msg fb_api_msg_t;

/** The structure for representing an #fb_api presence. **/
typedef struct fb_api_pres fb_api_pres_t;

/** The structure for representing an #fb_api thread. **/
typedef struct fb_api_thread fb_api_thread_t;

/** The structure for representing an #fb_api user typing state. **/
typedef struct fb_api_typing fb_api_typing_t;

/** The structure for representing an #fb_api user. **/
typedef struct fb_api_user fb_api_user_t;


/**
 * The #GError codes of #fb_api.
 **/
enum fb_api_error
{
    FB_API_ERROR_GENERAL /** General **/
};

/**
 * The main structure for #fb_api callback functions.
 **/
struct fb_api_funcs
{
    /**
     * The error function. This is called whenever an error occurs
     * within the #fb_api.
     *
     * @param api  The #fb_api.
     * @param err  The #GError.
     * @param data The user-defined data or NULL.
     **/
    void (*error) (fb_api_t *api, GError *err, gpointer data);

    /**
     * The auth function. This is called whenever authentication has
     * been successfully completed. This is called as a result of
     * #fb_api_auth().
     *
     * @param api  The #fb_api.
     * @param data The user-defined data or NULL.
     **/
    void (*auth) (fb_api_t *api, gpointer data);

    /**
     * The connect function. This is called whenever the #fb_api has
     * been successfully connected. This connects to the MQTT service.
     * This is called as a result of #fb_api_connect().
     *
     * @param api  The #fb_api.
     * @param data The user-defined data or NULL.
     **/
    void (*connect) (fb_api_t *api, gpointer data);

    /**
     * The contacts function. This is called whenever the #fb_api has
     * retrieved a set contacts. This is called as a result of
     * #fb_api_contacts().
     *
     * @param api   The #fb_api.
     * @param users The #GSList of #fb_api_user.
     * @param data  The user-defined data or NULL.
     **/
    void (*contacts) (fb_api_t *api, GSList *users, gpointer data);

    /**
     * The message function. This is called whenever the #fb_api has
     * retrieved a message.
     *
     * @param api  The #fb_api.
     * @param msgs The #GSList of #fb_api_msg.
     * @param data The user-defined data or NULL.
     **/
    void (*message) (fb_api_t *api, GSList *msgs, gpointer data);

    /**
     * The presence function. This is called whenever the #fb_api has
     * retrieved a presence update.
     *
     * @param api   The #fb_api.
     * @param press The #GSList of #fb_api_pres.
     * @param data  The user-defined data or NULL.
     **/
    void (*presence) (fb_api_t *api, GSList *press, gpointer data);

    /**
     * The thread_create function. This is called whenever the #fb_api
     * has created a thread. This is called as a result of
     * #fb_api_thread_create().
     *
     * @param api  The #fb_api.
     * @param tid  The thread #fb_id.
     * @param data The user-defined data or NULL.
     **/
    void (*thread_create) (fb_api_t *api, fb_id_t tid, gpointer data);

    /**
     * The thread_info function. This is called whenever the #fb_api
     * has retrieved thread information. This is called as a result of
     * #fb_api_thread_info().
     *
     * @param api  The #fb_api.
     * @param thrd The #fb_api_thread.
     * @param data The user-defined data or NULL.
     **/
    void (*thread_info) (fb_api_t *api, fb_api_thread_t *thrd, gpointer data);

    /**
     * The thread_list function. This is called whenever the #fb_api
     * has retrieved a set of threads. This is called as a result of
     * #fb_api_thread_list().
     *
     * @param api   The #fb_api.
     * @param thrds The #GSList of #fb_api_thread.
     * @param data  The user-defined data or NULL.
     **/
    void (*thread_list) (fb_api_t *api, GSList *thrds, gpointer data);

    /**
     * The typing function. This is called whenever the #fb_api has
     * retrieved a typing state update.
     *
     * @param api  The #fb_api.
     * @param typg The #fb_api_typing.
     * @param data The user-defined data or NULL.
     **/
    void (*typing) (fb_api_t *api, fb_api_typing_t *typg, gpointer data);
};

/**
 * The structure for interacting with the Facebook API.
 **/
struct fb_api
{
    fb_api_funcs_t funcs; /** The #fb_api_funcs. **/
    gpointer       data;  /** The user-defined data or NULL. **/

    fb_http_t *http;      /** The #fb_http. **/
    fb_mqtt_t *mqtt;      /** The #fb_mqtt. **/
    GError    *err;       /** The #GError or NULL. **/

    fb_id_t  uid;        /** The The #fb_id of the user. **/
    gchar   *token;      /** The session token. **/
    gchar   *stoken;     /** The sync token. **/
    gchar   *cid;        /** The client identifier. **/
    gchar   *mid;        /** The MQTT identifier. **/
    gchar   *cuid;       /** The client unique identifier. **/
};

/**
 * The structure for representing an #fb_api message.
 **/
struct fb_api_msg
{
    fb_id_t      uid;  /** The #fb_id of the user. **/
    fb_id_t      tid;  /** The #fb_id of the thread. **/
    const gchar *text; /** The message text. **/
};

/**
 * The structure for representing an #fb_api presence.
 **/
struct fb_api_pres
{
    fb_id_t  uid;    /** The #fb_id of the user. **/
    gboolean active; /** TRUE if the user is active. **/
};

/**
 * The structure for representing an #fb_api thread.
 **/
struct fb_api_thread
{
    fb_id_t      tid;   /** The #fb_id of the thread. **/
    const gchar *topic; /** The topic of the thread or NULL. **/
    GSList      *users; /** The #GList of #fb_api_user. **/
};

/**
 * The structure for representing an #fb_api user typing state.
 **/
struct fb_api_typing
{
    fb_id_t  uid;   /** The #fb_id of the user. **/
    gboolean state; /** TRUE if the user is typing. **/
};

/**
 * The structure for representing an #fb_api user.
 **/
struct fb_api_user
{
    fb_id_t      uid;  /** The #fb_id of the user. **/
    const gchar *name; /** The name of the user. **/
};


#define FB_API_ERROR fb_api_error_quark()

GQuark fb_api_error_quark(void);

fb_api_t *fb_api_new(const fb_api_funcs_t *funcs, gpointer data);

void fb_api_rehash(fb_api_t *api);

void fb_api_free(fb_api_t *api);

void fb_api_error(fb_api_t *api, fb_api_error_t err, const gchar *fmt, ...)
    G_GNUC_PRINTF(3, 4);

void fb_api_auth(fb_api_t *api, const gchar *user, const gchar *pass);

void fb_api_contacts(fb_api_t *api);

void fb_api_connect(fb_api_t *api);

void fb_api_disconnect(fb_api_t *api);

void fb_api_message(fb_api_t *api, fb_id_t id, gboolean thread,
                    const gchar *msg);

void fb_api_publish(fb_api_t *api, const gchar *topic, const gchar *fmt, ...)
    G_GNUC_PRINTF(3, 4);

void fb_api_thread_create(fb_api_t *api, GSList *uids);

void fb_api_thread_info(fb_api_t *api, fb_id_t tid);

void fb_api_thread_invite(fb_api_t *api, fb_id_t tid, fb_id_t uid);

void fb_api_thread_list(fb_api_t *api, guint limit);

void fb_api_thread_topic(fb_api_t *api, fb_id_t tid, const gchar *topic);

void fb_api_typing(fb_api_t *api, fb_id_t uid, gboolean state);

#endif /* _FACEBOOK_API_H */

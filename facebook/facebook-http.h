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

#ifndef _FACEBOOK_HTTP_H
#define _FACEBOOK_HTTP_H

#include <glib.h>
#include <http_client.h>


#define FB_HTTP_CLIENT_FREED   (1 << 31)
#define FB_HTTP_RESEND_MAX     3
#define FB_HTTP_RESEND_TIMEOUT 2000


/**
 * Creates a #fb_http_pair in-line.
 *
 * @param k The key.
 * @param v The value.
 *
 * @return The resulting fb_http_pair.
 **/
#define FB_HTTP_PAIR(k, v) ((fb_http_pair_t *) &((fb_http_pair_t) {k, v}))


/** The #GError codes of #fb_http. **/
typedef enum fb_http_error fb_http_error_t;

/** The flags of #fb_http_req. **/
typedef enum fb_http_req_flags fb_http_req_flags_t;

/** The structure for managing #fb_http_req. **/
typedef struct fb_http fb_http_t;

/** The structure for key/value pairs of strings. **/
typedef struct fb_http_pair fb_http_pair_t;

/** The structure for a #fb_http request. **/
typedef struct fb_http_req fb_http_req_t;


/**
 * The type of callback for #fb_http_req operations.
 *
 * @param req  The #fb_http_req.
 * @param data The user defined data or NULL.
 **/
typedef void (*fb_http_func_t) (fb_http_req_t *req, gpointer data);


/**
 * The #GError codes of #fb_http.
 **/
enum fb_http_error
{
    FB_HTTP_ERROR_CLOSED = 1, /** Closed **/
    FB_HTTP_ERROR_INIT,       /** Initializing **/
    FB_HTTP_ERROR_TIMEOUT,    /** Timeout **/
};

/**
 * The flags of #fb_http_req.
 **/
enum fb_http_req_flags
{
    FB_HTTP_REQ_FLAG_GET  = 1 << 0, /** Use the GET method **/
    FB_HTTP_REQ_FLAG_POST = 1 << 1, /** Use the POST method **/
    FB_HTTP_REQ_FLAG_SSL  = 1 << 2  /** Use encryption via SSL **/
};

/**
 * The structure for managing #fb_http_req.
 **/
struct fb_http
{
    gchar      *agent;   /** The agent. **/
    GHashTable *cookies; /** The #GHashTable of cookies. **/
    GHashTable *reqs;    /** The #GHashTable of #fb_http_req. **/
};

/**
 * The structure for key/value pairs of strings.
 **/
struct fb_http_pair
{
    const gchar *key; /** The key. **/
    const gchar *val; /** The value. **/
};

/**
 * he structure for a #fb_http request.
 **/
struct fb_http_req
{
    fb_http_t           *http;    /** The #fb_http. **/
    fb_http_req_flags_t  flags;   /** The #fb_http_req_flags. **/

    gchar *host;                  /** The hostname. **/
    gint   port;                  /** The port number. **/
    gchar *path;                  /** The pathname. **/
    gint   timeout;               /** The timeout. **/

    GHashTable *headers;          /** The #GHashTable of headers. **/
    GHashTable *params;           /** The #GHashTable of parameters. **/

    fb_http_func_t func;          /** The user callback function or NULL. **/
    gpointer       data;          /** The user define data or NULL. **/

    struct http_request *request; /** The underlying #http_request. **/

    GError *err;                  /** The #GError or NULL. **/
    gchar  *status;               /** Shortcut to request->status_string. **/
    gint    scode;                /** Shortcut to request->status_code. **/
    gchar  *header;               /** Shortcut to request->reply_headers. **/
    gchar  *body;                 /** Shortcut to request->reply_body. **/
    gint    body_size;            /** Shortcut to request->body_size. **/

    gint   toid;                  /** The event ID for the timeout. **/
    guint8 rsc;                   /** The resend count. **/
};


#define FB_HTTP_ERROR fb_http_error_quark()

GQuark fb_http_error_quark(void);

fb_http_t *fb_http_new(const gchar *agent);

void fb_http_free_reqs(fb_http_t *http);

void fb_http_free(fb_http_t *http);

void fb_http_cookies_set(fb_http_t *http, const fb_http_pair_t *pair, ...)
    G_GNUC_NULL_TERMINATED;

void fb_http_cookies_parse_req(fb_http_t *http, const fb_http_req_t *req);

void fb_http_cookies_parse_str(fb_http_t *http, const gchar *data);

gchar *fb_http_cookies_str(fb_http_t *http);

fb_http_req_t *fb_http_req_new(fb_http_t *http, const gchar *host,
                               gint port, const gchar *path,
                               fb_http_func_t func, gpointer data);

void fb_http_req_free(fb_http_req_t *req);

void fb_http_req_headers_set(fb_http_req_t *req, const fb_http_pair_t *pair,
                             ...) G_GNUC_NULL_TERMINATED;

void fb_http_req_params_set(fb_http_req_t *req, const fb_http_pair_t *pair,
                            ...) G_GNUC_NULL_TERMINATED;

void fb_http_req_send(fb_http_req_t *req);

gchar *fb_http_uri_escape(const gchar *unescaped);

gchar *fb_http_uri_unescape(const gchar *escaped);

#endif /* _FACEBOOK_HTTP_H */

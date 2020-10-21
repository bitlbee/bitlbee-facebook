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
#include <string.h>
#include <url.h>

#include "facebook-http.h"
#include "facebook-util.h"

struct _FbHttpPrivate
{
    FbHttpValues *cookies;
    GHashTable *reqs;
    gchar *agent;
};

struct _FbHttpRequestPrivate
{
    FbHttp *http;
    gchar *url;
    url_t purl;
    gboolean post;

    FbHttpValues *headers;
    FbHttpValues *params;

    FbHttpFunc func;
    gpointer data;

    GError *error;
    struct http_request *request;
    gboolean freed;
};

G_DEFINE_TYPE_WITH_PRIVATE(FbHttp, fb_http, G_TYPE_OBJECT);
G_DEFINE_TYPE_WITH_PRIVATE(FbHttpRequest, fb_http_request, G_TYPE_OBJECT);

static void
fb_http_dispose(GObject *obj)
{
    FbHttp *http = FB_HTTP(obj);
    FbHttpPrivate *priv = http->priv;

    g_free(priv->agent);
    fb_http_close_requests(http);
    g_hash_table_destroy(priv->reqs);
    fb_http_values_free(priv->cookies);
}

static void
fb_http_class_init(FbHttpClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    gklass->dispose = fb_http_dispose;
}

static void
fb_http_init(FbHttp *http)
{
    FbHttpPrivate *priv;

    priv = fb_http_get_instance_private(http);
    http->priv = priv;

    priv->cookies = fb_http_values_new();
    priv->reqs = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void
fb_http_req_close_nuller(struct http_request *request)
{

}

static void
fb_http_request_dispose(GObject *obj)
{
    FbHttpRequestPrivate *priv = FB_HTTP_REQUEST(obj)->priv;

    if ((priv->request != NULL) && !priv->freed) {
        /* Prevent more than one call to request->func() */
        priv->request->func = fb_http_req_close_nuller;
        priv->request->data = NULL;
        http_close(priv->request);
    }

    if (priv->error != NULL) {
        g_error_free(priv->error);
    }

    g_free(priv->url);
    fb_http_values_free(priv->headers);
    fb_http_values_free(priv->params);
}

static void
fb_http_request_class_init(FbHttpRequestClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    gklass->dispose = fb_http_request_dispose;
}

static void
fb_http_request_init(FbHttpRequest *req)
{
    FbHttpRequestPrivate *priv;

    priv = fb_http_request_get_instance_private(req);
    req->priv = priv;

    priv->headers = fb_http_values_new();
    priv->params = fb_http_values_new();
}

GQuark
fb_http_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("fb-http-error-quark");

    return q;
}

FbHttp *
fb_http_new(const gchar *agent)
{
    FbHttp *http;
    FbHttpPrivate *priv;

    http = g_object_new(FB_TYPE_HTTP, NULL);
    priv = http->priv;
    priv->agent = g_strdup(agent);
    return http;
}

FbHttpValues *
fb_http_get_cookies(FbHttp *http)
{
    FbHttpPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP(http), NULL);
    priv = http->priv;

    return priv->cookies;
}

void
fb_http_close_requests(FbHttp *http)
{
    FbHttpPrivate *priv;
    FbHttpRequest *req;
    GHashTableIter iter;

    g_return_if_fail(FB_IS_HTTP(http));
    priv = http->priv;

    g_hash_table_iter_init(&iter, priv->reqs);

    while (g_hash_table_iter_next(&iter, (gpointer) &req, NULL)) {
        g_hash_table_iter_remove(&iter);
        g_object_unref(req);
    }
}

void
fb_http_cookies_parse_request(FbHttp *http, FbHttpRequest *req)
{
    FbHttpPrivate *hriv;
    FbHttpRequestPrivate *priv;
    gchar **hdrs;
    gchar **kv;
    gchar *str;
    guint i;
    guint j;

    g_return_if_fail(FB_IS_HTTP(http));
    g_return_if_fail(FB_IS_HTTP_REQUEST(req));
    hriv = http->priv;
    priv = req->priv;

    if (priv->request == NULL) {
        return;
    }

    hdrs = g_strsplit(priv->request->reply_headers, "\r\n", 0);

    for (i = 0; hdrs[i] != NULL; i++) {
        if (g_ascii_strncasecmp(hdrs[i], "Set-Cookie", 10) != 0) {
            continue;
        }

        str = strchr(hdrs[i], ';');

        if (str != NULL) {
            str[0] = 0;
        }

        str = strchr(hdrs[i], ':');

        if (str == NULL) {
            continue;
        }

        str = g_strstrip(++str);
        kv  = g_strsplit(str, "=", 2);

        for (j = 0; kv[j] != NULL; j++) {
            str = g_uri_unescape_string(kv[j], NULL);
            g_free(kv[j]);
            kv[j] = str;
        }

        if (g_strv_length(kv) > 1) {
            fb_http_values_set_str(hriv->cookies, kv[0], kv[1]);
        }

        g_strfreev(kv);
    }

    g_strfreev(hdrs);
}

void
fb_http_set_agent(FbHttp *http, const gchar *agent)
{
    FbHttpPrivate *priv;

    g_return_if_fail(FB_IS_HTTP(http));
    priv = http->priv;

    if (agent != priv->agent && g_strcmp0(agent, priv->agent)) {
        g_free(priv->agent);
        priv->agent = g_strdup(agent);
    }
}

FbHttpRequest *
fb_http_request_new(FbHttp *http, const gchar *url, gboolean post,
                    FbHttpFunc func, gpointer data)
{
    FbHttpPrivate *hriv;
    FbHttpRequest *req;
    FbHttpRequestPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP(http), NULL);
    g_return_val_if_fail(url != NULL, NULL);
    g_return_val_if_fail(func != NULL, NULL);

    req = g_object_new(FB_TYPE_HTTP_REQUEST, NULL);
    priv = req->priv;
    hriv = http->priv;

    if (!url_set(&priv->purl, url)) {
        g_object_unref(req);
        return NULL;
    }

    priv->http = http;
    priv->url = g_strdup(url);
    priv->post = post;
    priv->func = func;
    priv->data = data;

    if (hriv->agent != NULL) {
        fb_http_values_set_str(priv->headers, "User-Agent", hriv->agent);
    }

    fb_http_values_set_str(priv->headers, "Host", priv->purl.host);
    fb_http_values_set_str(priv->headers, "Accept", "*/*");
    fb_http_values_set_str(priv->headers, "Connection", "Close");

    return req;
}

const gchar *
fb_http_request_get_data(FbHttpRequest *req, gsize *size)
{
    FbHttpRequestPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP_REQUEST(req), NULL);
    priv = req->priv;

    if (priv->request == NULL) {
        if (size != NULL) {
            *size = 0;
        }

        return NULL;
    }

    if (size != NULL) {
        *size = priv->request->body_size;
    }

    return priv->request->reply_body;
}

FbHttpValues *
fb_http_request_get_headers(FbHttpRequest *req)
{
    FbHttpRequestPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP_REQUEST(req), NULL);
    priv = req->priv;

    return priv->headers;
}

FbHttpValues *
fb_http_request_get_params(FbHttpRequest *req)
{
    FbHttpRequestPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP_REQUEST(req), NULL);
    priv = req->priv;

    return priv->params;
}

const gchar *
fb_http_request_get_status(FbHttpRequest *req, gint *code)
{
    FbHttpRequestPrivate *priv;

    g_return_val_if_fail(FB_IS_HTTP_REQUEST(req), NULL);
    priv = req->priv;

    if (priv->request == NULL) {
        if (code != NULL) {
            *code = 0;
        }

        return NULL;
    }

    if (code != NULL) {
        *code = priv->request->status_code;
    }

    return priv->request->status_string;
}

GError *
fb_http_request_take_error(FbHttpRequest *req)
{
    FbHttpRequestPrivate *priv;
    GError *err;

    g_return_val_if_fail(FB_IS_HTTP_REQUEST(req), NULL);
    priv = req->priv;

    err = priv->error;
    priv->error = NULL;

    return err;
}

static void
fb_http_request_debug(FbHttpRequest *req, gboolean response,
                      const gchar *header, const gchar *body)
{
    const gchar *action;
    const gchar *method;
    const gchar *status;
    FbHttpRequestPrivate *priv = req->priv;
    gchar **lines;
    gchar *str;
    gint code;
    guint i;

    status = fb_http_request_get_status(req, &code);
    action = response ? "Response" : "Request";
    method = priv->post ? "POST" : "GET";

    if (status != NULL) {
        str = g_strdup_printf(" (%s)", status);
    } else if (response) {
        str = g_strdup_printf(" (%d)", code);
    } else {
        str = g_strdup("");
    }

    fb_util_debug_info("%s %s (%p): %s%s",
                       method, action, req,
                       priv->url, str);
    g_free(str);

    if ((header != NULL) && (strlen(header) > 0)) {
        lines = g_strsplit(header, "\n", 0);

        for (i = 0; lines[i] != NULL; i++) {
            fb_util_debug_info("  %s", lines[i]);
        }

        g_strfreev(lines);
    } else {
        fb_util_debug_info("  ** No header data **");
        fb_util_debug_info("%s", "");
    }

    if ((body != NULL) && (strlen(body) > 0)) {
        lines = g_strsplit(body, "\n", 0);

        for (i = 0; lines[i] != NULL; i++) {
            fb_util_debug_info("  %s", lines[i]);
        }

        g_strfreev(lines);
    } else {
        fb_util_debug_info("  ** No body data **");
    }
}

static void
fb_http_request_cb(struct http_request *request)
{
    const gchar *status;
    FbHttpRequest *req = request->data;
    FbHttpRequestPrivate *priv = req->priv;
    gint code;

    status = fb_http_request_get_status(req, &code);
    g_hash_table_remove(priv->http->priv->reqs, req);
    priv->freed = TRUE;

    switch (code) {
    case 200:
    case 301:
    case 302:
    case 303:
    case 307:
        break;

    default:
        g_set_error(&priv->error, FB_HTTP_ERROR, code, "%s", status);
    }

    fb_http_request_debug(req, TRUE, priv->request->reply_headers,
                          priv->request->reply_body);

    if (G_LIKELY(priv->func != NULL)) {
        priv->func(req, priv->data);
    }

    g_object_unref(req);
}

void
fb_http_request_send(FbHttpRequest *req)
{
    FbHttpPrivate *hriv;
    FbHttpRequestPrivate *priv;
    gchar *hdrs;
    gchar *prms;
    gchar *str;
    gsize size;

    g_return_if_fail(FB_IS_HTTP_REQUEST(req));
    priv = req->priv;
    hriv = priv->http->priv;

    if (g_hash_table_size(hriv->cookies) > 0) {
        str = fb_http_values_str_cookies(hriv->cookies);
        fb_http_values_set_str(priv->headers, "Cookie", str);
        g_free(str);
    }

    prms = fb_http_values_str_params(priv->params, NULL);

    if (priv->post) {
        size = strlen(prms);
        fb_http_values_set_strf(priv->headers, "Content-Length",
                                "%" G_GSIZE_FORMAT, size);
        fb_http_values_set_str(priv->headers, "Content-Type",
                               "application/x-www-form-urlencoded");
    }

    hdrs = fb_http_values_str_headers(priv->headers);

    if (priv->post) {
        str = g_strdup_printf("POST %s HTTP/1.1\r\n%s\r\n%s",
                              priv->purl.file, hdrs, prms);
    } else {
        str = g_strdup_printf("GET %s?%s HTTP/1.1\r\n%s\r\n",
                              priv->purl.file, prms, hdrs);
    }

    fb_http_request_debug(req, FALSE, hdrs, prms);
    priv->request = http_dorequest(priv->purl.host, priv->purl.port,
                                   priv->purl.proto == PROTO_HTTPS,
                                   str, fb_http_request_cb, req);

    g_free(hdrs);
    g_free(prms);
    g_free(str);

    if (G_UNLIKELY(priv->request == NULL)) {
        g_set_error(&priv->error, FB_HTTP_ERROR, FB_HTTP_ERROR_INIT,
                    "Failed to init request");

        if (G_LIKELY(priv->func != NULL)) {
            priv->func(req, priv->data);
        }

        g_object_unref(req);
        return;
    }

    g_hash_table_replace(hriv->reqs, req, req);
}

gboolean
fb_http_urlcmp(const gchar *url1, const gchar *url2, gboolean protocol)
{
    gboolean ret;
    url_t purl1;
    url_t purl2;

    if ((url1 == NULL) || (url2 == NULL)) {
        return url1 == url2;
    }

    if (strstr(url1, url2) != NULL || strstr(url2, url1) != NULL) {
        return TRUE;
    }

    if (!url_set(&purl1, url1) || !url_set(&purl2, url2)) {
        return g_ascii_strcasecmp(url1, url2) == 0;
    }

    ret = (g_ascii_strcasecmp(purl1.host, purl2.host) == 0) &&
          (g_strcmp0(purl1.file, purl2.file) == 0) &&
          (g_strcmp0(purl1.user, purl2.user) == 0) &&
          (g_strcmp0(purl1.pass, purl2.pass) == 0);

    if (ret && protocol) {
        ret = (purl1.proto == purl2.proto) && (purl1.port == purl2.port);
    }

    return ret;
}

static gboolean
fb_http_value_equal(gconstpointer a, gconstpointer b)
{
    return g_ascii_strcasecmp(a, b) == 0;
}

FbHttpValues *
fb_http_values_new(void)
{
        return g_hash_table_new_full(g_str_hash, fb_http_value_equal,
                                     g_free, g_free);
}

void
fb_http_values_free(FbHttpValues *values)
{
    g_hash_table_destroy(values);
}

void
fb_http_values_consume(FbHttpValues *values, FbHttpValues *consume)
{
    GHashTableIter iter;
    gpointer key;
    gpointer val;

    g_hash_table_iter_init(&iter, consume);

    while (g_hash_table_iter_next(&iter, &key, &val)) {
        g_hash_table_iter_steal(&iter);
        g_hash_table_replace(values, key, val);
    }

    g_hash_table_destroy(consume);
}

void
fb_http_values_parse(FbHttpValues *values, const gchar *data, gboolean isurl)
{
    const gchar *tail;
    gchar *key;
    gchar **params;
    gchar *val;
    guint i;

    g_return_if_fail(data != NULL);

    if (isurl) {
        data = strchr(data, '?');

        if (data == NULL) {
            return;
        }

        tail = strchr(++data, '#');

        if (tail != NULL) {
            data = g_strndup(data, tail - data);
        } else {
            data = g_strdup(data);
        }
    }

    params = g_strsplit(data, "&", 0);

    for (i = 0; params[i] != NULL; i++) {
        key = params[i];
        val = strchr(params[i], '=');

        if (val == NULL) {
            continue;
        }

        *(val++) = 0;
        key = g_uri_unescape_string(key, NULL);
        val = g_uri_unescape_string(val, NULL);
        g_hash_table_replace(values, key, val);
    }

    if (isurl) {
        g_free((gchar *) data);
    }

    g_strfreev(params);
}

gchar *
fb_http_values_str_cookies(FbHttpValues *values)
{
    GHashTableIter iter;
    gchar *key;
    gchar *val;
    GString *ret;

    ret = g_string_new(NULL);
    g_hash_table_iter_init(&iter, values);

    while (g_hash_table_iter_next(&iter, (gpointer) &key, (gpointer) &val)) {
        if (val == NULL) {
            val = "";
        }

        if (ret->len > 0) {
            g_string_append(ret, "; ");
        }

        g_string_append_uri_escaped(ret, key, NULL, TRUE);
        g_string_append_c(ret, '=');
        g_string_append_uri_escaped(ret, val, NULL, TRUE);
    }

    return g_string_free(ret, FALSE);
}

gchar *
fb_http_values_str_headers(FbHttpValues *values)
{
    GHashTableIter iter;
    gchar *key;
    gchar *val;
    GString *ret;

    ret = g_string_new(NULL);
    g_hash_table_iter_init(&iter, values);

    while (g_hash_table_iter_next(&iter, (gpointer) &key, (gpointer) &val)) {
        if (val == NULL) {
            val = "";
        }

        g_string_append_printf(ret, "%s: %s\r\n", key, val);
    }

    return g_string_free(ret, FALSE);
}

gchar *
fb_http_values_str_params(FbHttpValues *values, const gchar *url)
{
    GHashTableIter iter;
    gchar *key;
    gchar *val;
    GString *ret;

    ret = g_string_new(NULL);
    g_hash_table_iter_init(&iter, values);

    while (g_hash_table_iter_next(&iter, (gpointer) &key, (gpointer) &val)) {
        if (val == NULL) {
            val = "";
        }

        if (ret->len > 0) {
            g_string_append_c(ret, '&');
        }

        g_string_append_uri_escaped(ret, key, NULL, TRUE);
        g_string_append_c(ret, '=');
        g_string_append_uri_escaped(ret, val, NULL, TRUE);
    }

    if (url != NULL) {
        g_string_prepend_c(ret, '?');
        g_string_prepend(ret, url);
    }

    return g_string_free(ret, FALSE);
}

gboolean
fb_http_values_remove(FbHttpValues *values, const gchar *name)
{
    return g_hash_table_remove(values, name);
}

GList *
fb_http_values_get_keys(FbHttpValues *values)
{
    return g_hash_table_get_keys(values);
}

static const gchar *
fb_http_values_get(FbHttpValues *values, const gchar *name, GError **error)
{
    const gchar *ret;

    ret = g_hash_table_lookup(values, name);

    if (ret == NULL) {
        g_set_error(error, FB_HTTP_ERROR, FB_HTTP_ERROR_NOMATCH,
                    "No matches for %s", name);
        return NULL;
    }

    return ret;
}

gboolean
fb_http_values_get_bool(FbHttpValues *values, const gchar *name,
                       GError **error)
{
    const gchar *val;

    val = fb_http_values_get(values, name, error);

    if (val == NULL) {
        return FALSE;
    }

    return bool2int((gchar *) name);
}

gdouble
fb_http_values_get_dbl(FbHttpValues *values, const gchar *name,
                      GError **error)
{
    const gchar *val;

    val = fb_http_values_get(values, name, error);

    if (val == NULL) {
        return 0.0;
    }

    return g_ascii_strtod(val, NULL);
}

gint64
fb_http_values_get_int(FbHttpValues *values, const gchar *name,
                       GError **error)
{
    const gchar *val;

    val = fb_http_values_get(values, name, error);

    if (val == NULL) {
        return 0;
    }

    return g_ascii_strtoll(val, NULL, 10);
}


const gchar *
fb_http_values_get_str(FbHttpValues *values, const gchar *name,
                       GError **error)
{
    return fb_http_values_get(values, name, error);
}

gchar *
fb_http_values_dup_str(FbHttpValues *values, const gchar *name,
                       GError **error)
{
    const gchar *str;

    str = fb_http_values_get_str(values, name, error);
    return g_strdup(str);
}

static void
fb_http_values_set(FbHttpValues *values, const gchar *name, gchar *value)
{
    gchar *key;

    key = g_strdup(name);
    g_hash_table_replace(values, key, value);
}

void
fb_http_values_set_bool(FbHttpValues *values, const gchar *name,
                        gboolean value)
{
    gchar *val;

    val = g_strdup(value ? "true" : "false");
    fb_http_values_set(values, name, val);
}

void
fb_http_values_set_dbl(FbHttpValues *values, const gchar *name, gdouble value)
{
    gchar *val;

    val = g_strdup_printf("%f", value);
    fb_http_values_set(values, name, val);
}

void
fb_http_values_set_int(FbHttpValues *values, const gchar *name, gint64 value)
{
    gchar *val;

    val = g_strdup_printf("%" G_GINT64_FORMAT, value);
    fb_http_values_set(values, name, val);
}

void
fb_http_values_set_str(FbHttpValues *values, const gchar *name,
                       const gchar *value)
{
    gchar *val;

    val = g_strdup(value);
    fb_http_values_set(values, name, val);
}

void
fb_http_values_set_strf(FbHttpValues *values, const gchar *name,
                        const gchar *format, ...)
{
    gchar *val;
    va_list ap;

    va_start(ap, format);
    val = g_strdup_vprintf(format, ap);
    va_end(ap);

    fb_http_values_set(values, name, val);
}

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

#include <string.h>

#include "facebook-api.h"

/**
 * Gets the error domain for #fb_api.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark fb_api_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("fb-api-error-quark");

    return q;
}

/**
 * Creates a new #fb_api. The returned #fb_api should be freed with
 * #fb_api_free() when no longer needed.
 *
 * @param funcs The #fb_api_funcs.
 * @param data  The user-defined data or NULL.
 *
 * @return The #fb_api or NULL on error.
 **/
fb_api_t *fb_api_new(const fb_api_funcs_t *funcs, gpointer data)
{
    fb_api_t *api;

    g_return_val_if_fail(funcs != NULL, NULL);

    api = g_new0(fb_api_t, 1);
    memcpy(&api->funcs, funcs, sizeof *funcs);
    api->data = data;
    api->http = fb_http_new(FB_API_AGENT);

    return api;
}

/**
 * Frees all memory used by a #fb_api.
 *
 * @param api The #fb_api.
 **/
void fb_api_free(fb_api_t *api)
{
    if (G_UNLIKELY(api == NULL))
        return;

    if (api->err != NULL)
        g_error_free(api->err);

    fb_http_free(api->http);

    g_free(api->token);
    g_free(api);
}

/**
 * Handles an error within an #fb_api. This sets #fb_api->err and calls
 * the error function. If the fmt argument is NULL, then #fb_api->err
 * is handled.
 *
 * @param api The #fb_api.
 * @param err The #fb_api_error.
 * @param fmt The format string or NULL.
 * @param ... The arguments of the format string.
 **/
void fb_api_error(fb_api_t *api, fb_api_error_t err, const gchar *fmt, ...)
{
    gchar   *str;
    va_list  ap;

    g_return_if_fail(api != NULL);

    if (fmt != NULL) {
        va_start(ap, fmt);
        str = g_strdup_vprintf(fmt, ap);
        va_end(ap);

        g_clear_error(&api->err);
        g_set_error_literal(&api->err, FB_API_ERROR, err, str);
        g_free(str);
    }

    if (api->err != NULL)
        FB_API_FUNC(api, error, api->err);
}

/**
 * Creates a new #json_value for JSON contents of the #fb_api. This
 * function is special in that it handles all errors, unlike the parent
 * function #fb_json_new(). The returned #json_value should be freed
 * with #json_value_free() when no longer needed.
 *
 * @param api  The #fb_api.
 * @param data The data.
 * @param size The size of the data.
 *
 * @return TRUE if the data was parsed without error, otherwise FALSE.
 **/
static json_value *fb_api_json_new(fb_api_t *api, const gchar *data,
                                   gsize size)
{
    json_value  *json;
    const gchar *msg;
    gint64       code;

    json = fb_json_new(data, size, &api->err);

    if (api->err != NULL) {
        fb_api_error(api, 0, NULL);
        return NULL;
    }

    if (fb_json_int_chk(json, "error_code", &code)) {
        if (!fb_json_str_chk(json, "error_msg", &msg))
            msg = "Generic Error";

        fb_api_error(api, FB_API_ERROR_GENERAL, "%s", msg);
        json_value_free(json);
        return NULL;
    }

    return json;
}

/**
 * Creates a new #fb_http_req for a #fb_api request.
 *
 * @param api    The #fb_api.
 * @param host   The host.
 * @param path   The path.
 * @param func   The #fb_http_func.
 * @param class  The class.
 * @param name   The friendly name.
 * @param method The method.
 **/
static fb_http_req_t *fb_api_req_new(fb_api_t *api, const gchar *host,
                                     const gchar *path, fb_http_func_t func,
                                     const gchar *class, const gchar *name,
                                     const gchar *method)
{
    fb_http_req_t *req;

    req = fb_http_req_new(api->http, host, 443, path, func, api);
    req->flags = FB_HTTP_REQ_FLAG_POST | FB_HTTP_REQ_FLAG_SSL;

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("api_key",                  FB_API_KEY),
        FB_HTTP_PAIR("fb_api_caller_class",      class),
        FB_HTTP_PAIR("fb_api_req_friendly_name", name),
        FB_HTTP_PAIR("method",                   method),
        FB_HTTP_PAIR("client_country_code",      "US"),
        FB_HTTP_PAIR("format",                   "json"),
        FB_HTTP_PAIR("locale",                   "en_US"),
        NULL
    );

    return req;
}

/**
 * Sends a #fb_http_req for a #fb_api. This computes the signature for
 * the request and sets the "sig" parameter. This sets the OAuth header
 * for authorization.
 *
 * @param api The #fb_api.
 * @param req The #fb_http_req.
 **/
static void fb_api_req_send(fb_api_t *api, fb_http_req_t *req)
{
    GString     *gstr;
    GList       *keys;
    GList       *l;
    const gchar *key;
    const gchar *val;
    gchar       *hash;
    gchar       *auth;

    /* Ensure an old signature is not computed */
    g_hash_table_remove(req->params, "sig");

    gstr = g_string_sized_new(128);
    keys = g_hash_table_get_keys(req->params);
    keys = g_list_sort(keys, (GCompareFunc) g_ascii_strcasecmp);

    for (l = keys; l != NULL; l = l->next) {
        key = l->data;
        val = g_hash_table_lookup(req->params, key);
        g_string_append_printf(gstr, "%s=%s", key, val);
    }

    g_string_append(gstr, FB_API_SECRET);
    hash = g_compute_checksum_for_string(G_CHECKSUM_MD5, gstr->str, gstr->len);

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("sig", hash),
        NULL
    );

    g_free(hash);
    g_list_free(keys);
    g_string_free(gstr, TRUE);

    if (api->token != NULL) {
        auth = g_strdup_printf("OAuth %s", api->token);
        fb_http_req_headers_set(req,
            FB_HTTP_PAIR("Authorization", auth),
            NULL
        );
        g_free(auth);
    }

    fb_http_req_send(req);
}

/**
 * Implemented #fb_http_func for #fb_api_auth().
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_auth(fb_http_req_t *req, gpointer data)
{
    fb_api_t    *api = data;
    json_value  *json;
    const gchar *str;

    json = fb_api_json_new(api, req->body, req->body_size);

    if (json == NULL)
        return;

    if (!fb_json_str_chk(json, "access_token", &str)) {
        fb_api_error(api, FB_API_ERROR_GENERAL, "Failed to obtain token");
        goto finish;
    }

    g_free(api->token);
    api->token = g_strdup(str);
    FB_API_FUNC(api, auth);

finish:
    json_value_free(json);
}

/**
 * Sends a authentication request.
 *
 * @param api  The #fb_api.
 * @param user The username (email).
 * @param pass The password.
 **/
void fb_api_auth(fb_api_t *api, const gchar *user, const gchar *pass)
{
    fb_http_req_t *req;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_BHOST, FB_API_PATH_AUTH,
                         fb_api_cb_auth,
                         "com.facebook.auth.protocol.d",
                         "authenticate",
                         "auth.login");

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("email",    user),
        FB_HTTP_PAIR("password", pass),
        NULL
    );

    fb_api_req_send(api, req);
}

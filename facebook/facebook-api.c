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

#include <stdarg.h>
#include <string.h>
#include <sha1.h>

#include "facebook-api.h"
#include "facebook-thrift.h"

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
 * Creates a new #json_value for JSON contents of the #fb_api. This
 * function is special in that it handles all errors, unlike the parent
 * function #fb_json_new(). The returned #json_value should be freed
 * with #json_value_free() when no longer needed.
 *
 * @param api  The #fb_api.
 * @param data The data.
 * @param size The size of the data.
 * @param json The return location for the json_value.
 *
 * @return TRUE if the data was parsed without error, otherwise FALSE.
 **/
static gboolean fb_api_json_new(fb_api_t *api, const gchar *data, gsize size,
                                json_value **json)
{
    json_value  *jv;
    const gchar *msg;
    gint64       code;

    jv = fb_json_new(data, size, &api->err);

    if (G_UNLIKELY(api->err != NULL)) {
        fb_api_error(api, 0, NULL);
        return FALSE;
    }

    if (fb_json_int_chk(jv, "error_code", &code)) {
        if (!fb_json_str_chk(jv, "error_msg", &msg))
            msg = "Generic Error";

        fb_api_error(api, FB_API_ERROR_GENERAL, "%s", msg);
        json_value_free(jv);
        return FALSE;
    } else if (fb_json_str_chk(jv, "errorCode", &msg)) {
        if ((g_ascii_strcasecmp(msg, "ERROR_QUEUE_NOT_FOUND") == 0) ||
            (g_ascii_strcasecmp(msg, "ERROR_QUEUE_LOST") == 0))
        {
            g_free(api->stoken);
            api->stoken = NULL;
        }

        fb_api_error(api, FB_API_ERROR_GENERAL, "%s", msg);
        json_value_free(jv);
        return FALSE;
    }

    *json = jv;
    return TRUE;
}

/**
 * Checks an #fb_http_req for errors.
 *
 * @param api The #fb_api.
 * @param req The #fb_http_req.
 *
 * @return TRUE if no errors were found, otherwise FALSE.
 **/
static gboolean fb_api_http_chk(fb_api_t *api, fb_http_req_t *req)
{
    if (G_UNLIKELY(api->err != NULL)) {
        fb_api_error(api, 0, NULL);
        return FALSE;
    }

    if (req->err != NULL) {
        api->err = g_error_copy(req->err);
        fb_api_error(api, 0, NULL);
        return FALSE;
    }

    return TRUE;
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
 * Implemented #fb_http_func for simple boolean error checking.
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_http_bool(fb_http_req_t *req, gpointer data)
{
    fb_api_t *api = data;

    if (!fb_api_http_chk(api, req))
        return;

    if (bool2int(req->body) == 0)
        fb_api_error(api, FB_API_ERROR, "Failed generic API operation");
}


/**
 * Implements #fb_mqtt_funcs->error().
 *
 * @param mqtt The #fb_mqtt.
 * @param err  The #GError.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_mqtt_error(fb_mqtt_t *mqtt, GError *err, gpointer data)
{
    fb_api_t *api = data;

    if (api->err == NULL) {
        api->err = g_error_copy(err);
        fb_api_error(api, 0, NULL);
    }
}

/**
 * Implements #fb_mqtt_funcs->open().
 *
 * @param mqtt The #fb_mqtt.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_mqtt_open(fb_mqtt_t *mqtt, gpointer data)
{
    fb_api_t *api = data;
    gchar    *msg;

    static guint8 flags =
        FB_MQTT_CONNECT_FLAG_USER |
        FB_MQTT_CONNECT_FLAG_PASS |
        FB_MQTT_CONNECT_FLAG_CLR;

    msg = g_strdup_printf("{"
            "\"u\":\"%" FB_ID_FORMAT "\","
            "\"a\":\"" FB_API_AGENT "\","
            "\"mqtt_sid\":%s,"
            "\"d\":\"%s\","
            "\"chat_on\":true,"
            "\"no_auto_fg\":true,"
            "\"fg\":false,"
            "\"pf\":\"jz\","
            "\"nwt\":1,"
            "\"nwst\":0"
        "}", api->uid, api->mid, api->cuid);

    fb_mqtt_connect(mqtt,
        flags,      /* Flags */
        api->cid,   /* Client identifier */
        msg,        /* Will message */
        api->token, /* Username */
        NULL);

    g_free(msg);
}

/**
 * Implemented #fb_http_func for the sequence identifier.
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_seqid(fb_http_req_t *req, gpointer data)
{
    fb_api_t    *api = data;
    json_value  *json;
    json_value  *jv;
    const gchar *str;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    /* Scattered values lead to a gnarly conditional... */
    if (!fb_json_val_chk(json, "data", json_array, &jv) ||

        /* Obtain the first array element */
        (jv->u.array.length != 1) ||
        ((jv = jv->u.array.values[0]) == NULL) ||

        /* Check the name */
        !fb_json_str_chk(jv, "name", &str) ||
        (g_ascii_strcasecmp(str, "thread_list_ids") != 0) ||

        /* Obtain the sequence identifier */
        !fb_json_val_chk(jv, "fql_result_set", json_array, &jv) ||
        (jv->u.array.length != 1) ||
        !fb_json_str_chk(jv->u.array.values[0], "sync_sequence_id", &str))
    {
        fb_api_error(api, FB_API_ERROR, "Failed to obtain SequenceID");
        goto finish;
    }

    if (api->stoken == NULL) {
        fb_api_publish(api, "/messenger_sync_create_queue", "{"
                "\"device_params\":{},"
                "\"encoding\":\"JSON\","
                "\"max_deltas_able_to_process\":1250,"
                "\"initial_titan_sequence_id\":%s,"
                "\"sync_api_version\":2,"
                "\"delta_batch_size\":125,"
                "\"device_id\":\"%s\""
            "}", str, api->cuid);

        goto finish;
    }

    fb_api_publish(api, "/messenger_sync_get_diffs", "{"
            "\"encoding\":\"JSON\","
            "\"last_seq_id\":%s,"
            "\"max_deltas_able_to_process\":1250,"
            "\"sync_api_version\":2,"
            "\"sync_token\":\"%s\","
            "\"delta_batch_size\":125"
        "}", str, api->stoken);

    FB_API_FUNC(api, connect);

finish:
    json_value_free(json);
}

/**
 * Implements #fb_mqtt_funcs->connack().
 *
 * @param mqtt The #fb_mqtt.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_mqtt_connack(fb_mqtt_t *mqtt, gpointer data)
{
    fb_api_t      *api = data;
    fb_http_req_t *req;

    fb_api_publish(api, "/foreground_state", "{"
            "\"foreground\": true,"
            "\"keepalive_timeout\": %d"
        "}", FB_MQTT_KA);

    fb_mqtt_subscribe(mqtt,
        "/inbox", 0,
        "/mercury", 0,
        "/messaging_events", 0,
        "/orca_presence", 0,
        "/orca_typing_notifications", 0,
        "/pp", 0,
        "/t_ms", 0,
        "/t_p", 0,
        "/t_rtc", 0,
        "/webrtc", 0,
        "/webrtc_response", 0,
        NULL
    );

    /* Notifications seem to lead to some sort of sending rate limit */
    fb_mqtt_unsubscribe(mqtt, "/orca_message_notifications", NULL);

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_FQL,
                         fb_api_cb_seqid,
                         "com.facebook.orca.protocol.methods.u",
                         "fetchThreadList",
                         "GET");

    static const gchar *query = "{"
        "\"thread_list_ids\":\""
            "SELECT sync_sequence_id "
                "FROM unified_thread "
                "WHERE folder='inbox' "
                "ORDER BY sync_sequence_id "
                "DESC LIMIT 1\""
        "}";

    fb_http_req_params_set(req, FB_HTTP_PAIR("q", query), NULL);
    fb_api_req_send(api, req);
}

/**
 * Handles typing notifications which are to be published to the user.
 *
 * @param api   The #fb_api.
 * @param pload The message payload.
 **/
static void fb_api_cb_publish_tn(fb_api_t *api, const GByteArray *pload)
{
    json_value      *json;
    fb_api_typing_t  typg;
    const gchar     *str;
    gint64           uid;
    gint64           state;

    if (!fb_api_json_new(api, (gchar*) pload->data, pload->len, &json))
        return;

    if (!fb_json_str_chk(json, "type", &str) ||
        (g_ascii_strcasecmp(str, "typ") != 0))
    {
        goto finish;
    }

    if (!fb_json_int_chk(json, "sender_fbid", &uid) ||
        !fb_json_int_chk(json, "state", &state))
    {
        fb_api_error(api, FB_API_ERROR, "Failed to obtain typing state");
        goto finish;
    }

    typg.uid   = uid;
    typg.state = state;
    FB_API_FUNC(api, typing, &typg);

finish:
    json_value_free(json);
}

/**
 * Handles messages which are to be published to the user.
 *
 * @param api   The #fb_api.
 * @param pload The message payload.
 **/
static void fb_api_cb_publish_ms(fb_api_t *api, const GByteArray *pload)
{
    GSList       *msgs;
    fb_api_msg_t  msg;
    fb_thrift_t  *thft;
    json_value   *json;
    json_value   *jv;
    json_value   *jx;
    json_value   *jy;
    json_value   *jz;
    const gchar  *str;
    gint64        in;
    guint         i;

    thft = fb_thrift_new((GByteArray*) pload, 0, TRUE);
    fb_thrift_read_str(thft, NULL);
    i = thft->pos;
    fb_thrift_free(thft);

    g_return_if_fail(i < pload->len);

    if (!fb_api_json_new(api, (gchar*) pload->data + i, pload->len - i, &json))
        return;

    msgs = NULL;

    if (fb_json_str_chk(json, "syncToken", &str)) {
        g_free(api->stoken);
        api->stoken = g_strdup(str);
        FB_API_FUNC(api, connect);
        goto finish;
    }

    if (!fb_json_val_chk(json, "deltas", json_array, &jv))
        goto finish;

    for (i = 0; i < jv->u.array.length; i++) {
        jx = jv->u.array.values[i];

        if (!fb_json_val_chk(jx, "deltaNewMessage", json_object, &jy) ||
            !fb_json_val_chk(jy, "messageMetadata", json_object, &jz) ||
            !fb_json_int_chk(jz, "actorFbId", &in) ||
            (in == api->uid))
        {
            continue;
        }

        msg.uid = in;
        msg.tid = 0;

        if (fb_json_val_chk(jz, "threadKey", json_object, &jz) &&
            fb_json_int_chk(jz, "threadFbId", &in))
        {
            msg.tid = in;
        }

        if (fb_json_str_chk(jy, "body", &str)) {
            msg.text = str;
            msgs = g_slist_prepend(msgs, g_memdup(&msg, sizeof msg));
        }

        if (fb_json_val_chk(jy, "attachments", json_array, &jy) &&
            (jy->u.array.length > 0))
        {
            msg.text = "* Non-Displayable Attachments *";
            msgs = g_slist_prepend(msgs, g_memdup(&msg, sizeof msg));
        }
    }

    msgs = g_slist_reverse(msgs);
    FB_API_FUNC(api, message, msgs);

finish:
    g_slist_free_full(msgs, g_free);
    json_value_free(json);
}

/**
 * Handles a presence states which are to be published to the user.
 *
 * @param api   The #fb_api.
 * @param pload The message payload.
 **/
static void fb_api_cb_publish_p(fb_api_t *api, const GByteArray *pload)
{
    fb_thrift_t      *thft;
    fb_thrift_type_t  type;
    fb_api_pres_t     pres;
    GSList           *press;
    gint64            i64;
    gint32            i32;
    guint             size;
    guint             i;

    /* Start at 1 to skip the NULL byte */
    thft  = fb_thrift_new((GByteArray*) pload, 1, TRUE);
    press = NULL;

    /* Skip the full list boolean field */
    fb_thrift_read_field(thft, &type, NULL);
    g_warn_if_fail(type == FB_THRIFT_TYPE_BOOL);
    fb_thrift_read_bool(thft, NULL);

    /* Read the list field */
    fb_thrift_read_field(thft, &type, NULL);
    g_warn_if_fail(type == FB_THRIFT_TYPE_LIST);

    /* Read the list */
    fb_thrift_read_list(thft, &type, &size);
    g_warn_if_fail(type == FB_THRIFT_TYPE_STRUCT);

    for (i = 0; i < size; i++) {
        /* Read the user identifier field */
        fb_thrift_read_field(thft, &type, NULL);
        g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
        fb_thrift_read_i64(thft, &i64);

        /* Read the active field */
        fb_thrift_read_field(thft, &type, NULL);
        g_warn_if_fail(type == FB_THRIFT_TYPE_I32);
        fb_thrift_read_i32(thft, &i32);

        pres.uid    = i64;
        pres.active = i32 != 0;
        press = g_slist_prepend(press, g_memdup(&pres, sizeof pres));
        FB_UTIL_DEBUGLN("Presence: %" FB_ID_FORMAT " (%d)", i64, i32 != 0);

        /* Skip the last active timestamp field */
        if (!fb_thrift_read_field(thft, &type, NULL))
            continue;

        g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
        fb_thrift_read_i64(thft, NULL);

        /* Skip the active client bits field */
        if (!fb_thrift_read_field(thft, &type, NULL))
            continue;

        g_warn_if_fail(type == FB_THRIFT_TYPE_I16);
        fb_thrift_read_i16(thft, NULL);

        /* Skip the VoIP compatibility bits field */
        if (!fb_thrift_read_field(thft, &type, NULL))
            continue;

        g_warn_if_fail(type == FB_THRIFT_TYPE_I64);
        fb_thrift_read_i64(thft, NULL);

        /* Read the field stop */
        fb_thrift_read_stop(thft);
    }

    /* Read the field stop */
    fb_thrift_read_stop(thft);
    fb_thrift_free(thft);

    press = g_slist_reverse(press);
    FB_API_FUNC(api, presence, press);
    g_slist_free_full(press, g_free);
}

/**
 * Implements #fb_mqtt_funcs->publish(().
 *
 * @param mqtt  The #fb_mqtt.
 * @param topic The message topic.
 * @param pload The message payload.
 * @param data  The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_mqtt_publish(fb_mqtt_t *mqtt, const gchar *topic,
                                   const GByteArray *pload, gpointer data)
{
    fb_api_t   *api = data;
    GByteArray *bytes;
    gboolean    comp;

    comp = fb_util_zcompressed(pload);

    if (G_LIKELY(comp)) {
        bytes = fb_util_zuncompress(pload);

        if (G_UNLIKELY(bytes == NULL)) {
            fb_api_error(api, FB_API_ERROR, "Failed to decompress");
            return;
        }
    } else {
        bytes = (GByteArray*) pload;
    }

    fb_util_hexdump(bytes, 2, "Reading message (topic: %s):", topic);

    if (g_ascii_strcasecmp(topic, "/orca_typing_notifications") == 0)
        fb_api_cb_publish_tn(api, bytes);
    else if (g_ascii_strcasecmp(topic, "/t_ms") == 0)
        fb_api_cb_publish_ms(api, bytes);
    else if (g_ascii_strcasecmp(topic, "/t_p") == 0)
        fb_api_cb_publish_p(api, bytes);

    if (G_LIKELY(comp))
        g_byte_array_free(bytes, TRUE);
}

/**
 * Creates a new #fb_api. The returned #fb_api should be freed with
 * #fb_api_free() when no longer needed.
 *
 * @param funcs The #fb_api_funcs.
 * @param data  The user-defined data or NULL.
 * @param cid   The client identifier or NULL.
 * @param mid   The MQTT identifier or NULL.
 * @param cuid  The client unique identifier or NULL.
 *
 * @return The #fb_api or NULL on error.
 **/
fb_api_t *fb_api_new(const fb_api_funcs_t *funcs, gpointer data)
{
    fb_api_t *api;

    static const fb_mqtt_funcs_t muncs = {
        .error   = fb_api_cb_mqtt_error,
        .open    = fb_api_cb_mqtt_open,
        .connack = fb_api_cb_mqtt_connack,
        .publish = fb_api_cb_mqtt_publish
    };

    g_return_val_if_fail(funcs != NULL, NULL);

    api = g_new0(fb_api_t, 1);
    memcpy(&api->funcs, funcs, sizeof *funcs);
    api->data = data;
    api->http = fb_http_new(FB_API_AGENT);
    api->mqtt = fb_mqtt_new(&muncs, api);

    return api;
}

/**
 * Rehashes the internal settings of a #fb_api.
 *
 * @param api The #fb_api.
 **/
void fb_api_rehash(fb_api_t *api)
{
    sha1_state_t sha;
    guint8       rb[50];

    if (api->cid == NULL) {
        random_bytes(rb, sizeof rb);
        api->cid = g_compute_checksum_for_data(G_CHECKSUM_MD5, rb, sizeof rb);
    }

    if (api->mid == 0)
        api->mid = g_strdup_printf("%" G_GUINT32_FORMAT, g_random_int());

    if (api->cuid == NULL) {
        sha1_init(&sha);
        random_bytes(rb, sizeof rb);
        sha1_append(&sha, rb, sizeof rb);
        api->cuid = sha1_random_uuid(&sha);
    }

    if (strlen(api->cid) > 20) {
        api->cid = g_realloc_n(api->cid , 21, sizeof *api->cid);
        api->cid[20] = 0;
    }
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

    fb_mqtt_free(api->mqtt);
    fb_http_free(api->http);

    g_free(api->cuid);
    g_free(api->mid);
    g_free(api->cid);
    g_free(api->stoken);
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
    gint64       in;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    if (!fb_json_int_chk(json, "uid", &in) ||
        !fb_json_str_chk(json, "access_token", &str))
    {
        fb_api_error(api, FB_API_ERROR_GENERAL, "Failed to obtain user info");
        goto finish;
    }

    g_free(api->token);
    api->token = g_strdup(str);

    api->uid = in;
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

/**
 * Implemented #fb_http_func for #fb_api_contacts().
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_contacts(fb_http_req_t *req, gpointer data)
{
    fb_api_t      *api = data;
    GSList        *users;
    fb_api_user_t  user;
    json_value    *json;
    json_value    *jv;
    json_value    *jx;
    json_value    *jy;
    json_value    *jz;
    const gchar   *str;
    const gchar   *uid;
    const gchar   *name;
    guint          i;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    users = NULL;

    if (!fb_json_val_chk(json, "viewer",             json_object, &jv) ||
        !fb_json_val_chk(jv,   "messenger_contacts", json_object, &jv) ||
        !fb_json_val_chk(jv,   "nodes",              json_array,  &jv))
    {
        fb_api_error(api, FB_API_ERROR_GENERAL, "Failed to parse contacts");
        goto finish;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        jx = jv->u.array.values[i];

        /* Scattered values lead to a gnarly conditional... */
        if (!fb_json_val_chk(jx, "represented_profile", json_object, &jy) ||

            /* Check the contact type is "user" */
            !fb_json_val_chk(jy, "__type__", json_object, &jz) ||
            !fb_json_str_chk(jz, "name", &str) ||
            (g_ascii_strcasecmp(str, "user") != 0) ||

            /* Check the contact is a friend */
            !fb_json_str_chk(jy, "friendship_status", &str) ||
            (g_ascii_strcasecmp(str, "ARE_FRIENDS") != 0) ||

            /* Obtain the contact user identifier */
            !fb_json_str_chk(jy, "id", &uid) ||

            /* Obtain the name of the user */
            !fb_json_val_chk(jx, "structured_name", json_object, &jy) ||
            !fb_json_str_chk(jy, "text", &name))
        {
            continue;
        }

        user.uid = FB_ID_FROM_STR(uid);

        if (user.uid != api->uid) {
            user.name = name;
            users = g_slist_prepend(users, g_memdup(&user, sizeof user));
        }
    }

    FB_API_FUNC(api, contacts, users);

finish:
    g_slist_free_full(users, g_free);
    json_value_free(json);
}

/**
 * Sends a contacts request.
 *
 * @param api  The #fb_api.
 **/
void fb_api_contacts(fb_api_t *api)
{
    fb_http_req_t *req;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_GQL,
                         fb_api_cb_contacts,
                         "com.facebook.contacts.service.d",
                         "FetchContactsFullQuery",
                         "get");

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("query_id",     FB_API_QRYID_CONTACTS),
        FB_HTTP_PAIR("query_params", "{}"),
        NULL
    );

    fb_api_req_send(api, req);
}

/**
 * Connects the #fb_api to the remote services. This is mainly for
 * connecting and setting up the internal #fb_mqtt.
 *
 * @param The #fb_api.
 **/
void fb_api_connect(fb_api_t *api)
{
    g_return_if_fail(api != NULL);

    fb_mqtt_open(api->mqtt, FB_MQTT_HOST, FB_MQTT_PORT);
}

/**
 * Disconnects the #fb_api from the remote services. This is mainly for
 * disconnecting the internal #fb_mqtt. This will close the internal
 * #fb_mqtt via #fb_mqtt_close().
 *
 * @param The #fb_api.
 **/
void fb_api_disconnect(fb_api_t *api)
{
    g_return_if_fail(api != NULL);

    fb_mqtt_disconnect(api->mqtt);
}

/**
 * Sends a message to a user.
 *
 * @param api    The #fb_api.
 * @param id     The #fb_id of the user.
 * @param thread TRUE to send to a thread identifier, otherwise FALSE.
 * @param msg    The message.
 **/
void fb_api_message(fb_api_t *api, fb_id_t id, gboolean thread,
                    const gchar *msg)
{
    guint64      msgid;
    const gchar *tpfx;
    gchar       *escaped;

    g_return_if_fail(api != NULL);
    g_return_if_fail(msg != NULL);

    msgid = FB_API_MSGID(g_get_real_time() / 1000, g_random_int());
    tpfx  = thread ? "tfbid_" : "";

    escaped = fb_json_str_escape(msg);

    fb_api_publish(api, "/send_message2", "{"
            "\"body\":\"%s\","
            "\"to\":\"%s%" FB_ID_FORMAT "\","
            "\"sender_fbid\":\"%" FB_ID_FORMAT "\","
            "\"msgid\":%" G_GUINT64_FORMAT
        "}", escaped, tpfx, id, api->uid, msgid);

    g_free(escaped);
}

/**
 * Publishes a string based message to the MQTT service. This enables
 * compression of the message via zlib.
 *
 * @param api   The #fb_api.
 * @param topic The message topic.
 * @param fmt   The format string.
 * @param ...   The format arguments.
 **/
void fb_api_publish(fb_api_t *api, const gchar *topic, const gchar *fmt, ...)
{
    GByteArray *bytes;
    GByteArray *cytes;
    gchar      *msg;
    va_list     ap;

    g_return_if_fail(api   != NULL);
    g_return_if_fail(topic != NULL);
    g_return_if_fail(fmt   != NULL);

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    bytes = g_byte_array_new_take((guint8*) msg, strlen(msg));
    cytes = fb_util_zcompress(bytes);

    fb_util_hexdump(bytes, 2, "Writing message:");
    fb_mqtt_publish(api->mqtt, topic, cytes);

    g_byte_array_free(cytes, TRUE);
    g_byte_array_free(bytes, TRUE);
}

/**
 * Implemented #fb_http_func for #fb_api_thread_create().
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_thread_create(fb_http_req_t *req, gpointer data)
{
    fb_api_t    *api = data;
    json_value  *json;
    const gchar *str;
    fb_id_t      tid;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    if (!fb_json_str_chk(json, "thread_fbid", &str)) {
        fb_api_error(api, FB_API_ERROR, "Failed to create thread");
        goto finish;
    }

    tid = FB_ID_FROM_STR(str);
    FB_API_FUNC(api, thread_create, tid);

finish:
    json_value_free(json);
}

/**
 * Sends a thread creation request.
 *
 * @param api  The #fb_api.
 * @param uids The #GSList of #fb_id.
 **/
void fb_api_thread_create(fb_api_t *api, GSList *uids)
{
    fb_http_req_t *req;
    GSList        *cids;
    GSList        *l;
    GString       *to;
    fb_id_t       *uid;

    g_return_if_fail(api != NULL);
    g_warn_if_fail((uids != NULL) && (uids->next != NULL));

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_THRDS,
                         fb_api_cb_thread_create,
                         "ccom.facebook.orca.send.service.l",
                         "createThread",
                         "POST");

    to   = g_string_new(NULL);
    cids = g_slist_copy(uids);
    cids = g_slist_prepend(cids, &api->uid);

    for (l = cids; l != NULL; l = l->next) {
        uid = l->data;

        if (to->len > 0)
            g_string_append_c(to, ',');

        g_string_append_printf(to, "{"
                "\"type\":\"id\","
                "\"id\":\"%" FB_ID_FORMAT "\""
            "}", *uid);
    }

    g_string_prepend_c(to, '[');
    g_string_append_c(to, ']');

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("to", to->str),
        NULL
    );

    fb_api_req_send(api, req);
    g_string_free(to, TRUE);
    g_slist_free(cids);
}

/**
 * Implemented #fb_http_func for #fb_api_thread().
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_thread_info(fb_http_req_t *req, gpointer data)
{
    fb_api_t        *api = data;
    fb_api_thread_t  thrd;
    fb_api_user_t    user;
    json_value      *json;
    json_value      *jv;
    json_value      *jx;
    gpointer         mptr;
    const gchar     *str;
    guint            i;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    /* Scattered values lead to a gnarly conditional... */
    if (!fb_json_val_chk(json, "data", json_array, &jv) ||

        /* Obtain the first array element */
        (jv->u.array.length != 1) ||
        ((jv = jv->u.array.values[0]) == NULL) ||

        /* Check the name */
        !fb_json_str_chk(jv, "name", &str) ||
        (g_ascii_strcasecmp(str, "threads") != 0) ||

        /* Obtain result array */
        !fb_json_val_chk(jv, "fql_result_set", json_array, &jv) ||
        (jv->u.array.length != 1) ||
        ((jv = jv->u.array.values[0]) == NULL) ||

        /* Obtain the thread identifier */
        !fb_json_str_chk(jv, "thread_fbid", &str))
    {
        fb_api_error(api, FB_API_ERROR, "Failed to fetch thread info");
        goto finish;
    }

    thrd.tid   = FB_ID_FROM_STR(str);
    thrd.topic = NULL;
    thrd.users = NULL;

    if (fb_json_str_chk(jv, "name", &str) && (strlen(str) > 0))
        thrd.topic = str;

    if (fb_json_val_chk(jv, "participants", json_array, &jv)) {
        for (i = 0; i < jv->u.array.length; i++) {
            jx = jv->u.array.values[i];

            if (!fb_json_str_chk(jx, "user_id", &str))
                continue;

            user.uid = FB_ID_FROM_STR(str);

            if (fb_json_str_chk(jx, "name", &str) && (user.uid != api->uid)) {
                user.name = str;
                mptr = g_memdup(&user, sizeof user);
                thrd.users = g_slist_prepend(thrd.users, mptr);
            }
        }
    }

    FB_API_FUNC(api, thread_info, &thrd);
    g_slist_free_full(thrd.users, g_free);

finish:
    json_value_free(json);
}

/**
 * Sends a thread info request.
 *
 * @param api The #fb_api.
 * @param tid The thread #fb_id.
 **/
void fb_api_thread_info(fb_api_t *api, fb_id_t tid)
{
    fb_http_req_t *req;
    gchar         *query;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_FQL,
                         fb_api_cb_thread_info,
                         "com.facebook.orca.protocol.methods.u",
                         "fetchThreadList",
                         "GET");

    query = g_strdup_printf("{"
        "\"threads\":\""
            "SELECT thread_fbid, participants, name "
                "FROM unified_thread "
                "WHERE thread_fbid='%" FB_ID_FORMAT "' "
                "LIMIT 1\""
        "}", tid);

    fb_http_req_params_set(req, FB_HTTP_PAIR("q", query), NULL);
    fb_api_req_send(api, req);
    g_free(query);
}

/**
 * Sends a thread invite request.
 *
 * @param api The #fb_api.
 * @param tid The thread #fb_id.
 * @param uid The user #fb_id.
 **/
void fb_api_thread_invite(fb_api_t *api, fb_id_t tid, fb_id_t uid)
{
    fb_http_req_t *req;
    gchar         *stid;
    gchar         *to;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_PARTS,
                         fb_api_cb_http_bool,
                         "com.facebook.orca.protocol.a",
                         "addMembers",
                         "POST");

    stid = g_strdup_printf("t_id.%" FB_ID_FORMAT, tid);
    to   = g_strdup_printf("[{"
            "\"type\":\"id\","
            "\"id\":\"%" FB_ID_FORMAT "\""
        "}]", uid);

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("id", stid),
        FB_HTTP_PAIR("to", to),
        NULL
    );

    fb_api_req_send(api, req);
    g_free(stid);
    g_free(to);
}

/**
 * Frees all memory used by a #fb_api_thread.
 *
 * @param thrd The #fb_api_thread.
 **/
static void fb_api_cb_threads_free(fb_api_thread_t *thrd)
{
    g_slist_free_full(thrd->users, g_free);
    g_free(thrd);
}

/**
 * Implemented #fb_http_func for #fb_api_threads().
 *
 * @param req  The #fb_http_req.
 * @param data The user-defined data, which is #fb_api.
 **/
static void fb_api_cb_thread_list(fb_http_req_t *req, gpointer data)
{
    fb_api_t        *api = data;
    fb_api_thread_t  thrd;
    fb_api_user_t    user;
    GSList          *thrds;
    json_value      *json;
    json_value      *jv;
    json_value      *jx;
    json_value      *jy;
    gpointer         mptr;
    const gchar     *str;
    guint            i;
    guint            j;

    if (!fb_api_http_chk(api, req) ||
        !fb_api_json_new(api, req->body, req->body_size, &json))
    {
        return;
    }

    thrds = NULL;

    /* Scattered values lead to a gnarly conditional... */
    if (!fb_json_val_chk(json, "data", json_array, &jv) ||

        /* Obtain the first array element */
        (jv->u.array.length != 1) ||
        ((jv = jv->u.array.values[0]) == NULL) ||

        /* Check the name */
        !fb_json_str_chk(jv, "name", &str) ||
        (g_ascii_strcasecmp(str, "threads") != 0) ||

        /* Obtain result array */
        !fb_json_val_chk(jv, "fql_result_set", json_array, &jv))
    {
        fb_api_error(api, FB_API_ERROR, "Failed to fetch thread list");
        goto finish;
    }

    for (i = 0; i < jv->u.array.length; i++) {
        jx = jv->u.array.values[i];

        if (!fb_json_str_chk(jx, "thread_fbid", &str))
            continue;

        thrd.tid   = FB_ID_FROM_STR(str);
        thrd.topic = NULL;
        thrd.users = NULL;

        if (fb_json_str_chk(jx, "name", &str) && (strlen(str) > 0))
            thrd.topic = str;

        if (!fb_json_val_chk(jx, "participants", json_array, &jx)) {
            thrds = g_slist_prepend(thrds, g_memdup(&thrd, sizeof thrd));
            continue;
        }

        for (j = 0; j < jx->u.array.length; j++) {
            jy = jx->u.array.values[j];

            if (!fb_json_str_chk(jy, "user_id", &str))
                continue;

            user.uid = FB_ID_FROM_STR(str);

            if (fb_json_str_chk(jy, "name", &str) && (user.uid != api->uid)) {
                user.name = str;
                mptr = g_memdup(&user, sizeof user);
                thrd.users = g_slist_prepend(thrd.users, mptr);
            }
        }

        thrds = g_slist_prepend(thrds, g_memdup(&thrd, sizeof thrd));
    }

    thrds = g_slist_reverse(thrds);
    FB_API_FUNC(api, thread_list, thrds);

finish:
    g_slist_free_full(thrds, (GDestroyNotify) fb_api_cb_threads_free);
    json_value_free(json);
}

/**
 * Sends a thread list request.
 *
 * @param api   The #fb_api.
 * @param limit The thread count limit.
 **/
void fb_api_thread_list(fb_api_t *api, guint limit)
{
    fb_http_req_t *req;
    gchar         *query;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_GHOST, FB_API_PATH_FQL,
                         fb_api_cb_thread_list,
                         "com.facebook.orca.protocol.methods.u",
                         "fetchThreadList",
                         "GET");

    query = g_strdup_printf("{"
        "\"threads\":\""
            "SELECT thread_fbid, participants, name "
                "FROM unified_thread "
                "WHERE folder='inbox' "
                "ORDER BY timestamp DESC "
                "LIMIT %u\""
        "}", limit);

    fb_http_req_params_set(req, FB_HTTP_PAIR("q", query), NULL);
    fb_api_req_send(api, req);
    g_free(query);
}

/**
 * Sends a thread topic request.
 *
 * @param api   The #fb_api.
 * @param tid   The thread #fb_id.
 * @param topic The topic message.
 **/
void fb_api_thread_topic(fb_api_t *api, fb_id_t tid, const gchar *topic)
{
    fb_http_req_t *req;
    gchar         *stid;

    g_return_if_fail(api != NULL);

    req = fb_api_req_new(api, FB_API_HOST, FB_API_PATH_TOPIC,
                         fb_api_cb_http_bool,
                         "com.facebook.orca.protocol.a",
                         "setThreadName",
                         "messaging.setthreadname");

    stid = g_strdup_printf("t_id.%" FB_ID_FORMAT, tid);

    fb_http_req_params_set(req,
        FB_HTTP_PAIR("tid",  stid),
        FB_HTTP_PAIR("name", topic),
        NULL
    );

    fb_api_req_send(api, req);
    g_free(stid);
}

/**
 * Sends a typing state to a user.
 *
 * @param api   The #fb_api.
 * @param uid   The #fb_id.
 * @param state TRUE if the user is typing, otherwise FALSE.
 **/
void fb_api_typing(fb_api_t *api, fb_id_t uid, gboolean state)
{
    g_return_if_fail(api != NULL);

    fb_api_publish(api, "/typing", "{"
            "\"to\":\"%" FB_ID_FORMAT "\","
            "\"state\":%d"
        "}", uid, state != 0);
}

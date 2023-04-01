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
#include <stdarg.h>
#include <string.h>

#include "facebook-api.h"
#include "facebook-http.h"
#include "facebook-json.h"
#include "facebook-marshal.h"
#include "facebook-thrift.h"
#include "facebook-util.h"

typedef struct _FbApiData FbApiData;
typedef struct _FbApiPreloginData FbApiPreloginData;

enum
{
    PROP_0,

    PROP_CID,
    PROP_DID,
    PROP_MID,
    PROP_STOKEN,
    PROP_TOKEN,
    PROP_UID,
    PROP_TWEAK,
    PROP_WORK,
    PROP_MACHINE_ID,
    PROP_LOGIN_FIRST_FACTOR,
    PROP_TWOFACTOR_CODE,

    PROP_N
};

struct _FbApiPrivate
{
    FbHttp *http;
    FbMqtt *mqtt;
    GHashTable *data;
    gboolean retrying;

    FbId uid;
    gint64 sid;
    guint64 mid;
    gchar *cid;
    gchar *did;
    gchar *stoken;
    gchar *token;

    GQueue *msgs;
    gboolean invisible;
    guint unread;
    FbId lastmid;
    gchar *contacts_delta;
    int tweak;
    gboolean is_work;
    gboolean need_work_switch;
    gchar *sso_verifier;
    FbId work_community_id;
    gchar *machine_id;
    gchar *login_first_factor;
    gchar *twofactor_code;
};

struct _FbApiData
{
    gpointer data;
    GDestroyNotify func;
};

struct _FbApiPreloginData
{
    FbApi *api;
    gchar *user;
    gchar *pass;
};

static void
fb_api_attach(FbApi *api, FbId aid, const gchar *msgid, FbApiMessage *msg);

static void
fb_api_contacts_after(FbApi *api, const gchar *cursor);

static void
fb_api_message_send(FbApi *api, FbApiMessage *msg);

static void
fb_api_sticker(FbApi *api, FbId sid, FbApiMessage *msg);

void
fb_api_contacts_delta(FbApi *api, const gchar *delta_cursor);

G_DEFINE_TYPE_WITH_PRIVATE(FbApi, fb_api, G_TYPE_OBJECT);

static const gchar *agents[] = {
    FB_API_AGENT,
    FB_API_AGENT_BASE " " "[FBAN/Orca-Android;FBAV/64.0.0.5.83;FBPN/com.facebook.orca;FBLC/en_US;FBBV/26040814]",
    FB_API_AGENT_BASE " " "[FBAN/Orca-Android;FBAV/109.0.0.17.70;FBBV/52182662]",
    FB_API_AGENT_BASE " " "[FBAN/Orca-Android;FBAV/109.0.0.17.70;FBPN/com.facebook.orca;FBLC/en_US;FBBV/52182662]",
    NULL,
};

static const gchar *
fb_api_get_agent_string(int tweak, gboolean mqtt)
{
    gboolean http_only = tweak & 4;
    gboolean mqtt_only = tweak & 8;

    if (tweak <= 0 || tweak > 15 || (http_only && mqtt) || (mqtt_only && !mqtt)) {
        return agents[0];
    }

    return agents[tweak & 3];
}

static void
fb_api_set_property(GObject *obj, guint prop, const GValue *val,
                    GParamSpec *pspec)
{
    FbApiPrivate *priv = FB_API(obj)->priv;

    switch (prop) {
    case PROP_CID:
        g_free(priv->cid);
        priv->cid = g_value_dup_string(val);
        break;
    case PROP_DID:
        g_free(priv->did);
        priv->did = g_value_dup_string(val);
        break;
    case PROP_MID:
        priv->mid = g_value_get_uint64(val);
        break;
    case PROP_STOKEN:
        g_free(priv->stoken);
        priv->stoken = g_value_dup_string(val);
        break;
    case PROP_TOKEN:
        g_free(priv->token);
        priv->token = g_value_dup_string(val);
        break;
    case PROP_UID:
        priv->uid = g_value_get_int64(val);
        break;
    case PROP_TWEAK:
        priv->tweak = g_value_get_int(val);
        fb_http_set_agent(priv->http, fb_api_get_agent_string(priv->tweak, 0));
        break;
    case PROP_WORK:
        priv->is_work = g_value_get_boolean(val);
        break;
    case PROP_MACHINE_ID:
        g_free(priv->machine_id);
        priv->machine_id = g_value_dup_string(val);
        break;
    case PROP_LOGIN_FIRST_FACTOR:
        g_free(priv->login_first_factor);
        priv->login_first_factor = g_value_dup_string(val);
        break;
    case PROP_TWOFACTOR_CODE:
        g_free(priv->twofactor_code);
        priv->twofactor_code = g_value_dup_string(val);
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
        break;
    }
}

static void
fb_api_get_property(GObject *obj, guint prop, GValue *val, GParamSpec *pspec)
{
    FbApiPrivate *priv = FB_API(obj)->priv;

    switch (prop) {
    case PROP_CID:
        g_value_set_string(val, priv->cid);
        break;
    case PROP_DID:
        g_value_set_string(val, priv->did);
        break;
    case PROP_MID:
        g_value_set_uint64(val, priv->mid);
        break;
    case PROP_STOKEN:
        g_value_set_string(val, priv->stoken);
        break;
    case PROP_TOKEN:
        g_value_set_string(val, priv->token);
        break;
    case PROP_UID:
        g_value_set_int64(val, priv->uid);
        break;
    case PROP_TWEAK:
        g_value_set_int(val, priv->tweak);
        break;
    case PROP_WORK:
        g_value_set_boolean(val, priv->is_work);
        break;
    case PROP_MACHINE_ID:
        g_value_set_string(val, priv->machine_id);
        break;
    case PROP_LOGIN_FIRST_FACTOR:
        g_value_set_string(val, priv->login_first_factor);
        break;
    case PROP_TWOFACTOR_CODE:
        g_value_set_string(val, priv->twofactor_code);
        break;

    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (obj, prop, pspec);
        break;
    }
}


static void
fb_api_dispose(GObject *obj)
{
    FbApiData *fata;
    FbApiPrivate *priv = FB_API(obj)->priv;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, priv->data);

    while (g_hash_table_iter_next(&iter, NULL, (gpointer) &fata)) {
        fata->func(fata->data);
        g_free(fata);
    }

    g_object_unref(priv->http);
    g_object_unref(priv->mqtt);
    g_hash_table_destroy(priv->data);
    g_queue_free_full(priv->msgs, (GDestroyNotify) fb_api_message_free);

    g_free(priv->cid);
    g_free(priv->did);
    g_free(priv->stoken);
    g_free(priv->token);
    g_free(priv->contacts_delta);
    g_free(priv->sso_verifier);
    g_free(priv->machine_id);
    g_free(priv->login_first_factor);
    g_free(priv->twofactor_code);
}

static void
fb_api_class_init(FbApiClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);
    GParamSpec *props[PROP_N] = {NULL};

    gklass->set_property = fb_api_set_property;
    gklass->get_property = fb_api_get_property;
    gklass->dispose = fb_api_dispose;

    /**
     * FbApi:cid:
     *
     * The client identifier for MQTT. This value should be saved
     * and loaded for persistence.
     */
    props[PROP_CID] = g_param_spec_string(
        "cid",
        "Client ID",
        "Client identifier for MQTT",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:did:
     *
     * The device identifier for the MQTT message queue. This value
     * should be saved and loaded for persistence.
     */
    props[PROP_DID] = g_param_spec_string(
        "did",
        "Device ID",
        "Device identifier for the MQTT message queue",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:mid:
     *
     * The MQTT identifier. This value should be saved and loaded
     * for persistence.
     */
    props[PROP_MID] = g_param_spec_uint64(
        "mid",
        "MQTT ID",
        "MQTT identifier",
        0, G_MAXUINT64, 0,
        G_PARAM_READWRITE);

    /**
     * FbApi:stoken:
     *
     * The synchronization token for the MQTT message queue. This
     * value should be saved and loaded for persistence.
     */
    props[PROP_STOKEN] = g_param_spec_string(
        "stoken",
        "Sync Token",
        "Synchronization token for the MQTT message queue",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:token:
     *
     * The access token for authentication. This value should be
     * saved and loaded for persistence.
     */
    props[PROP_TOKEN] = g_param_spec_string(
        "token",
        "Access Token",
        "Access token for authentication",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:uid:
     *
     * The #FbId of the user of the #FbApi.
     */
    props[PROP_UID] = g_param_spec_int64(
        "uid",
        "User ID",
        "User identifier",
        0, G_MAXINT64, 0,
        G_PARAM_READWRITE);

    /**
     * FbApi:tweak:
     */
    props[PROP_TWEAK] = g_param_spec_int(
        "tweak",
        "Tweak",
        "",
        0, G_MAXINT, 0,
        G_PARAM_READWRITE);

    /**
     * FbApi:work:
     */
    props[PROP_WORK] = g_param_spec_boolean(
        "work",
        "Work",
        "",
        FALSE,
        G_PARAM_READWRITE);

    /**
     * FbApi:machine_id:
     *
     * The machine id we ask facebook to generate for us.
     * Saved automatically for persistence.
     *
     * NOT TO BE CONFUSED WITH mid!
     */
    props[PROP_MACHINE_ID] = g_param_spec_string(
        "machine_id",
        "Machine Id",
        "Machine Id generated by facebook",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:login_first_factor:
     *
     * The first factor challenge code fo 2FA.
     * Saved automatically for persistence.
     */
    props[PROP_LOGIN_FIRST_FACTOR] = g_param_spec_string(
        "login_first_factor",
        "Login First Factor",
        "Login First Factor challenge code for 2FA",
        NULL,
        G_PARAM_READWRITE);

    /**
     * FbApi:twofactor_code:
     *
     * The 2FA code the user receives via external means.
     * User needs to set this manually to the account.
     */
    props[PROP_TWOFACTOR_CODE] = g_param_spec_string(
        "twofactor_code",
        "Twofactor Code",
        "Twofactor Code externally received, for 2FA",
        NULL,
        G_PARAM_READWRITE);

    g_object_class_install_properties(gklass, PROP_N, props);

    /**
     * FbApi::auth:
     * @api: The #FbApi.
     *
     * Emitted upon the successful completion of the authentication
     * process. This is emitted as a result of #fb_api_auth().
     */
    g_signal_new("auth",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__VOID,
                 G_TYPE_NONE,
                 0);

    /**
     * FbApi::connect:
     * @api: The #FbApi.
     *
     * Emitted upon the successful completion of the connection
     * process. This is emitted as a result of #fb_api_connect().
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
     * FbApi::contact:
     * @api: The #FbApi.
     * @user: The #FbApiUser.
     *
     * Emitted upon the successful reply of a contact request. This
     * is emitted as a result of #fb_api_contact().
     */
    g_signal_new("contact",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::contacts:
     * @api: The #FbApi.
     * @users: The #GSList of #FbApiUser's.
     * @complete: #TRUE if the list is fetched, otherwise #FALSE.
     *
     * Emitted upon the successful reply of a contacts request.
     * This is emitted as a result of #fb_api_contacts(). This can
     * be emitted multiple times before the entire contacts list
     * has been fetched. Use @complete for detecting the completion
     * status of the list fetch.
     */
    g_signal_new("contacts",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER_BOOLEAN,
                 G_TYPE_NONE,
                 2, G_TYPE_POINTER, G_TYPE_BOOLEAN);

    /**
     * FbApi::contacts-delta:
     * @api: The #FbApi.
     * @added: The #GSList of added #FbApiUser's.
     * @removed: The #GSList of strings with removed user ids.
     *
     * Like 'contacts', but only the deltas.
     */
    g_signal_new("contacts-delta",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER_POINTER,
                 G_TYPE_NONE,
                 2, G_TYPE_POINTER, G_TYPE_POINTER);

    /**
     * FbApi::error:
     * @api: The #FbApi.
     * @error: The #GError.
     *
     * Emitted whenever an error is hit within the #FbApi. This
     * should disconnect the #FbApi with #fb_api_disconnect().
     */
    g_signal_new("error",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::events:
     * @api: The #FbApi.
     * @events: The #GSList of #FbApiEvent's.
     *
     * Emitted upon incoming events from the stream.
     */
    g_signal_new("events",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::messages:
     * @api: The #FbApi.
     * @msgs: The #GSList of #FbApiMessage's.
     *
     * Emitted upon incoming messages from the stream.
     */
    g_signal_new("messages",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::presences:
     * @api: The #FbApi.
     * @press: The #GSList of #FbApiPresence's.
     *
     * Emitted upon incoming presences from the stream.
     */
    g_signal_new("presences",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::thread:
     * @api: The #FbApi.
     * @thrd: The #FbApiThread.
     *
     * Emitted upon the successful reply of a thread request. This
     * is emitted as a result of #fb_api_thread().
     */
    g_signal_new("thread",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::thread-create:
     * @api: The #FbApi.
     * @tid: The thread #FbId.
     *
     * Emitted upon the successful reply of a thread creation
     * request. This is emitted as a result of
     * #fb_api_thread_create().
     */
    g_signal_new("thread-create",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__INT64,
                 G_TYPE_NONE,
                 1, FB_TYPE_ID);

    /**
     * FbApi::thread-kicked:
     * @api: The #FbApi.
     * @thrd: The #FbApiThread.
     *
     * Emitted upon the reply of a thread request when the user is no longer
     * part of that thread. This is emitted as a result of #fb_api_thread().
     */
    g_signal_new("thread-kicked",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::threads:
     * @api: The #FbApi.
     * @thrds: The #GSList of #FbApiThread's.
     *
     * Emitted upon the successful reply of a threads request. This
     * is emitted as a result of #fb_api_threads().
     */
    g_signal_new("threads",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::typing:
     * @api: The #FbApi.
     * @typg: The #FbApiTyping.
     *
     * Emitted upon an incoming typing state from the stream.
     */
    g_signal_new("typing",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__POINTER,
                 G_TYPE_NONE,
                 1, G_TYPE_POINTER);

    /**
     * FbApi::work-sso-login:
     * @api: The #FbApi.
     *
     * Emitted when user interaction is required to continue SAML SSO login
     */

    g_signal_new("work-sso-login",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__VOID,
                 G_TYPE_NONE,
                 0);

    /**
     * FbApi::twofactor-code-prompt:
     * @api: The #FbApi.
     *
     * Emitted when we want to instruct the user about how to input
     * new twofactor code.
     */

    g_signal_new("twofactor-code-prompt",
                 G_TYPE_FROM_CLASS(klass),
                 G_SIGNAL_ACTION,
                 0,
                 NULL, NULL,
                 fb_marshal_VOID__VOID,
                 G_TYPE_NONE,
                 0);
}

static void
fb_api_init(FbApi *api)
{
    FbApiPrivate *priv;

    priv = fb_api_get_instance_private(api);
    api->priv = priv;

    priv->http = fb_http_new(FB_API_AGENT);
    priv->mqtt = fb_mqtt_new();
    priv->msgs = g_queue_new();
    priv->data = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                       NULL, NULL);
}

GQuark
fb_api_error_quark(void)
{
    static GQuark q = 0;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("fb-api-error-quark");
    }

    return q;
}

static void
fb_api_data_set(FbApi *api, gpointer handle, gpointer data,
                GDestroyNotify func)
{
    FbApiData *fata;
    FbApiPrivate *priv = api->priv;

    fata = g_new0(FbApiData, 1);
    fata->data = data;
    fata->func = func;
    g_hash_table_replace(priv->data, handle, fata);
}

static gpointer
fb_api_data_take(FbApi *api, gconstpointer handle)
{
    FbApiData *fata;
    FbApiPrivate *priv = api->priv;
    gpointer data;

    fata = g_hash_table_lookup(priv->data, handle);

    if (fata == NULL) {
        return NULL;
    }

    data = fata->data;
    g_hash_table_remove(priv->data, handle);
    g_free(fata);
    return data;
}

static void
fb_api_json_update_from_error_data(FbApi *api, gconstpointer data, gssize size, JsonNode **node)
{
    gchar *str;
    FbApiPrivate *priv;
    gboolean found_data = FALSE;
    GError *err = NULL;
    gint64 code;
    gint64 uid;
    JsonNode *root;
    gchar *error_data;
    JsonNode *error_data_root;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    if (G_UNLIKELY(size == 0)) {
        return;
    }
    root = fb_json_node_new(data, size, &err);
    if (err != NULL) {
        g_clear_error(&err);
        return;
    }
    // We handle all error stuff for info, not just 406

    error_data = fb_json_node_get_str(root,  "$.error_data", &err);
    if (err != NULL) {
        // No error data. This is ok.
        json_node_free(root);
        g_clear_error(&err);
        return;
    }

    error_data_root = fb_json_node_new(error_data, -1, &err);
    if (err != NULL) {
        g_free(error_data);
        json_node_free(root);
        return;
    }


    // Finally, parse individual datas
    // uid, special case
    uid = fb_json_node_get_int(error_data_root, "$.uid", &err);
    if (err != NULL) { g_clear_error(&err) ; } else {
        if (uid != priv->uid) {
            priv->uid = uid;
            found_data = TRUE;
        }
    }
    // machine_id
    str = fb_json_node_get_str(error_data_root, "$.machine_id", &err);
    if (err != NULL) { g_clear_error(&err) ; } else {
        if (g_strcmp0(str, priv->machine_id) != 0) {
            g_free(priv->machine_id);
            priv->machine_id = g_strdup(str);
            found_data = TRUE;
        }
        g_free(str);
    }
    // login_first_factor
    str = fb_json_node_get_str(error_data_root, "$.login_first_factor", &err);
    if (err != NULL) { g_clear_error(&err) ; } else {
        if (g_strcmp0(str, priv->login_first_factor) != 0) {
            g_free(priv->login_first_factor);
            priv->login_first_factor = g_strdup(str);
            found_data = TRUE;
        }
        g_free(str);
    }

    json_node_free(error_data_root);
    g_free(error_data);
    json_node_free(root);

    // If the data changed, with high probability we need new code and invalidate old
    if (found_data) {
        g_free(priv->twofactor_code);
        priv->twofactor_code = NULL;
    }
}


static gboolean
fb_api_json_chk(FbApi *api, gconstpointer data, gssize size, JsonNode **node)
{
    const gchar *str;
    FbApiError errc = FB_API_ERROR_GENERAL;
    FbApiPrivate *priv;
    FbJsonValues *values;
    gboolean success = TRUE;
    gchar *msg;
    GError *err = NULL;
    gint64 code;
    guint i;
    JsonNode *root;

    static const gchar *exprs[] = {
        "$.error.message",
        "$.error.summary",
        "$.error_msg",
        "$.errorCode",
        "$.failedSend.errorMessage",
    };

    g_return_val_if_fail(FB_IS_API(api), FALSE);
    priv = api->priv;

    if (G_UNLIKELY(size == 0)) {
        fb_api_error(api, FB_API_ERROR_GENERAL, "Empty JSON data");
        return FALSE;
    }
    fb_util_debug_info("Parsing JSON: %.*s", (gint) size,
                       (const gchar *) data);
    root = fb_json_node_new(data, size, &err);
    FB_API_ERROR_EMIT(api, err, return FALSE);

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE, "$.error_code");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.error.type");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.errorCode");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return FALSE
    );

    code = fb_json_values_next_int(values, 0);
    str = fb_json_values_next_str(values, NULL);

    if ((g_strcmp0(str, "OAuthException") == 0) || (code == 401)) {
        errc = FB_API_ERROR_AUTH;
        success = FALSE;

        g_free(priv->stoken);
        priv->stoken = NULL;

        g_free(priv->token);
        priv->token = NULL;

        g_free(priv->twofactor_code);
        priv->twofactor_code = NULL;
    }

    if (code == 406) {
        g_signal_emit_by_name(api, "twofactor-code-prompt");
    }

    /* 509 is used for "invalid attachment id" */
    if (code == 509) {
        errc = FB_API_ERROR_NONFATAL;
        success = FALSE;
    }

    str = fb_json_values_next_str(values, NULL);

    if ((g_strcmp0(str, "ERROR_QUEUE_NOT_FOUND") == 0) ||
        (g_strcmp0(str, "ERROR_QUEUE_LOST") == 0))
    {
        errc = FB_API_ERROR_QUEUE;
        success = FALSE;

        g_free(priv->stoken);
        priv->stoken = NULL;
    }

    g_object_unref(values);

    for (msg = NULL, i = 0; i < G_N_ELEMENTS(exprs); i++) {
        msg = fb_json_node_get_str(root, exprs[i], NULL);

        if (msg != NULL) {
            success = FALSE;
            break;
        }
    }

    if (!success && (msg == NULL)) {
        msg = g_strdup("Unknown error");
    }

    if (msg != NULL) {
        fb_api_error(api, errc, "%s", msg);
        json_node_free(root);
        g_free(msg);
        return FALSE;
    }

    if (node != NULL) {
        *node = root;
    } else {
        json_node_free(root);
    }

    return TRUE;
}


static gboolean
fb_api_http_chk(FbApi *api, FbHttpRequest *req, JsonNode **root)
{
    const gchar *data;
    GError *err;
    gsize size;

    data = fb_http_request_get_data(req, &size);
    err = fb_http_request_take_error(req);

    if ((err == NULL) && (root == NULL)) {
        return TRUE;
    }

    /* Rudimentary check to prevent wrongful error parsing */
    if ((size < 2) || (data[0] != '{') || (data[size - 1] != '}')) {
        FB_API_ERROR_EMIT(api, err, return FALSE);
    }

    // Scan possible error data for important auth state info changes
    fb_api_json_update_from_error_data(api, data, size, root);

    // Actual, propagable errors still handled here:
    if (!fb_api_json_chk(api, data, size, root)) {
        if (G_UNLIKELY(err != NULL)) {
            g_error_free(err);
        }

        return FALSE;
    }

    FB_API_ERROR_EMIT(api, err, return FALSE);
    return TRUE;
}

static FbHttpRequest *
fb_api_http_req(FbApi *api, const gchar *url, const gchar *name,
                const gchar *method, FbHttpValues *values,
                FbHttpFunc func)
{
    const gchar *key;
    const gchar *val;
    FbApiPrivate *priv = api->priv;
    FbHttpRequest *req;
    FbHttpValues *hdrs;
    FbHttpValues *prms;
    gchar *data;
    GList *keys;
    GList *l;
    GString *gstr;

    fb_http_values_set_str(values, "api_key",
        priv->is_work ? FB_WORK_API_KEY : FB_API_KEY);
    fb_http_values_set_str(values, "device_id", priv->did);
    fb_http_values_set_str(values, "fb_api_req_friendly_name", name);
    fb_http_values_set_str(values, "format", "json");
    fb_http_values_set_str(values, "method", method);

    data = fb_util_get_locale();
    fb_http_values_set_str(values, "locale", data);
    g_free(data);

    req = fb_http_request_new(priv->http, url, TRUE, func, api);
    fb_http_values_remove(values, "sig");

    gstr = g_string_new(NULL);
    keys = fb_http_values_get_keys(values);
    keys = g_list_sort(keys, (GCompareFunc) g_ascii_strcasecmp);

    for (l = keys; l != NULL; l = l->next) {
        key = l->data;
        val = fb_http_values_get_str(values, key, NULL);
        g_string_append_printf(gstr, "%s=%s", key, val);
    }

    g_string_append(gstr, priv->is_work ? FB_WORK_API_SECRET : FB_API_SECRET);
    data = g_compute_checksum_for_string(G_CHECKSUM_MD5, gstr->str, gstr->len);
    fb_http_values_set_str(values, "sig", data);

    g_string_free(gstr, TRUE);
    g_list_free(keys);
    g_free(data);

    if (priv->token != NULL) {
        hdrs = fb_http_request_get_headers(req);
        fb_http_values_set_strf(hdrs, "Authorization", "OAuth %s", priv->token);
    }

    prms = fb_http_request_get_params(req);
    fb_http_values_consume(prms, values);
    fb_http_request_send(req);
    return req;
}

static FbHttpRequest *
fb_api_http_query(FbApi *api, gint64 query, JsonBuilder *builder,
                  FbHttpFunc func)
{
    const gchar *name;
    FbHttpValues *prms;
    gchar *json;

    switch (query) {
    case FB_API_QUERY_CONTACT:
        name = "UsersQuery";
        break;
    case FB_API_QUERY_CONTACTS:
        name = "FetchContactsFullQuery";
        break;
    case FB_API_QUERY_CONTACTS_AFTER:
        name = "FetchContactsFullWithAfterQuery";
        break;
    case FB_API_QUERY_CONTACTS_DELTA:
        name = "FetchContactsDeltaQuery";
        break;
    case FB_API_QUERY_STICKER:
        name = "FetchStickersWithPreviewsQuery";
        break;
    case FB_API_QUERY_THREAD:
        name = "ThreadQuery";
        break;
    case FB_API_QUERY_SEQ_ID:
    case FB_API_QUERY_THREADS:
        name = "ThreadListQuery";
        break;
    case FB_API_QUERY_XMA:
        name = "XMAQuery";
        break;
    default:
        g_return_val_if_reached(NULL);
        return NULL;
    }

    prms = fb_http_values_new();
    json = fb_json_bldr_close(builder, JSON_NODE_OBJECT, NULL);
    fb_http_values_set_strf(prms, "query_id", "%" G_GINT64_FORMAT, query);
    fb_http_values_set_str(prms, "query_params", json);
    g_free(json);

    return fb_api_http_req(api, FB_API_URL_GQL, name, "get", prms, func);
}

static void
fb_api_cb_http_bool(FbHttpRequest *req, gpointer data)
{
    const gchar *hata;
    FbApi *api = data;

    if (!fb_api_http_chk(api, req, NULL)) {
        return;
    }

    hata = fb_http_request_get_data(req, NULL);

    if (G_UNLIKELY(hata == NULL)) {
        hata = "false";
    }

    if (!bool2int((gchar *) hata)) {
        fb_api_error(api, FB_API_ERROR, "Failed generic API operation");
    }
}

static void
fb_api_cb_mqtt_error(FbMqtt *mqtt, GError *error, gpointer data)
{
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;

    if (!priv->retrying) {
        priv->retrying = TRUE;
        fb_util_debug_info("Attempting to reconnect the MQTT stream...");
        fb_api_connect(api, priv->invisible);
    } else {
        g_signal_emit_by_name(api, "error", error);
    }
}

static void
fb_api_cb_mqtt_open(FbMqtt *mqtt, gpointer data)
{
    const GByteArray *bytes;
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    FbThrift *thft;
    GByteArray *cytes;
    GError *err = NULL;

    static guint8 flags = FB_MQTT_CONNECT_FLAG_USER |
                          FB_MQTT_CONNECT_FLAG_PASS |
                          FB_MQTT_CONNECT_FLAG_CLR;

    thft = fb_thrift_new(NULL, 0);

    /* Write the client identifier */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_STRING, 1, 0);
    fb_thrift_write_str(thft, priv->cid);

    fb_thrift_write_field(thft, FB_THRIFT_TYPE_STRUCT, 4, 1);

    /* Write the user identifier */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I64, 1, 0);
    fb_thrift_write_i64(thft, priv->uid);

    /* Write the information string */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_STRING, 2, 1);
    fb_thrift_write_str(thft, (priv->tweak != 0)
        ? fb_api_get_agent_string(priv->tweak, 1)
        : FB_API_MQTT_AGENT);

    /* Write the client capabilities */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I64, 3, 2);
    fb_thrift_write_i64(thft, FB_CP_ACKNOWLEDGED_DELIVERY |
                              FB_CP_PROCESSING_LASTACTIVE_PRESENCEINFO |
                              FB_CP_EXACT_KEEPALIVE |
                              FB_CP_DELTA_SENT_MESSAGE_ENABLED);

    /* Write the endpoint capabilitites */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I64, 4, 3);
    fb_thrift_write_i64(thft, 26);

    /* Write the publish payload format (deflate) */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I32, 5, 4);
    fb_thrift_write_i32(thft, 1);

    /* Write the noAutomaticForeground flag */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_BOOL, 6, 5);
    fb_thrift_write_bool(thft, TRUE);

    /* Write the visibility state (makeUserAvailableInForeground flag) */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_BOOL, 7, 6);
    fb_thrift_write_bool(thft, !priv->invisible);

    /* Write the device identifier */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_STRING, 8, 7);
    fb_thrift_write_str(thft, priv->did);

    /* Write the isInitiallyForeground flag */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_BOOL, 9, 8);
    fb_thrift_write_bool(thft, TRUE);

    /* Write the network type (WIFI) */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I32, 10, 9);
    fb_thrift_write_i32(thft, 1);

    /* Write the network subtype (none) */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I32, 11, 10);
    fb_thrift_write_i32(thft, 0);

    /* Write the MQTT identifier */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_I64, 12, 11);
    fb_thrift_write_i64(thft, priv->mid);

    /* Write the list of topics to subscribe */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_LIST, 14, 12);
    fb_thrift_write_list(thft, FB_THRIFT_TYPE_I32, 0);

    /* Write the STOP for the struct */
    fb_thrift_write_stop(thft);

    /* Write the token */
    fb_thrift_write_field(thft, FB_THRIFT_TYPE_STRING, 5, 4);
    fb_thrift_write_str(thft, priv->token);

    /* Write the STOP for the message */
    fb_thrift_write_stop(thft);

    bytes = fb_thrift_get_bytes(thft);
    cytes = fb_util_zlib_deflate(bytes, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(thft);
        return;
    );

    fb_util_debug_hexdump(FB_UTIL_DEBUG_LEVEL_INFO, bytes, "Writing connect");
    fb_mqtt_connect(mqtt, flags, cytes);

    g_byte_array_free(cytes, TRUE);
    g_object_unref(thft);
}

static void
fb_api_connect_queue(FbApi *api)
{
    FbApiMessage *msg;
    FbApiPrivate *priv = api->priv;
    gchar *json;
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_int(bldr, "delta_batch_size", 125);
    fb_json_bldr_add_int(bldr, "max_deltas_able_to_process", 1250);
    fb_json_bldr_add_int(bldr, "sync_api_version", 3);
    fb_json_bldr_add_str(bldr, "encoding", "JSON");

    if (priv->stoken == NULL) {
        fb_json_bldr_add_int(bldr, "initial_titan_sequence_id", priv->sid);
        fb_json_bldr_add_str(bldr, "device_id", priv->did);
        fb_json_bldr_add_int(bldr, "entity_fbid", priv->uid);

        fb_json_bldr_obj_begin(bldr, "queue_params");
        fb_json_bldr_add_str(bldr, "buzz_on_deltas_enabled", "false");

        fb_json_bldr_obj_begin(bldr, "graphql_query_hashes");
        fb_json_bldr_add_str(bldr, "xma_query_id",
                             G_STRINGIFY(FB_API_QUERY_XMA));
        fb_json_bldr_obj_end(bldr);

        fb_json_bldr_obj_begin(bldr, "graphql_query_params");
        fb_json_bldr_obj_begin(bldr, G_STRINGIFY(FB_API_QUERY_XMA));
        fb_json_bldr_add_str(bldr, "xma_id", "<ID>");
        fb_json_bldr_obj_end(bldr);
        fb_json_bldr_obj_end(bldr);
        fb_json_bldr_obj_end(bldr);

        json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
        fb_api_publish(api, "/messenger_sync_create_queue", "%s", json);
        g_free(json);
        return;
    }

    fb_json_bldr_add_int(bldr, "last_seq_id", priv->sid);
    fb_json_bldr_add_str(bldr, "sync_token", priv->stoken);

    json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
    fb_api_publish(api, "/messenger_sync_get_diffs", "%s", json);
    g_signal_emit_by_name(api, "connect");
    g_free(json);

    if (!g_queue_is_empty(priv->msgs)) {
        msg = g_queue_peek_head(priv->msgs);
        fb_api_message_send(api, msg);
    }

    if (priv->retrying) {
        priv->retrying = FALSE;
        fb_util_debug_info("Reconnected the MQTT stream");
    }
}

static void
fb_api_cb_seqid(FbHttpRequest *req, gpointer data)
{
    const gchar *str;
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
                       "$.viewer.message_threads.sync_sequence_id");
    fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE,
                       "$.viewer.message_threads.unread_count");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    str = fb_json_values_next_str(values, "0");
    priv->sid = g_ascii_strtoll(str, NULL, 10);
    priv->unread = fb_json_values_next_int(values, 0);

    fb_api_connect_queue(api);
    g_object_unref(values);
    json_node_free(root);
}

static void
fb_api_cb_mqtt_connect(FbMqtt *mqtt, gpointer data)
{
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    gchar *json;
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_bool(bldr, "foreground", TRUE);
    fb_json_bldr_add_int(bldr, "keepalive_timeout", FB_MQTT_KA);

    json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
    fb_api_publish(api, "/foreground_state", "%s", json);
    g_free(json);

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

    if (priv->sid == 0) {
        bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
        fb_json_bldr_add_str(bldr, "1", "0");
        fb_api_http_query(api, FB_API_QUERY_SEQ_ID, bldr, fb_api_cb_seqid);
    } else {
        fb_api_connect_queue(api);
    }
}

static void
fb_api_cb_publish_mark(FbApi *api, GByteArray *pload)
{
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_BOOL, FALSE, "$.succeeded");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    if (!fb_json_values_next_bool(values, TRUE)) {
        fb_api_error(api, FB_API_ERROR_GENERAL,
                     "Failed to mark thread as read");
    }

    g_object_unref(values);
    json_node_free(root);
}

static GSList *
fb_api_event_parse(FbApi *api, FbApiEvent *event, GSList *events,
                   JsonNode *root, GError **error)
{
    const gchar *str;
    FbApiEvent *devent;
    FbJsonValues *values;
    GError *err = NULL;
    guint i;

    static const struct {
        FbApiEventType type;
        const gchar *expr;
    } evtypes[] = {
        {
            FB_API_EVENT_TYPE_THREAD_USER_ADDED,
             "$.log_message_data.added_participants"
        }, {
            FB_API_EVENT_TYPE_THREAD_USER_REMOVED,
            "$.log_message_data.removed_participants"
        }
    };

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.log_message_type");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.author");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.log_message_data.name");
    fb_json_values_update(values, &err);

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
        g_object_unref(values);
        return events;
    }

    str = fb_json_values_next_str(values, NULL);

    if (g_strcmp0(str, "log:thread-name") == 0) {
        str = fb_json_values_next_str(values, "");
        str = strrchr(str, ':');

        if (str != NULL) {
            devent = fb_api_event_dup(event, FALSE);
            devent->type = FB_API_EVENT_TYPE_THREAD_TOPIC;
            devent->uid = FB_ID_FROM_STR(str + 1);
            devent->text = fb_json_values_next_str_dup(values, NULL);
            events = g_slist_prepend(events, devent);
        }
    }

    g_object_unref(values);

    for (i = 0; i < G_N_ELEMENTS(evtypes); i++) {
        values = fb_json_values_new(root);
        fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$");
        fb_json_values_set_array(values, FALSE, evtypes[i].expr);

        while (fb_json_values_update(values, &err)) {
            str = fb_json_values_next_str(values, "");
            str = strrchr(str, ':');

            if (str != NULL) {
                devent = fb_api_event_dup(event, FALSE);
                devent->type = evtypes[i].type;
                devent->uid = FB_ID_FROM_STR(str + 1);
                events = g_slist_prepend(events, devent);
            }
        }

        g_object_unref(values);

        if (G_UNLIKELY(err != NULL)) {
            g_propagate_error(error, err);
            break;
        }
    }

    return events;
}

static void
fb_api_cb_publish_mercury(FbApi *api, GByteArray *pload)
{
    const gchar *str;
    FbApiEvent event;
    FbJsonValues *values;
    GError *err = NULL;
    GSList *events = NULL;
    JsonNode *root;
    JsonNode *node;

    if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.thread_fbid");
    fb_json_values_set_array(values, FALSE, "$.actions");

    while (fb_json_values_update(values, &err)) {
        fb_api_event_reset(&event, FALSE);
        str = fb_json_values_next_str(values, "0");
        event.tid = FB_ID_FROM_STR(str);

        node = fb_json_values_get_root(values);
        events = fb_api_event_parse(api, &event, events, node, &err);
    }

    if (G_LIKELY(err == NULL)) {
        events = g_slist_reverse(events);
        g_signal_emit_by_name(api, "events", events);
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(events, (GDestroyNotify) fb_api_event_free);
    g_object_unref(values);
    json_node_free(root);

}

static void
fb_api_cb_publish_typing(FbApi *api, GByteArray *pload)
{
    const gchar *str;
    FbApiPrivate *priv = api->priv;
    FbApiTyping typg;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.type");
    fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.sender_fbid");
    fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.state");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    str = fb_json_values_next_str(values, NULL);

    if (g_ascii_strcasecmp(str, "typ") == 0) {
        typg.uid = fb_json_values_next_int(values, 0);

        if (typg.uid != priv->uid) {
            typg.state = fb_json_values_next_int(values, 0);
            g_signal_emit_by_name(api, "typing", &typg);
        }
    }

    g_object_unref(values);
    json_node_free(root);
}

static void
fb_api_cb_publish_ms_r(FbApi *api, GByteArray *pload)
{
    FbApiMessage *msg;
    FbApiPrivate *priv = api->priv;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_json_chk(api, pload->data, pload->len, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_BOOL, TRUE, "$.succeeded");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    if (fb_json_values_next_bool(values, TRUE)) {
        /* Pop and free the successful message */
        msg = g_queue_pop_head(priv->msgs);
        fb_api_message_free(msg);

        if (!g_queue_is_empty(priv->msgs)) {
            msg = g_queue_peek_head(priv->msgs);
            fb_api_message_send(api, msg);
        }
    } else {
        fb_api_error(api, FB_API_ERROR_GENERAL,
                     "Failed to send message");
    }

    g_object_unref(values);
    json_node_free(root);
}

static gchar *
fb_api_xma_parse(FbApi *api, const gchar *body, JsonNode *root, GError **error)
{
    const gchar *str;
    const gchar *url;
    FbHttpValues *prms;
    FbJsonValues *values;
    gchar *text;
    GError *err = NULL;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.story_attachment.target.__type__.name");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.story_attachment.url");
    fb_json_values_update(values, &err);

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
        g_object_unref(values);
        return NULL;
    }

    str = fb_json_values_next_str(values, NULL);
    url = fb_json_values_next_str(values, NULL);

    if ((str == NULL) || (url == NULL)) {
        text = g_strdup("<Unsupported Attachment>");
        g_object_unref(values);
        return text;
    }

    if (g_strcmp0(str, "ExternalUrl") == 0) {
        prms = fb_http_values_new();
        fb_http_values_parse(prms, url, TRUE);
        if (g_str_has_prefix(url, FB_API_FBRPC_PREFIX)) {
            text = fb_http_values_dup_str(prms, "target_url", NULL);
        } else {
            text = fb_http_values_dup_str(prms, "u", NULL);
        }
        fb_http_values_free(prms);
    } else {
        text = g_strdup(url);
    }

    if (fb_http_urlcmp(body, text, FALSE)) {
        g_free(text);
        g_object_unref(values);
        return NULL;
    }

    g_object_unref(values);
    return text;
}

static GSList *
fb_api_message_parse_attach(FbApi *api, const gchar *mid, FbApiMessage *msg,
                            GSList *msgs, const gchar *body, JsonNode *root,
                            GError **error)
{
    const gchar *str;
    FbApiMessage *dmsg;
    FbId id;
    FbJsonValues *values;
    gchar *xma;
    GError *err = NULL;
    JsonNode *node;
    JsonNode *xode;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.xmaGraphQL");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE, "$.fbid");
    fb_json_values_set_array(values, FALSE, "$.attachments");

    while (fb_json_values_update(values, &err)) {
        str = fb_json_values_next_str(values, NULL);

        if (str == NULL) {
            id = fb_json_values_next_int(values, 0);
            dmsg = fb_api_message_dup(msg, FALSE);
            fb_api_attach(api, id, mid, dmsg);
            continue;
        }

        node = fb_json_node_new(str, -1, &err);

        if (G_UNLIKELY(err != NULL)) {
            break;
        }

        xode = fb_json_node_get_nth(node, 0);
        xma = fb_api_xma_parse(api, body, xode, &err);

        if (xma != NULL) {
            dmsg = fb_api_message_dup(msg, FALSE);
            dmsg->text = xma;
            msgs = g_slist_prepend(msgs, dmsg);
        }

        json_node_free(node);

        if (G_UNLIKELY(err != NULL)) {
            break;
        }
    }

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
    }

    g_object_unref(values);
    return msgs;
}

static GSList *
fb_api_cb_publish_ms_new_message(FbApi *api, JsonNode *root, GSList *msgs, GError **error);

static GSList *
fb_api_cb_publish_ms_event(FbApi *api, JsonNode *root, GSList *events, FbApiEventType type, GError **error);

static void
fb_api_cb_publish_mst(FbThrift *thft, GError **error)
{
    if (fb_thrift_read_isstop(thft)) {
        FB_API_TCHK(fb_thrift_read_stop(thft));
    } else {
        FbThriftType type;
        gint16 id;

        FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, 0));
        FB_API_TCHK(type == FB_THRIFT_TYPE_STRING);
        fb_util_debug_info("fb_api_cb_publish_mst() id: %d", id);
        FB_API_TCHK(id == 1 || id == 2);
        FB_API_TCHK(fb_thrift_read_str(thft, NULL));
        FB_API_TCHK(fb_thrift_read_stop(thft));
    }

    return;
}

static void
fb_api_cb_publish_ms(FbApi *api, GByteArray *pload)
{
    const gchar *data;
    FbApiPrivate *priv = api->priv;
    FbJsonValues *values;
    FbThrift *thft;
    gchar *stoken;
    GError *err = NULL;
    GList *elms, *l;
    GSList *msgs = NULL;
    GSList *events = NULL;
    guint size;
    JsonNode *root;
    JsonNode *node;
    JsonArray *arr;

    static const struct {
        const gchar *member;
        FbApiEventType type;
        gboolean is_message;
    } event_types[] = {
        {"deltaNewMessage", 0, 1},
        {"deltaThreadName", FB_API_EVENT_TYPE_THREAD_TOPIC, 0},
        {"deltaParticipantsAddedToGroupThread", FB_API_EVENT_TYPE_THREAD_USER_ADDED, 0},
        {"deltaParticipantLeftGroupThread", FB_API_EVENT_TYPE_THREAD_USER_REMOVED, 0},
    };

    /* Read identifier string (for Facebook employees) */
    thft = fb_thrift_new(pload, 0);
    fb_api_cb_publish_mst(thft, &err);
    size = fb_thrift_get_pos(thft);
    g_object_unref(thft);

    FB_API_ERROR_EMIT(api, err,
        return;
    );

    g_return_if_fail(size < pload->len);
    data = (gchar *) pload->data + size;
    size = pload->len - size;

    if (!fb_api_json_chk(api, data, size, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE, "$.lastIssuedSeqId");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.syncToken");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    priv->sid = fb_json_values_next_int(values, 0);
    stoken = fb_json_values_next_str_dup(values, NULL);
    g_object_unref(values);

    if (G_UNLIKELY(stoken != NULL)) {
        g_free(priv->stoken);
        priv->stoken = stoken;
        g_signal_emit_by_name(api, "connect");
        json_node_free(root);
        return;
    }

    arr = fb_json_node_get_arr(root, "$.deltas", NULL);
    elms = json_array_get_elements(arr);

    for (l = elms; l != NULL; l = l->next) {
        guint i = 0;
        JsonObject *o = json_node_get_object(l->data);

        for (i = 0; i < G_N_ELEMENTS(event_types); i++) {
            if ((node = json_object_get_member(o, event_types[i].member))) {
                if (event_types[i].is_message) {
                    msgs = fb_api_cb_publish_ms_new_message(
                        api, node, msgs, &err
                    );
                } else {
                    events = fb_api_cb_publish_ms_event(
                        api, node, events, event_types[i].type, &err
                    );
                }
            }
        }

        if (G_UNLIKELY(err != NULL)) {
            break;
        }
    }

    g_list_free(elms);
    json_array_unref(arr);

    if (G_LIKELY(err == NULL)) {
        if (msgs) {
            msgs = g_slist_reverse(msgs);
            g_signal_emit_by_name(api, "messages", msgs);
        }

        if (events) {
            events = g_slist_reverse(events);
            g_signal_emit_by_name(api, "events", events);
        }
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
    g_slist_free_full(events, (GDestroyNotify) fb_api_event_free);
    json_node_free(root);
}


static GSList *
fb_api_cb_publish_ms_new_message(FbApi *api, JsonNode *root, GSList *msgs, GError **error)
{
    const gchar *body;
    const gchar *str;
    GError *err = NULL;
    FbApiPrivate *priv = api->priv;
    FbApiMessage *dmsg;
    FbApiMessage msg;
    FbId id;
    FbId oid;
    FbJsonValues *values;
    JsonNode *node;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata.offlineThreadingId");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata.actorFbId");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata"
                        ".threadKey.otherUserFbId");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata"
                        ".threadKey.threadFbId");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata.timestamp");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.body");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.stickerId");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.messageMetadata.messageId");

    if (fb_json_values_update(values, &err)) {
        id = fb_json_values_next_int(values, 0);

        /* Ignore everything but new messages */
        if (id == 0) {
            goto beach;
        }

        /* Ignore sequential duplicates */
        if (id == priv->lastmid) {
            fb_util_debug_info("Ignoring duplicate %" FB_ID_FORMAT, id);
            goto beach;
        }

        priv->lastmid = id;
        fb_api_message_reset(&msg, FALSE);
        msg.uid = fb_json_values_next_int(values, 0);
        oid = fb_json_values_next_int(values, 0);
        msg.tid = fb_json_values_next_int(values, 0);
        msg.tstamp = fb_json_values_next_int(values, 0);

        if (msg.uid == priv->uid) {
            msg.flags |= FB_API_MESSAGE_FLAG_SELF;

            if (msg.tid == 0) {
                msg.uid = oid;
            }
        }

        body = fb_json_values_next_str(values, NULL);

        if (body != NULL) {
            dmsg = fb_api_message_dup(&msg, FALSE);
            dmsg->text = g_strdup(body);
            msgs = g_slist_prepend(msgs, dmsg);
        }

        id = fb_json_values_next_int(values, 0);

        if (id != 0) {
            dmsg = fb_api_message_dup(&msg, FALSE);
            fb_api_sticker(api, id, dmsg);
        }

        str = fb_json_values_next_str(values, NULL);

        if (str == NULL) {
            goto beach;
        }

        node = fb_json_values_get_root(values);
        msgs = fb_api_message_parse_attach(api, str, &msg, msgs, body, node,
                                           &err);

        if (G_UNLIKELY(err != NULL)) {
            g_propagate_error(error, err);
            goto beach;
        }
    }

beach:
    g_object_unref(values);
    return msgs;
}

static GSList *
fb_api_cb_publish_ms_event(FbApi *api, JsonNode *root, GSList *events, FbApiEventType type, GError **error)
{
    FbApiEvent *event;
    FbJsonValues *values = NULL;
    FbJsonValues *values_inner = NULL;
    GError *err = NULL;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata.threadKey.threadFbId");
    fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                       "$.messageMetadata.actorFbId");

    switch (type) {
        case FB_API_EVENT_TYPE_THREAD_TOPIC:
            fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                               "$.name");
            break;

        case FB_API_EVENT_TYPE_THREAD_USER_ADDED:
            values_inner = fb_json_values_new(root);

            fb_json_values_add(values_inner, FB_JSON_TYPE_INT, FALSE,
                               "$.userFbId");

            /* use the text field for the full name */
            fb_json_values_add(values_inner, FB_JSON_TYPE_STR, FALSE,
                               "$.fullName");

            fb_json_values_set_array(values_inner, FALSE,
                                     "$.addedParticipants");
            break;

        case FB_API_EVENT_TYPE_THREAD_USER_REMOVED:
            fb_json_values_add(values, FB_JSON_TYPE_INT, FALSE,
                               "$.leftParticipantFbId");

            /* use the text field for the kick message */
            fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                               "$.messageMetadata.adminText");
            break;
    }

    fb_json_values_update(values, &err);

    event = fb_api_event_dup(NULL, FALSE);
    event->type = type;
    event->tid = fb_json_values_next_int(values, 0);
    event->uid = fb_json_values_next_int(values, 0);

    if (type == FB_API_EVENT_TYPE_THREAD_TOPIC) {
        event->text = fb_json_values_next_str_dup(values, NULL);
    } else if (type == FB_API_EVENT_TYPE_THREAD_USER_REMOVED) {
        /* overwrite actor with subject */
        event->uid = fb_json_values_next_int(values, 0);
        event->text = fb_json_values_next_str_dup(values, NULL);
    } else if (type == FB_API_EVENT_TYPE_THREAD_USER_ADDED) {

        while (fb_json_values_update(values_inner, &err)) {
            FbApiEvent *devent = fb_api_event_dup(event, FALSE);

            devent->uid = fb_json_values_next_int(values_inner, 0);
            devent->text = fb_json_values_next_str_dup(values_inner, NULL);

            events = g_slist_prepend(events, devent);
        }
        fb_api_event_free(event);
        event = NULL;
        g_object_unref(values_inner);
    }

    g_object_unref(values);

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
    } else if (event) {
        events = g_slist_prepend(events, event);
    }

    return events;
}

static void
fb_api_cb_publish_pt(FbThrift *thft, GSList **press, GError **error)
{
    FbApiPresence *pres;
    FbThriftType type;
    gint16 id;
    gint32 i32;
    gint64 i64;
    guint i;
    guint size = 0;

    /* Read identifier string (for Facebook employees) */
    FB_API_TCHK(fb_thrift_read_str(thft, NULL));

    /* Read the full list boolean field */
    FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, 0));
    FB_API_TCHK(type == FB_THRIFT_TYPE_BOOL);
    FB_API_TCHK(id == 1);
    FB_API_TCHK(fb_thrift_read_bool(thft, NULL));

    /* Read the list field */
    FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, id));
    FB_API_TCHK(type == FB_THRIFT_TYPE_LIST);
    FB_API_TCHK(id == 2);

    /* Read the list */
    FB_API_TCHK(fb_thrift_read_list(thft, &type, &size));
    FB_API_TCHK(type == FB_THRIFT_TYPE_STRUCT);

    for (i = 0; i < size; i++) {
        /* Read the user identifier field */
        FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, 0));
        FB_API_TCHK(type == FB_THRIFT_TYPE_I64);
        FB_API_TCHK(id == 1);
        FB_API_TCHK(fb_thrift_read_i64(thft, &i64));

        /* Read the active field */
        FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, id));
        FB_API_TCHK(type == FB_THRIFT_TYPE_I32);
        FB_API_TCHK(id == 2);
        FB_API_TCHK(fb_thrift_read_i32(thft, &i32));

        pres = fb_api_presence_dup(NULL);
        pres->uid = i64;
        pres->active = i32 != 0;
        *press = g_slist_prepend(*press, pres);

        fb_util_debug_info("Presence: %" FB_ID_FORMAT " (%d) id: %d",
                           i64, i32 != 0, id);

        while (id <= 6) {
            if (fb_thrift_read_isstop(thft)) {
                break;
            }

            FB_API_TCHK(fb_thrift_read_field(thft, &type, &id, id));

            switch (id) {
            case 3:
                /* Read the last active timestamp field */
                FB_API_TCHK(type == FB_THRIFT_TYPE_I64);
                FB_API_TCHK(fb_thrift_read_i64(thft, NULL));
                break;

            case 4:
                /* Read the active client bits field */
                FB_API_TCHK(type == FB_THRIFT_TYPE_I16);
                FB_API_TCHK(fb_thrift_read_i16(thft, NULL));
                break;

            case 5:
                /* Read the VoIP compatibility bits field */
                FB_API_TCHK(type == FB_THRIFT_TYPE_I64);
                FB_API_TCHK(fb_thrift_read_i64(thft, NULL));
                break;

            case 6:
                /* Unknown new field */
                FB_API_TCHK(type == FB_THRIFT_TYPE_I64);
                FB_API_TCHK(fb_thrift_read_i64(thft, NULL));
                break;

            default:
                /* Try to read unknown fields as varint */
                FB_API_TCHK(type == FB_THRIFT_TYPE_I16 ||
                            type == FB_THRIFT_TYPE_I32 ||
                            type == FB_THRIFT_TYPE_I64);
                FB_API_TCHK(fb_thrift_read_i64(thft, NULL));
                break;
            }
        }

        /* Read the field stop */
        FB_API_TCHK(fb_thrift_read_stop(thft));
    }

    /* Read the field stop */
    if (fb_thrift_read_isstop(thft)) {
        FB_API_TCHK(fb_thrift_read_stop(thft));
    }
}

static void
fb_api_cb_publish_p(FbApi *api, GByteArray *pload)
{
    FbThrift *thft;
    GError *err = NULL;
    GSList *press = NULL;

    thft = fb_thrift_new(pload, 0);
    fb_api_cb_publish_pt(thft, &press, &err);
    g_object_unref(thft);

    if (G_LIKELY(err == NULL)) {
        g_signal_emit_by_name(api, "presences", press);
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(press, (GDestroyNotify) fb_api_presence_free);
}

static void
fb_api_cb_mqtt_publish(FbMqtt *mqtt, const gchar *topic, GByteArray *pload,
                       gpointer data)
{
    FbApi *api = data;
    gboolean comp;
    GByteArray *bytes;
    GError *err = NULL;
    guint i;

    static const struct {
        const gchar *topic;
        void (*func) (FbApi *api, GByteArray *pload);
    } parsers[] = {
        {"/mark_thread_response", fb_api_cb_publish_mark},
        {"/mercury", fb_api_cb_publish_mercury},
        {"/orca_typing_notifications", fb_api_cb_publish_typing},
        {"/send_message_response", fb_api_cb_publish_ms_r},
        {"/t_ms", fb_api_cb_publish_ms},
        {"/t_p", fb_api_cb_publish_p}
    };

    comp = fb_util_zlib_test(pload);

    if (G_LIKELY(comp)) {
        bytes = fb_util_zlib_inflate(pload, &err);
        FB_API_ERROR_EMIT(api, err, return);
    } else {
        bytes = (GByteArray *) pload;
    }

    fb_util_debug_hexdump(FB_UTIL_DEBUG_LEVEL_INFO, bytes,
                          "Reading message (topic: %s)",
                          topic);

    for (i = 0; i < G_N_ELEMENTS(parsers); i++) {
        if (g_ascii_strcasecmp(topic, parsers[i].topic) == 0) {
            parsers[i].func(api, bytes);
            break;
        }
    }

    if (G_LIKELY(comp)) {
        g_byte_array_free(bytes, TRUE);
    }
}

FbApi *
fb_api_new(void)
{
    FbApi *api;
    FbApiPrivate *priv;

    api = g_object_new(FB_TYPE_API, NULL);
    priv = api->priv;

    g_signal_connect(priv->mqtt,
                     "connect",
                     G_CALLBACK(fb_api_cb_mqtt_connect),
                     api);
    g_signal_connect(priv->mqtt,
                     "error",
                     G_CALLBACK(fb_api_cb_mqtt_error),
                     api);
    g_signal_connect(priv->mqtt,
                     "open",
                     G_CALLBACK(fb_api_cb_mqtt_open),
                     api);
    g_signal_connect(priv->mqtt,
                     "publish",
                     G_CALLBACK(fb_api_cb_mqtt_publish),
                     api);

    return api;
}

void
fb_api_rehash(FbApi *api)
{
    FbApiPrivate *priv;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    if (priv->cid == NULL) {
        priv->cid = fb_util_rand_alnum(32);
    }

    if (priv->did == NULL) {
        priv->did = fb_util_rand_uuid();
    }

    if (priv->mid == 0) {
        priv->mid = g_random_int();
    }

    if (strlen(priv->cid) > 20) {
        priv->cid = g_realloc_n(priv->cid , 21, sizeof *priv->cid);
        priv->cid[20] = 0;
    }
}

gboolean
fb_api_is_invisible(FbApi *api)
{
    FbApiPrivate *priv;

    g_return_val_if_fail(FB_IS_API(api), FALSE);
    priv = api->priv;

    return priv->invisible;
}

void
fb_api_error(FbApi *api, FbApiError error, const gchar *format, ...)
{
    GError *err;
    va_list ap;

    g_return_if_fail(FB_IS_API(api));

    va_start(ap, format);
    err = g_error_new_valist(FB_API_ERROR, error, format, ap);
    va_end(ap);

    fb_api_error_emit(api, err);
}

void
fb_api_error_emit(FbApi *api, GError *error)
{
    g_return_if_fail(FB_IS_API(api));
    g_return_if_fail(error != NULL);

    g_signal_emit_by_name(api, "error", error);
    g_error_free(error);
}

static void
fb_api_cb_attach(FbHttpRequest *req, gpointer data)
{
    const gchar *str;
    FbApi *api = data;
    FbApiMessage *msg;
    FbJsonValues *values;
    gchar *name;
    GError *err = NULL;
    GSList *msgs = NULL;
    guint i;
    JsonNode *root;

    static const gchar *imgexts[] = {".jpg", ".png", ".gif"};

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.filename");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.redirect_uri");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    msg = fb_api_data_take(api, req);
    str = fb_json_values_next_str(values, NULL);
    name = g_ascii_strdown(str, -1);

    for (i = 0; i < G_N_ELEMENTS(imgexts); i++) {
        if (g_str_has_suffix(name, imgexts[i])) {
            msg->flags |= FB_API_MESSAGE_FLAG_IMAGE;
            break;
        }
    }

    g_free(name);
    msg->text = fb_json_values_next_str_dup(values, NULL);
    msgs = g_slist_prepend(msgs, msg);

    g_signal_emit_by_name(api, "messages", msgs);
    g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
    g_object_unref(values);
    json_node_free(root);

}

static void
fb_api_attach(FbApi *api, FbId aid, const gchar *msgid, FbApiMessage *msg)
{
    FbHttpRequest *req;
    FbHttpValues *prms;

    prms = fb_http_values_new();
    fb_http_values_set_str(prms, "mid", msgid);
    fb_http_values_set_strf(prms, "aid", "%" FB_ID_FORMAT, aid);

    req = fb_api_http_req(api, FB_API_URL_ATTACH, "getAttachment",
                          "messaging.getAttachment", prms,
                          fb_api_cb_attach);
    fb_api_data_set(api, req, msg, (GDestroyNotify) fb_api_message_free);
}

static void
fb_api_cb_work_peek(FbHttpRequest *req, gpointer data)
{
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    GError *err = NULL;
    JsonNode *root;
    gchar *community = NULL;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    /* The work_users[0] explicitly only handles the first user.
     * If more than one user is ever needed, this is what you want to change,
     * but as far as I know this feature (linked work accounts) is deprecated
     * and most users can detach their work accounts from their personal
     * accounts by assigning a password to the work account. */
    community = fb_json_node_get_str(root,
        "$.data.viewer.work_users[0].community.login_identifier", &err);

    FB_API_ERROR_EMIT(api, err,
        g_free(community);
        json_node_free(root);
        return;
    );

    priv->work_community_id = FB_ID_FROM_STR(community);

    fb_api_auth(api, "X", "X", "personal_to_work_switch");

    g_free(community);
    json_node_free(root);
}

static FbHttpRequest *
fb_api_work_peek(FbApi *api)
{
    FbHttpValues *prms;

    prms = fb_http_values_new();
    fb_http_values_set_int(prms, "doc_id", FB_API_WORK_COMMUNITY_PEEK);

    return fb_api_http_req(api, FB_API_URL_GQL, "WorkCommunityPeekQuery",
        "post", prms, fb_api_cb_work_peek);
}

static void
fb_api_cb_auth(FbHttpRequest *req, gpointer data)
{
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.access_token");

    /* extremely silly difference */
    if (priv->is_work) {
        fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.uid");
    } else {
        fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.uid");
    }

    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    g_free(priv->token);
    priv->token = fb_json_values_next_str_dup(values, NULL);

    if (priv->is_work) {
        priv->uid = FB_ID_FROM_STR(fb_json_values_next_str(values, "0"));
    } else {
        priv->uid = fb_json_values_next_int(values, 0);
    }

    if (priv->need_work_switch) {
        fb_api_work_peek(api);
        priv->need_work_switch = FALSE;
    } else {
        g_signal_emit_by_name(api, "auth");
    }

    g_object_unref(values);
    json_node_free(root);
}

void
fb_api_auth(FbApi *api, const gchar *user, const gchar *pass, const gchar *credentials_type)
{
    FbApiPrivate *priv = api->priv;
    FbHttpValues *prms;

    prms = fb_http_values_new();
    fb_http_values_set_str(prms, "email", user);
    fb_http_values_set_str(prms, "password", pass);

    if (credentials_type) {
        fb_http_values_set_str(prms, "credentials_type", credentials_type);
    }

    if (priv->sso_verifier) {
        fb_http_values_set_str(prms, "code_verifier", priv->sso_verifier);
        g_free(priv->sso_verifier);
        priv->sso_verifier = NULL;
    }

    if (priv->work_community_id) {
        fb_http_values_set_int(prms, "community_id", priv->work_community_id);
    }

    if (priv->is_work && priv->token) {
        fb_http_values_set_str(prms, "access_token", priv->token);
    }

    if (!(priv->machine_id) || strlen(priv->machine_id) == 0) {
        fb_http_values_set_str(prms, "generate_machine_id", "1");
    } else {
        fb_http_values_set_str(prms, "machine_id", priv->machine_id);
    }

    if (priv->uid &&
        priv->machine_id && strlen(priv->machine_id) > 0 &&
        priv->login_first_factor && strlen(priv->login_first_factor) > 0 &&
        priv->twofactor_code && strlen(priv->twofactor_code) > 0) {

        // Everything ready for the whole 2fa auth set

        // uid, set_int is fine here
        fb_http_values_set_int(prms, "uid", priv->uid);

        // device_id comes from somewhere else

        // credentials_type magic
        fb_http_values_set_str(prms, "credentials_type", "two_factor");

        // first_factor, yes cleverly wants it with different name than gives
        fb_http_values_set_str(prms, "first_factor", priv->login_first_factor);

        // twofactor_code
        fb_http_values_set_str(prms, "twofactor_code", priv->twofactor_code);

        // password actually now same as twofactor_code
        fb_http_values_set_str(prms, "password", priv->twofactor_code);

        // userid , same as uid. needs to be here for 2FA to work.
        fb_http_values_set_int(prms, "userid", priv->uid);

        // machine_id already there (otherwise we would not be in this loop)
    }

    fb_api_http_req(api, FB_API_URL_AUTH, "authenticate", "auth.login", prms,
                    fb_api_cb_auth);
}

static void
fb_api_cb_work_prelogin(FbHttpRequest *req, gpointer data)
{
    FbApiPreloginData *pata = data;
    FbApi *api = pata->api;
    FbApiPrivate *priv = api->priv;
    GError *err = NULL;
    JsonNode *root;
    gchar *status;
    gchar *user = pata->user;
    gchar *pass = pata->pass;

    g_free(pata);

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    status = fb_json_node_get_str(root, "$.status", &err);

    FB_API_ERROR_EMIT(api, err,
        json_node_free(root);
        return;
    );

    if (g_strcmp0(status, "can_login_password") == 0) {
        fb_api_auth(api, user, pass, "work_account_password");

    } else if (g_strcmp0(status, "can_login_via_linked_account") == 0) {
        fb_api_auth(api, user, pass, "personal_account_password_with_work_username");
        priv->need_work_switch = TRUE;

    } else if (g_strcmp0(status, "can_login_sso") == 0) {
        g_signal_emit_by_name(api, "work-sso-login");

    } else if (g_strcmp0(status, "cannot_login") == 0) {
        char *reason = fb_json_node_get_str(root, "$.cannot_login_reason", NULL);

        if (g_strcmp0(reason, "non_business_email") == 0) {
            fb_api_error(api, FB_API_ERROR_AUTH,
                         "Cannot login with non-business email. "
                         "Change the 'username' setting or disable 'work'");
        } else {
            char *title = fb_json_node_get_str(root, "$.error_title", NULL);
            char *body = fb_json_node_get_str(root, "$.error_body", NULL);

            fb_api_error(api, FB_API_ERROR_AUTH,
                         "Work prelogin failed (%s - %s)", title, body);

            g_free(title);
            g_free(body);
        }

        g_free(reason);

    } else if (g_strcmp0(status, "can_self_invite") == 0) {
        fb_api_error(api, FB_API_ERROR_AUTH, "Unknown email. "
                     "Change the 'username' setting or disable 'work'");
    }

    g_free(status);
    json_node_free(root);
}

void
fb_api_work_login(FbApi *api, gchar *user, gchar *pass)
{
    FbApiPrivate *priv = api->priv;
    FbHttpRequest *req;
    FbHttpValues *prms, *hdrs;
    FbApiPreloginData *pata = g_new0(FbApiPreloginData, 1);

    pata->api = api;
    pata->user = user;
    pata->pass = pass;

    priv->is_work = TRUE;

    req = fb_http_request_new(priv->http, FB_API_URL_WORK_PRELOGIN, TRUE,
        fb_api_cb_work_prelogin, pata);

    hdrs = fb_http_request_get_headers(req);
    fb_http_values_set_str(hdrs, "Authorization", "OAuth null");

    prms = fb_http_request_get_params(req);
    fb_http_values_set_str(prms, "email", user);
    fb_http_values_set_str(prms, "access_token",
        FB_WORK_API_KEY "|" FB_WORK_API_SECRET);

    fb_http_request_send(req);
}

gchar *
fb_api_work_gen_sso_url(FbApi *api, const gchar *user)
{
    FbApiPrivate *priv = api->priv;
    gchar *challenge, *verifier, *req_id, *email;
    gchar *ret;

    fb_util_gen_sso_verifier(&challenge, &verifier, &req_id);

    email = g_uri_escape_string(user, NULL, FALSE);

    ret = g_strdup_printf(FB_API_SSO_URL, req_id, challenge, email);

    g_free(req_id);
    g_free(challenge);
    g_free(email);

    g_free(priv->sso_verifier);
    priv->sso_verifier = verifier;

    return ret;
}

void
fb_api_work_got_nonce(FbApi *api, const gchar *url)
{
    gchar **split;
    gchar *uid = NULL;
    gchar *nonce = NULL;
    int i;

    if (!g_str_has_prefix(url, "fb-workchat-sso://sso/?")) {
        return;
    }

    split = g_strsplit(strchr(url, '?'), "&", -1);

    for (i = 0; split[i]; i++) {
        gchar *eq = strchr(split[i], '=');

        if (g_str_has_prefix(split[i], "uid=")) {
            uid = g_strstrip(eq + 1);
        } else if (g_str_has_prefix(split[i], "nonce=")) {
            nonce = g_strstrip(eq + 1);
        }
    }

    if (uid && nonce) {
        fb_api_auth(api, uid, nonce, "work_sso_nonce");
    }

    g_strfreev(split);
}

static gchar *
fb_api_user_icon_checksum(gchar *icon)
{
    gchar *csum;
    FbHttpValues *prms;

    if (G_UNLIKELY(icon == NULL)) {
        return NULL;
    }

    prms = fb_http_values_new();
    fb_http_values_parse(prms, icon, TRUE);
    csum = fb_http_values_dup_str(prms, "oh", NULL);
    fb_http_values_free(prms);

    if (G_UNLIKELY(csum == NULL)) {
        /* Revert to the icon URL as the unique checksum */
        csum = g_strdup(icon);
    }

    return csum;
}

static void
fb_api_cb_contact(FbHttpRequest *req, gpointer data)
{
    const gchar *str;
    FbApi *api = data;
    FbApiUser user;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *node;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    node = fb_json_node_get_nth(root, 0);

    if (node == NULL) {
        fb_api_error(api, FB_API_ERROR_GENERAL,
                     "Failed to obtain contact information");
        json_node_free(root);
        return;
    }

    values = fb_json_values_new(node);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.name");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.profile_pic_large.uri");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    fb_api_user_reset(&user, FALSE);
    str = fb_json_values_next_str(values, "0");
    user.uid = FB_ID_FROM_STR(str);
    user.name = fb_json_values_next_str_dup(values, NULL);
    user.icon = fb_json_values_next_str_dup(values, NULL);

    user.csum = fb_api_user_icon_checksum(user.icon);

    g_signal_emit_by_name(api, "contact", &user);
    fb_api_user_reset(&user, TRUE);
    g_object_unref(values);
    json_node_free(root);
}

void
fb_api_contact(FbApi *api, FbId uid)
{
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_arr_begin(bldr, "0");
    fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, uid);
    fb_json_bldr_arr_end(bldr);

    fb_json_bldr_add_str(bldr, "1", "true");
    fb_api_http_query(api, FB_API_QUERY_CONTACT, bldr, fb_api_cb_contact);
}

static GSList *
fb_api_cb_contacts_nodes(FbApi *api, JsonNode *root, GSList *users)
{
    const gchar *str;
    FbApiPrivate *priv = api->priv;
    FbApiUser *user;
    FbId uid;
    FbJsonValues *values;
    gboolean is_array;
    GError *err = NULL;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.represented_profile.id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.represented_profile.friendship_status");
    fb_json_values_add(values, FB_JSON_TYPE_BOOL, FALSE,
                       "$.is_on_viewer_contact_list");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.structured_name.text");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.hugePictureUrl.uri");

    is_array = (JSON_NODE_TYPE(root) == JSON_NODE_ARRAY);

    if (is_array) {
        fb_json_values_set_array(values, FALSE, "$");
    }

    while (fb_json_values_update(values, &err)) {
        gboolean in_contact_list;

        str = fb_json_values_next_str(values, "0");
        uid = FB_ID_FROM_STR(str);
        str = fb_json_values_next_str(values, NULL);
        in_contact_list = fb_json_values_next_bool(values, FALSE);

        if ((!in_contact_list && (g_strcmp0(str, "ARE_FRIENDS") != 0) &&
             (uid != priv->uid)) || (uid == 0))
        {
            if (!is_array) {
                break;
            }
            continue;
        }

        user = fb_api_user_dup(NULL, FALSE);
        user->uid = uid;
        user->name = fb_json_values_next_str_dup(values, NULL);
        user->icon = fb_json_values_next_str_dup(values, NULL);

        user->csum = fb_api_user_icon_checksum(user->icon);

        users = g_slist_prepend(users, user);

        if (!is_array) {
            break;
        }
    }

    g_object_unref(values);

    return users;
}

/* base64(contact:<our id>:<their id>:<whatever>) */
static GSList *
fb_api_cb_contacts_parse_removed(FbApi *api, JsonNode *node, GSList *users)
{
    gsize len;
    char **split;
    char *decoded = (char *) g_base64_decode(json_node_get_string(node), &len);

    g_return_val_if_fail(decoded[len] == '\0', users);
    g_return_val_if_fail(len == strlen(decoded), users);
    g_return_val_if_fail(g_str_has_prefix(decoded, "contact:"), users);

    split = g_strsplit_set(decoded, ":", 4);

    g_return_val_if_fail(g_strv_length(split) == 4, users);

    users = g_slist_prepend(users, g_strdup(split[2]));

    g_strfreev(split);
    g_free(decoded);

    return users;
}

static void
fb_api_cb_contacts(FbHttpRequest *req, gpointer data)
{
    const gchar *cursor;
    const gchar *delta_cursor;
    FbApi *api = data;
    FbApiPrivate *priv = api->priv;
    FbJsonValues *values;
    gboolean complete;
    gboolean is_delta;
    GError *err = NULL;
    GList *l;
    GSList *users = NULL;
    JsonNode *root;
    JsonNode *croot;
    JsonNode *node;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    croot = fb_json_node_get(root, "$.viewer.messenger_contacts.deltas", NULL);
    is_delta = (croot != NULL);

    if (!is_delta) {
        croot = fb_json_node_get(root, "$.viewer.messenger_contacts", NULL);
        node = fb_json_node_get(croot, "$.nodes", NULL);
        users = fb_api_cb_contacts_nodes(api, node, users);
        json_node_free(node);

    } else {
        GSList *added = NULL;
        GSList *removed = NULL;
        JsonArray *arr = fb_json_node_get_arr(croot, "$.nodes", NULL);
        GList *elms = json_array_get_elements(arr);

        for (l = elms; l != NULL; l = l->next) {
            if ((node = fb_json_node_get(l->data, "$.added", NULL))) {
                added = fb_api_cb_contacts_nodes(api, node, added);
                json_node_free(node);
            }

            if ((node = fb_json_node_get(l->data, "$.removed", NULL))) {
                removed = fb_api_cb_contacts_parse_removed(api, node, removed);
                json_node_free(node);
            }
        }

        g_signal_emit_by_name(api, "contacts-delta", added, removed);

        g_slist_free_full(added, (GDestroyNotify) fb_api_user_free);
        g_slist_free_full(removed, (GDestroyNotify) g_free);

        g_list_free(elms);
        json_array_unref(arr);
    }

    values = fb_json_values_new(croot);
    fb_json_values_add(values, FB_JSON_TYPE_BOOL, FALSE,
                       "$.page_info.has_next_page");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.page_info.delta_cursor");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.page_info.end_cursor");
    fb_json_values_update(values, NULL);

    complete = !fb_json_values_next_bool(values, FALSE);

    delta_cursor = fb_json_values_next_str(values, NULL);

    cursor = fb_json_values_next_str(values, NULL);

    if (G_UNLIKELY(err == NULL)) {

        if (is_delta || complete) {
            g_free(priv->contacts_delta);
            priv->contacts_delta = g_strdup(is_delta ? cursor : delta_cursor);
        }

        if (users || (complete && !is_delta)) {
            g_signal_emit_by_name(api, "contacts", users, complete);
        }

        if (!complete) {
            fb_api_contacts_after(api, cursor);
        }
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(users, (GDestroyNotify) fb_api_user_free);
    g_object_unref(values);

    json_node_free(croot);
    json_node_free(root);
}

void
fb_api_contacts(FbApi *api)
{
    FbApiPrivate *priv;
    JsonBuilder *bldr;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    if (priv->contacts_delta) {
        fb_api_contacts_delta(api, priv->contacts_delta);
        return;
    }

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_arr_begin(bldr, "0");
    fb_json_bldr_add_str(bldr, NULL, "user");
    fb_json_bldr_arr_end(bldr);

    fb_json_bldr_add_str(bldr, "1", G_STRINGIFY(FB_API_CONTACTS_COUNT));
    fb_api_http_query(api, FB_API_QUERY_CONTACTS, bldr,
                      fb_api_cb_contacts);
}

static void
fb_api_contacts_after(FbApi *api, const gchar *cursor)
{
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_arr_begin(bldr, "0");
    fb_json_bldr_add_str(bldr, NULL, "user");
    fb_json_bldr_arr_end(bldr);

    fb_json_bldr_add_str(bldr, "1", cursor);
    fb_json_bldr_add_str(bldr, "2", G_STRINGIFY(FB_API_CONTACTS_COUNT));
    fb_api_http_query(api, FB_API_QUERY_CONTACTS_AFTER, bldr,
                      fb_api_cb_contacts);
}

void
fb_api_contacts_delta(FbApi *api, const gchar *delta_cursor)
{
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);

    fb_json_bldr_add_str(bldr, "0", delta_cursor);

    fb_json_bldr_arr_begin(bldr, "1");
    fb_json_bldr_add_str(bldr, NULL, "user");
    fb_json_bldr_arr_end(bldr);

    fb_json_bldr_add_str(bldr, "2", G_STRINGIFY(FB_API_CONTACTS_COUNT));
    fb_api_http_query(api, FB_API_QUERY_CONTACTS_DELTA, bldr,
                      fb_api_cb_contacts);
}

void
fb_api_connect(FbApi *api, gboolean invisible)
{
    FbApiPrivate *priv;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    priv->invisible = invisible;
    fb_mqtt_open(priv->mqtt, FB_MQTT_HOST, FB_MQTT_PORT);
}

void
fb_api_disconnect(FbApi *api)
{
    FbApiPrivate *priv;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    fb_mqtt_disconnect(priv->mqtt);
}

static void
fb_api_message_send(FbApi *api, FbApiMessage *msg)
{
    const gchar *tpfx;
    FbApiPrivate *priv = api->priv;
    FbId id;
    FbId mid;
    gchar *json;
    JsonBuilder *bldr;

    mid = FB_API_MSGID(g_get_real_time() / 1000, g_random_int());
    priv->lastmid = mid;

    if (msg->tid != 0) {
        tpfx = "tfbid_";
        id = msg->tid;
    } else {
        tpfx = "";
        id = msg->uid;
    }

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_str(bldr, "body", msg->text);
    fb_json_bldr_add_strf(bldr, "msgid", "%" FB_ID_FORMAT, mid);
    fb_json_bldr_add_strf(bldr, "sender_fbid", "%" FB_ID_FORMAT, priv->uid);
    fb_json_bldr_add_strf(bldr, "to", "%s%" FB_ID_FORMAT, tpfx, id);

    json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
    fb_api_publish(api, "/send_message2", "%s", json);
    g_free(json);
}

static gboolean
fb_api_is_message_not_empty(const gchar *text)
{
    while (*text && *text == ' ') {
        text++;
    }
    return *text != '\0';
}

void
fb_api_message(FbApi *api, FbId id, gboolean thread, const gchar *text)
{
    FbApiMessage *msg;
    FbApiPrivate *priv;
    gboolean empty;

    g_return_if_fail(FB_IS_API(api));
    g_return_if_fail(text != NULL);
    g_return_if_fail(fb_api_is_message_not_empty(text));
    priv = api->priv;

    msg = fb_api_message_dup(NULL, FALSE);
    msg->text = g_strdup(text);

    if (thread) {
        msg->tid = id;
    } else {
        msg->uid = id;
    }

    empty = g_queue_is_empty(priv->msgs);
    g_queue_push_tail(priv->msgs, msg);

    if (empty && fb_mqtt_connected(priv->mqtt, FALSE)) {
        fb_api_message_send(api, msg);
    }
}

void
fb_api_publish(FbApi *api, const gchar *topic, const gchar *format, ...)
{
    FbApiPrivate *priv;
    GByteArray *bytes;
    GByteArray *cytes;
    gchar *msg;
    GError *err = NULL;
    va_list ap;

    g_return_if_fail(FB_IS_API(api));
    g_return_if_fail(topic != NULL);
    g_return_if_fail(format != NULL);
    priv = api->priv;

    va_start(ap, format);
    msg = g_strdup_vprintf(format, ap);
    va_end(ap);

    bytes = g_byte_array_new_take((guint8 *) msg, strlen(msg));
    cytes = fb_util_zlib_deflate(bytes, &err);

    FB_API_ERROR_EMIT(api, err,
        g_byte_array_free(bytes, TRUE);
        return;
    );

    fb_util_debug_hexdump(FB_UTIL_DEBUG_LEVEL_INFO, bytes,
                          "Writing message (topic: %s)",
                          topic);

    fb_mqtt_publish(priv->mqtt, topic, cytes);
    g_byte_array_free(cytes, TRUE);
    g_byte_array_free(bytes, TRUE);
}

void
fb_api_read(FbApi *api, FbId id, gboolean thread)
{
    const gchar *key;
    FbApiPrivate *priv;
    gchar *json;
    JsonBuilder *bldr;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_bool(bldr, "state", TRUE);
    fb_json_bldr_add_int(bldr, "syncSeqId", priv->sid);
    fb_json_bldr_add_str(bldr, "mark", "read");

    key = thread ? "threadFbId" : "otherUserFbId";
    fb_json_bldr_add_strf(bldr, key, "%" FB_ID_FORMAT, id);

    json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
    fb_api_publish(api, "/mark_thread", "%s", json);
    g_free(json);
}

static GSList *
fb_api_cb_unread_parse_attach(FbApi *api, const gchar *mid, FbApiMessage *msg,
                              GSList *msgs, JsonNode *root, GError **error)
{
    const gchar *str;
    FbApiMessage *dmsg;
    FbId id;
    FbJsonValues *values;
    GError *err = NULL;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.attachment_fbid");
    fb_json_values_set_array(values, FALSE, "$.blob_attachments");

    while (fb_json_values_update(values, &err)) {
        str = fb_json_values_next_str(values, NULL);
        id = FB_ID_FROM_STR(str);
        dmsg = fb_api_message_dup(msg, FALSE);
        fb_api_attach(api, id, mid, dmsg);
    }

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
    }

    g_object_unref(values);
    return msgs;
}

static void
fb_api_cb_unread_msgs(FbHttpRequest *req, gpointer data)
{
    const gchar *body;
    const gchar *str;
    FbApi *api = data;
    FbApiMessage *dmsg;
    FbApiMessage msg;
    FbId id;
    FbId tid;
    FbJsonValues *values;
    gchar *xma;
    GError *err = NULL;
    GSList *msgs = NULL;
    JsonNode *node;
    JsonNode *root;
    JsonNode *xode;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    node = fb_json_node_get_nth(root, 0);

    if (node == NULL) {
        fb_api_error(api, FB_API_ERROR_GENERAL,
                     "Failed to obtain unread messages");
        json_node_free(root);
        return;
    }

    values = fb_json_values_new(node);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.thread_key.thread_fbid");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        return;
    );

    fb_api_message_reset(&msg, FALSE);
    str = fb_json_values_next_str(values, "0");
    tid = FB_ID_FROM_STR(str);
    g_object_unref(values);

    values = fb_json_values_new(node);
    fb_json_values_add(values, FB_JSON_TYPE_BOOL, TRUE, "$.unread");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
                       "$.message_sender.messaging_actor.id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.message.text");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.timestamp_precise");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.sticker.id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.message_id");
    fb_json_values_set_array(values, FALSE, "$.messages.nodes");

    while (fb_json_values_update(values, &err)) {
        if (!fb_json_values_next_bool(values, FALSE)) {
            continue;
        }

        str = fb_json_values_next_str(values, "0");
        body = fb_json_values_next_str(values, NULL);

        fb_api_message_reset(&msg, FALSE);
        msg.uid = FB_ID_FROM_STR(str);
        msg.tid = tid;

        str = fb_json_values_next_str(values, "0");
        msg.tstamp = g_ascii_strtoll(str, NULL, 10);

        if (body != NULL) {
            dmsg = fb_api_message_dup(&msg, FALSE);
            dmsg->text = g_strdup(body);
            msgs = g_slist_prepend(msgs, dmsg);
        }

        str = fb_json_values_next_str(values, NULL);

        if (str != NULL) {
            dmsg = fb_api_message_dup(&msg, FALSE);
            id = FB_ID_FROM_STR(str);
            fb_api_sticker(api, id, dmsg);
        }

        node = fb_json_values_get_root(values);
        xode = fb_json_node_get(node, "$.extensible_attachment", NULL);

        if (xode != NULL) {
            xma = fb_api_xma_parse(api, body, xode, &err);

            if (xma != NULL) {
                dmsg = fb_api_message_dup(&msg, FALSE);
                dmsg->text = xma;
                msgs = g_slist_prepend(msgs, dmsg);
            }

            json_node_free(xode);

            if (G_UNLIKELY(err != NULL)) {
                break;
            }
        }

        str = fb_json_values_next_str(values, NULL);

        if (str == NULL) {
            continue;
        }

        msgs = fb_api_cb_unread_parse_attach(api, str, &msg, msgs, node, &err);

        if (G_UNLIKELY(err != NULL)) {
            break;
        }
    }

    if (G_UNLIKELY(err == NULL)) {
        msgs = g_slist_reverse(msgs);
        g_signal_emit_by_name(api, "messages", msgs);
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
    g_object_unref(values);
    json_node_free(root);
}

static void
fb_api_cb_unread(FbHttpRequest *req, gpointer data)
{
    const gchar *id;
    FbApi *api = data;
    FbJsonValues *values;
    GError *err = NULL;
    gint64 count;
    JsonBuilder *bldr;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_INT, TRUE, "$.unread_count");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.thread_key.other_user_id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.thread_key.thread_fbid");
    fb_json_values_set_array(values, FALSE, "$.viewer.message_threads.nodes");

    while (fb_json_values_update(values, &err)) {
        count = fb_json_values_next_int(values, -5);

        if (count < 1) {
            continue;
        }

        id = fb_json_values_next_str(values, NULL);

        if (id == NULL) {
            id = fb_json_values_next_str(values, "0");
        }

        bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
        fb_json_bldr_arr_begin(bldr, "0");
        fb_json_bldr_add_str(bldr, NULL, id);
        fb_json_bldr_arr_end(bldr);

        fb_json_bldr_add_str(bldr, "10", "true");
        fb_json_bldr_add_str(bldr, "11", "true");
        fb_json_bldr_add_int(bldr, "12", count);
        fb_json_bldr_add_str(bldr, "13", "false");
        fb_api_http_query(api, FB_API_QUERY_THREAD, bldr,
                          fb_api_cb_unread_msgs);
    }

    if (G_UNLIKELY(err != NULL)) {
        fb_api_error_emit(api, err);
    }

    g_object_unref(values);
    json_node_free(root);
}

void
fb_api_unread(FbApi *api)
{
    FbApiPrivate *priv;
    JsonBuilder *bldr;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    if (priv->unread < 1) {
        return;
    }

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_str(bldr, "2", "true");
    fb_json_bldr_add_int(bldr, "1", priv->unread);
    fb_json_bldr_add_str(bldr, "12", "true");
    fb_json_bldr_add_str(bldr, "13", "false");
    fb_api_http_query(api, FB_API_QUERY_THREADS, bldr,
                      fb_api_cb_unread);
}

static void
fb_api_cb_sticker(FbHttpRequest *req, gpointer data)
{
    FbApi *api = data;
    FbApiMessage *msg;
    FbJsonValues *values;
    GError *err = NULL;
    GSList *msgs = NULL;
    JsonNode *node;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    node = fb_json_node_get_nth(root, 0);
    values = fb_json_values_new(node);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.thread_image.uri");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    msg = fb_api_data_take(api, req);
    msg->flags |= FB_API_MESSAGE_FLAG_IMAGE;
    msg->text = fb_json_values_next_str_dup(values, NULL);
    msgs = g_slist_prepend(msgs, msg);

    g_signal_emit_by_name(api, "messages", msgs);
    g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
    g_object_unref(values);
    json_node_free(root);
}

static void
fb_api_sticker(FbApi *api, FbId sid, FbApiMessage *msg)
{
    JsonBuilder *bldr;
    FbHttpRequest *req;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_arr_begin(bldr, "0");
    fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, sid);
    fb_json_bldr_arr_end(bldr);

    req = fb_api_http_query(api, FB_API_QUERY_STICKER, bldr,
                            fb_api_cb_sticker);
    fb_api_data_set(api, req, msg, (GDestroyNotify) fb_api_message_free);
}

static gboolean
fb_api_thread_parse(FbApi *api, FbApiThread *thrd, JsonNode *root,
                    GError **error)
{
    const gchar *str;
    FbApiPrivate *priv = api->priv;
    FbApiUser *user;
    FbId uid;
    FbJsonValues *values;
    gboolean haself = FALSE;
    guint num_users = 0;
    GError *err = NULL;

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE,
                       "$.thread_key.thread_fbid");
    fb_json_values_add(values, FB_JSON_TYPE_STR, FALSE, "$.name");
    fb_json_values_update(values, &err);

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
        g_object_unref(values);
        return FALSE;
    }

    str = fb_json_values_next_str(values, NULL);

    if (str == NULL) {
        g_object_unref(values);
        return FALSE;
    }

    thrd->tid = FB_ID_FROM_STR(str);
    thrd->topic = fb_json_values_next_str_dup(values, NULL);
    g_object_unref(values);

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
                       "$.messaging_actor.id");
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE,
                       "$.messaging_actor.name");
    fb_json_values_set_array(values, TRUE, "$.all_participants.nodes");

    while (fb_json_values_update(values, &err)) {
        str = fb_json_values_next_str(values, "0");
        uid = FB_ID_FROM_STR(str);
        num_users++;

        if (uid != priv->uid) {
            user = fb_api_user_dup(NULL, FALSE);
            user->uid = uid;
            user->name = fb_json_values_next_str_dup(values, NULL);
            thrd->users = g_slist_prepend(thrd->users, user);
        } else {
            haself = TRUE;
        }
    }

    if (G_UNLIKELY(err != NULL)) {
        g_propagate_error(error, err);
        fb_api_thread_reset(thrd, TRUE);
        g_object_unref(values);
        return FALSE;
    }

    if (num_users < 2 || !haself) {
        g_object_unref(values);
        return FALSE;
    }

    g_object_unref(values);
    return TRUE;
}

static void
fb_api_cb_thread(FbHttpRequest *req, gpointer data)
{
    FbApi *api = data;
    FbApiThread thrd;
    GError *err = NULL;
    JsonNode *node;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    node = fb_json_node_get_nth(root, 0);

    if (node == NULL) {
        fb_api_error(api, FB_API_ERROR_GENERAL,
                     "Failed to obtain thread information");
        json_node_free(root);
        return;
    }

    fb_api_thread_reset(&thrd, FALSE);

    if (!fb_api_thread_parse(api, &thrd, node, &err)) {
        if (G_LIKELY(err == NULL)) {
            if (thrd.tid) {
                g_signal_emit_by_name(api, "thread-kicked", &thrd);
            } else {
                fb_api_error(api, FB_API_ERROR_GENERAL,
                             "Failed to parse thread information");
            }
        } else {
            fb_api_error_emit(api, err);
        }
    } else {
        g_signal_emit_by_name(api, "thread", &thrd);
    }

    fb_api_thread_reset(&thrd, TRUE);
    json_node_free(root);
}

void
fb_api_thread(FbApi *api, FbId tid)
{
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_arr_begin(bldr, "0");
    fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, tid);
    fb_json_bldr_arr_end(bldr);

    fb_json_bldr_add_str(bldr, "10", "false");
    fb_json_bldr_add_str(bldr, "11", "false");
    fb_json_bldr_add_str(bldr, "13", "false");
    fb_api_http_query(api, FB_API_QUERY_THREAD, bldr, fb_api_cb_thread);
}

static void
fb_api_cb_thread_create(FbHttpRequest *req, gpointer data)
{
    const gchar *str;
    FbApi *api = data;
    FbId tid;
    FbJsonValues *values;
    GError *err = NULL;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    values = fb_json_values_new(root);
    fb_json_values_add(values, FB_JSON_TYPE_STR, TRUE, "$.id");
    fb_json_values_update(values, &err);

    FB_API_ERROR_EMIT(api, err,
        g_object_unref(values);
        json_node_free(root);
        return;
    );

    str = fb_json_values_next_str(values, "0");
    tid = FB_ID_FROM_STR(str);
    g_signal_emit_by_name(api, "thread-create", tid);

    g_object_unref(values);
    json_node_free(root);
}

void
fb_api_thread_create(FbApi *api, GSList *uids)
{
    FbApiPrivate *priv;
    FbHttpValues *prms;
    FbId *uid;
    gchar *json;
    GSList *l;
    JsonBuilder *bldr;

    g_return_if_fail(FB_IS_API(api));
    g_warn_if_fail(g_slist_length(uids) > 1);
    priv = api->priv;

    bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
    fb_json_bldr_obj_begin(bldr, NULL);
    fb_json_bldr_add_str(bldr, "type", "id");
    fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, priv->uid);
    fb_json_bldr_obj_end(bldr);

    for (l = uids; l != NULL; l = l->next) {
        uid = l->data;
        fb_json_bldr_obj_begin(bldr, NULL);
        fb_json_bldr_add_str(bldr, "type", "id");
        fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, *uid);
        fb_json_bldr_obj_end(bldr);
    }

    json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);
    prms = fb_http_values_new();
    fb_http_values_set_str(prms, "recipients", json);
    fb_api_http_req(api, FB_API_URL_THREADS, "createGroup", "POST", prms,
                    fb_api_cb_thread_create);
    g_free(json);
}

void
fb_api_thread_invite(FbApi *api, FbId tid, FbId uid)
{
    FbHttpValues *prms;
    gchar *json;
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
    fb_json_bldr_obj_begin(bldr, NULL);
    fb_json_bldr_add_str(bldr, "type", "id");
    fb_json_bldr_add_strf(bldr, "id", "%" FB_ID_FORMAT, uid);
    fb_json_bldr_obj_end(bldr);
    json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);

    prms = fb_http_values_new();
    fb_http_values_set_str(prms, "to", json);
    fb_http_values_set_strf(prms, "id", "t_%" FB_ID_FORMAT, tid);
    fb_api_http_req(api, FB_API_URL_PARTS, "addMembers", "POST", prms,
                    fb_api_cb_http_bool);
    g_free(json);
}

void
fb_api_thread_remove(FbApi *api, FbId tid, FbId uid)
{
    FbApiPrivate *priv;
    FbHttpValues *prms;
    gchar *json;
    JsonBuilder *bldr;

    g_return_if_fail(FB_IS_API(api));
    priv = api->priv;

    prms = fb_http_values_new();
    fb_http_values_set_strf(prms, "id", "t_%" FB_ID_FORMAT, tid);

    if (uid == 0) {
        uid = priv->uid;
    }

    if (uid != priv->uid) {
        bldr = fb_json_bldr_new(JSON_NODE_ARRAY);
        fb_json_bldr_add_strf(bldr, NULL, "%" FB_ID_FORMAT, uid);
        json = fb_json_bldr_close(bldr, JSON_NODE_ARRAY, NULL);
        fb_http_values_set_str(prms, "to", json);
        g_free(json);
    }

    fb_api_http_req(api, FB_API_URL_PARTS, "removeMembers", "DELETE", prms,
                    fb_api_cb_http_bool);
}

void
fb_api_thread_topic(FbApi *api, FbId tid, const gchar *topic)
{
    FbHttpValues *prms;

    prms = fb_http_values_new();
    fb_http_values_set_str(prms, "name", topic);
    fb_http_values_set_int(prms, "tid", tid);
    fb_api_http_req(api, FB_API_URL_TOPIC, "setThreadName",
                    "messaging.setthreadname", prms,
                    fb_api_cb_http_bool);
}

static void
fb_api_cb_threads(FbHttpRequest *req, gpointer data)
{
    FbApi *api = data;
    FbApiThread *dthrd;
    FbApiThread thrd;
    GError *err = NULL;
    GList *elms;
    GList *l;
    GSList *thrds = NULL;
    JsonArray *arr;
    JsonNode *root;

    if (!fb_api_http_chk(api, req, &root)) {
        return;
    }

    arr = fb_json_node_get_arr(root, "$.viewer.message_threads.nodes",
                               &err);
    FB_API_ERROR_EMIT(api, err,
        json_node_free(root);
        return;
    );

    elms = json_array_get_elements(arr);

    for (l = elms; l != NULL; l = l->next) {
        fb_api_thread_reset(&thrd, FALSE);

        if (fb_api_thread_parse(api, &thrd, l->data, &err)) {
            dthrd = fb_api_thread_dup(&thrd, FALSE);
            thrds = g_slist_prepend(thrds, dthrd);
        } else {
            fb_api_thread_reset(&thrd, TRUE);
        }

        if (G_UNLIKELY(err != NULL)) {
            break;
        }
    }

    if (G_LIKELY(err == NULL)) {
        thrds = g_slist_reverse(thrds);
        g_signal_emit_by_name(api, "threads", thrds);
    } else {
        fb_api_error_emit(api, err);
    }

    g_slist_free_full(thrds, (GDestroyNotify) fb_api_thread_free);
    g_list_free(elms);
    json_array_unref(arr);
    json_node_free(root);
}

void
fb_api_threads(FbApi *api)
{
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_str(bldr, "2", "true");
    fb_json_bldr_add_str(bldr, "12", "false");
    fb_json_bldr_add_str(bldr, "13", "false");
    fb_api_http_query(api, FB_API_QUERY_THREADS, bldr, fb_api_cb_threads);
}

void
fb_api_typing(FbApi *api, FbId uid, gboolean state)
{
    gchar *json;
    JsonBuilder *bldr;

    bldr = fb_json_bldr_new(JSON_NODE_OBJECT);
    fb_json_bldr_add_int(bldr, "state", state != 0);
    fb_json_bldr_add_strf(bldr, "to", "%" FB_ID_FORMAT, uid);

    json = fb_json_bldr_close(bldr, JSON_NODE_OBJECT, NULL);
    fb_api_publish(api, "/typing", "%s", json);
    g_free(json);
}

FbApiEvent *
fb_api_event_dup(const FbApiEvent *event, gboolean deep)
{
    FbApiEvent *ret;

    if (event == NULL) {
        return g_new0(FbApiEvent, 1);
    }

    ret = g_memdup(event, sizeof *event);

    if (deep) {
        ret->text = g_strdup(event->text);
    }

    return ret;
}

void
fb_api_event_reset(FbApiEvent *event, gboolean deep)
{
    g_return_if_fail(event != NULL);

    if (deep) {
        g_free(event->text);
    }

    memset(event, 0, sizeof *event);
}

void
fb_api_event_free(FbApiEvent *event)
{
    if (G_LIKELY(event != NULL)) {
        g_free(event->text);
        g_free(event);
    }
}

FbApiMessage *
fb_api_message_dup(const FbApiMessage *msg, gboolean deep)
{
    FbApiMessage *ret;

    if (msg == NULL) {
        return g_new0(FbApiMessage, 1);
    }

    ret = g_memdup(msg, sizeof *msg);

    if (deep) {
        ret->text = g_strdup(msg->text);
    }

    return ret;
}

void
fb_api_message_reset(FbApiMessage *msg, gboolean deep)
{
    g_return_if_fail(msg != NULL);

    if (deep) {
        g_free(msg->text);
    }

    memset(msg, 0, sizeof *msg);
}

void
fb_api_message_free(FbApiMessage *msg)
{
    if (G_LIKELY(msg != NULL)) {
        g_free(msg->text);
        g_free(msg);
    }
}

FbApiPresence *
fb_api_presence_dup(const FbApiPresence *pres)
{
    if (pres == NULL) {
        return g_new0(FbApiPresence, 1);
    }

    return g_memdup(pres, sizeof *pres);
}

void
fb_api_presence_reset(FbApiPresence *pres)
{
    g_return_if_fail(pres != NULL);
    memset(pres, 0, sizeof *pres);
}

void
fb_api_presence_free(FbApiPresence *pres)
{
    if (G_LIKELY(pres != NULL)) {
        g_free(pres);
    }
}

FbApiThread *
fb_api_thread_dup(const FbApiThread *thrd, gboolean deep)
{
    FbApiThread *ret;
    FbApiUser *user;
    GSList *l;

    if (thrd == NULL) {
        return g_new0(FbApiThread, 1);
    }

    ret = g_memdup(thrd, sizeof *thrd);

    if (deep) {
        for (ret->users = NULL, l = thrd->users; l != NULL; l = l->next) {
            user = fb_api_user_dup(l->data, TRUE);
            ret->users = g_slist_prepend(ret->users, user);
        }

        ret->topic = g_strdup(thrd->topic);
        ret->users = g_slist_reverse(ret->users);
    }

    return ret;
}

void
fb_api_thread_reset(FbApiThread *thrd, gboolean deep)
{
    g_return_if_fail(thrd != NULL);

    if (deep) {
        g_slist_free_full(thrd->users, (GDestroyNotify) fb_api_user_free);
        g_free(thrd->topic);
    }

    memset(thrd, 0, sizeof *thrd);
}

void
fb_api_thread_free(FbApiThread *thrd)
{
    if (G_LIKELY(thrd != NULL)) {
        g_slist_free_full(thrd->users, (GDestroyNotify) fb_api_user_free);
        g_free(thrd->topic);
        g_free(thrd);
    }
}

FbApiTyping *
fb_api_typing_dup(const FbApiTyping *typg)
{
    if (typg == NULL) {
        return g_new0(FbApiTyping, 1);
    }

    return g_memdup(typg, sizeof *typg);
}

void
fb_api_typing_reset(FbApiTyping *typg)
{
    g_return_if_fail(typg != NULL);
    memset(typg, 0, sizeof *typg);
}

void
fb_api_typing_free(FbApiTyping *typg)
{
    if (G_LIKELY(typg != NULL)) {
        g_free(typg);
    }
}

FbApiUser *
fb_api_user_dup(const FbApiUser *user, gboolean deep)
{
    FbApiUser *ret;

    if (user == NULL) {
        return g_new0(FbApiUser, 1);
    }

    ret = g_memdup(user, sizeof *user);

    if (deep) {
        ret->name = g_strdup(user->name);
        ret->icon = g_strdup(user->icon);
        ret->csum = g_strdup(user->csum);
    }

    return ret;
}

void
fb_api_user_reset(FbApiUser *user, gboolean deep)
{
    g_return_if_fail(user != NULL);

    if (deep) {
        g_free(user->name);
        g_free(user->icon);
        g_free(user->csum);
    }

    memset(user, 0, sizeof *user);
}

void
fb_api_user_free(FbApiUser *user)
{
    if (G_LIKELY(user != NULL)) {
        g_free(user->name);
        g_free(user->icon);
        g_free(user->csum);
        g_free(user);
    }
}

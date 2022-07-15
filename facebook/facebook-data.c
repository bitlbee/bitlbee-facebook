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

#include <string.h>

#include "facebook-api.h"
#include "facebook-data.h"

struct _FbDataPrivate
{
    FbApi *api;
    struct im_connection *ic;
    GQueue *msgs;
    GQueue *tids;
    GHashTable *evs;
    GHashTable *gcs;
};

static const gchar *fb_props_strs[] = {
    "cid",
    "did",
    "stoken",
    "token",
    "machine_id",
    "login_first_factor",
    "twofactor_code"
};

G_DEFINE_TYPE_WITH_PRIVATE(FbData, fb_data, G_TYPE_OBJECT);

static void
fb_data_dispose(GObject *obj)
{
    FbDataPrivate *priv = FB_DATA(obj)->priv;
    GHashTableIter iter;
    gpointer ptr;

    g_object_unref(priv->api);
    g_hash_table_iter_init(&iter, priv->evs);

    while (g_hash_table_iter_next(&iter, NULL, &ptr)) {
        g_hash_table_iter_remove(&iter);
        b_event_remove(GPOINTER_TO_UINT(ptr));
    }

    g_hash_table_iter_init(&iter, priv->gcs);

    while (g_hash_table_iter_next(&iter, NULL, &ptr)) {
        g_hash_table_iter_remove(&iter);
        imcb_chat_free(ptr);
    }

    g_queue_free_full(priv->msgs, (GDestroyNotify) fb_api_message_free);
    g_queue_free_full(priv->tids, g_free);

    g_hash_table_destroy(priv->evs);
    g_hash_table_destroy(priv->gcs);
}

static void
fb_data_class_init(FbDataClass *klass)
{
    GObjectClass *gklass = G_OBJECT_CLASS(klass);

    gklass->dispose = fb_data_dispose;
}

static void
fb_data_init(FbData *fata)
{
    FbDataPrivate *priv;

    priv = fb_data_get_instance_private(fata);
    fata->priv = priv;

    priv->api = fb_api_new();
    priv->msgs = g_queue_new();
    priv->tids = g_queue_new();
    priv->evs = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    priv->gcs = g_hash_table_new(g_direct_hash, g_direct_equal);
}

FbData *
fb_data_new(account_t *acct)
{
    FbData *fata;
    FbDataPrivate *priv;

    fata = g_object_new(FB_TYPE_DATA, NULL);
    priv = fata->priv;

    priv->ic = imcb_new(acct);
    priv->ic->proto_data = fata;
    return fata;
}

gboolean
fb_data_load(FbData *fata)
{
    account_t *acct;
    const gchar *str;
    FbDataPrivate *priv;
    FbId id;
    gboolean ret = TRUE;
    guint i;
    guint64 uint;
    GValue val = G_VALUE_INIT;
    int num;

    g_return_val_if_fail(FB_IS_DATA(fata), FALSE);
    priv = fata->priv;
    acct = priv->ic->acc;

    for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
        str = set_getstr(&acct->set, fb_props_strs[i]);

        if (str == NULL) {
            ret = FALSE;
        }

        g_value_init(&val, G_TYPE_STRING);
        g_value_set_string(&val, str);
        g_object_set_property(G_OBJECT(priv->api), fb_props_strs[i],
                              &val);
        g_value_unset(&val);
    }

    str = set_getstr(&acct->set, "mid");

    if (str != NULL) {
        uint = g_ascii_strtoull(str, NULL, 10);
        g_value_init(&val, G_TYPE_UINT64);
        g_value_set_uint64(&val, uint);
        g_object_set_property(G_OBJECT(priv->api), "mid", &val);
        g_value_unset(&val);
    } else {
        ret = FALSE;
    }

    str = set_getstr(&acct->set, "uid");

    if (str != NULL) {
        id = FB_ID_FROM_STR(str);
        g_value_init(&val, FB_TYPE_ID);
        g_value_set_int64(&val, id);
        g_object_set_property(G_OBJECT(priv->api), "uid", &val);
        g_value_unset(&val);
    } else {
        ret = FALSE;
    }

    num = set_getint(&acct->set, "tweak");
    if (num != 0) {
        g_value_init(&val, G_TYPE_INT);
        g_value_set_int(&val, num);
        g_object_set_property(G_OBJECT(priv->api), "tweak", &val);
        g_value_unset(&val);
    }

    num = set_getbool(&acct->set, "work");
    if (num != 0) {
        g_value_init(&val, G_TYPE_BOOLEAN);
        g_value_set_boolean(&val, num);
        g_object_set_property(G_OBJECT(priv->api), "work", &val);
        g_value_unset(&val);
    }

    fb_api_rehash(priv->api);
    return ret;
}

void
fb_data_save(FbData *fata)
{
    account_t *acct;
    const gchar *str;
    FbDataPrivate *priv;
    gchar *dup;
    guint i;
    guint64 uint;
    GValue val = G_VALUE_INIT;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;
    acct = priv->ic->acc;

    for (i = 0; i < G_N_ELEMENTS(fb_props_strs); i++) {
        g_value_init(&val, G_TYPE_STRING);
        g_object_get_property(G_OBJECT(priv->api), fb_props_strs[i],
                              &val);
        str = g_value_get_string(&val);
        set_setstr(&acct->set, fb_props_strs[i], (gchar *) str);
        g_value_unset(&val);
    }

    g_value_init(&val, G_TYPE_UINT64);
    g_object_get_property(G_OBJECT(priv->api), "mid", &val);
    uint = g_value_get_uint64(&val);
    g_value_unset(&val);

    dup = g_strdup_printf("%" G_GINT64_FORMAT, uint);
    set_setstr(&acct->set, "mid", dup);
    g_free(dup);

    g_value_init(&val, G_TYPE_INT64);
    g_object_get_property(G_OBJECT(priv->api), "uid", &val);
    uint = g_value_get_int64(&val);
    g_value_unset(&val);

    dup = g_strdup_printf("%" FB_ID_FORMAT, uint);
    set_setstr(&acct->set, "uid", dup);
    g_free(dup);
}

void
fb_data_add_groupchat(FbData *fata, struct groupchat *gc)
{
    FbDataPrivate *priv;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    g_hash_table_replace(priv->gcs, gc, gc);
}

void
fb_data_remove_groupchat(FbData *fata, struct groupchat *gc)
{
    FbDataPrivate *priv;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    g_hash_table_remove(priv->gcs, gc);
}

void
fb_data_add_thread_head(FbData *fata, FbId tid)
{
    FbDataPrivate *priv;
    FbId *dtid;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    dtid = g_memdup(&tid, sizeof tid);
    g_queue_push_head(priv->tids, dtid);
}

void
fb_data_add_thread_tail(FbData *fata, FbId tid)
{
    FbDataPrivate *priv;
    FbId *dtid;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    dtid = g_memdup(&tid, sizeof tid);
    g_queue_push_tail(priv->tids, dtid);
}

void
fb_data_clear_threads(FbData *fata)
{
    FbDataPrivate *priv;
    FbId *tid;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    while (!g_queue_is_empty(priv->tids)) {
        tid = g_queue_pop_head(priv->tids);
        g_free(tid);
    }
}

FbId
fb_data_get_thread(FbData *fata, guint n)
{
    FbDataPrivate *priv;
    FbId *tid;

    g_return_val_if_fail(FB_IS_DATA(fata), 0);
    priv = fata->priv;

    tid = g_queue_peek_nth(priv->tids, n);

    if (tid == NULL) {
        return 0;
    }

    return *tid;
}

void
fb_data_add_timeout(FbData *fata, const gchar *name, guint interval,
                    b_event_handler func, gpointer data)
{
    FbDataPrivate *priv;
    gchar *key;
    guint id;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    fb_data_clear_timeout(fata, name, TRUE);

    key = g_strdup(name);
    id = b_timeout_add(interval, func, data);
    g_hash_table_replace(priv->evs, key, GUINT_TO_POINTER(id));
}

void
fb_data_clear_timeout(FbData *fata, const gchar *name, gboolean remove)
{
    FbDataPrivate *priv;
    gpointer ptr;
    guint id;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    ptr = g_hash_table_lookup(priv->evs, name);
    id = GPOINTER_TO_UINT(ptr);

    if ((id > 0) && remove) {
        b_event_remove(id);
    }

    g_hash_table_remove(priv->evs, name);
}

FbApi *
fb_data_get_api(FbData *fata)
{
    FbDataPrivate *priv;

    g_return_val_if_fail(FB_IS_DATA(fata), NULL);
    priv = fata->priv;

    return priv->api;
}

struct im_connection *
fb_data_get_connection(FbData *fata)
{
    FbDataPrivate *priv;

    g_return_val_if_fail(FB_IS_DATA(fata), NULL);
    priv = fata->priv;

    return priv->ic;
}

void
fb_data_add_message(FbData *fata, FbApiMessage *msg)
{
    FbDataPrivate *priv;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    g_queue_push_tail(priv->msgs, msg);
}

void
fb_data_remove_message(FbData *fata, FbApiMessage *msg)
{
    FbDataPrivate *priv;

    g_return_if_fail(FB_IS_DATA(fata));
    priv = fata->priv;

    g_queue_remove(priv->msgs, msg);
}

GSList *
fb_data_take_messages(FbData *fata, FbId uid)
{
    FbApiMessage *msg;
    FbDataPrivate *priv;
    GList *l;
    GList *prev;
    GSList *msgs = NULL;

    g_return_val_if_fail(FB_IS_DATA(fata), NULL);
    priv = fata->priv;
    l = priv->msgs->tail;

    while (l != NULL) {
        msg = l->data;
        prev = l->prev;

        if (msg->uid == uid) {
            msgs = g_slist_prepend(msgs, msg);
            g_queue_delete_link(priv->msgs, l);
        }

        l = prev;
    }

    return msgs;
}

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

#include "facebook-api.h"
#include "facebook-data.h"
#include "facebook-mqtt.h"
#include "facebook-util.h"

#ifndef OPT_SELFMESSAGE
#define OPT_SELFMESSAGE 0
#endif

static void
fb_cb_api_messages(FbApi *api, GSList *msgs, gpointer data);

static gboolean
fb_channel_join(struct im_connection *ic, FbId tid, const gchar **channel)
{
    const gchar *room;
    const gchar *tag;
    FbId rid;
    GSList *l;
    irc_t *irc = ic->acc->bee->ui_data;
    irc_channel_t *ich;

    for (l = irc->channels; l != NULL; l = l->next) {
        ich = l->data;
        tag = set_getstr(&ich->set, "account");

        if (g_strcmp0(tag, ic->acc->tag) != 0) {
            continue;
        }

        room = set_getstr(&ich->set, "room");

        if (room == NULL) {
            continue;
        }

        rid = FB_ID_FROM_STR(room);

        if (rid != tid) {
            continue;
        }

        if (!(ich->flags & IRC_CHANNEL_JOINED) && (ich->f != NULL)) {
            ich->f->join(ich);
        }

        if (channel != NULL) {
            *channel = ich->name;
        }

        return TRUE;
    }

    return FALSE;
}

static void
fb_cb_api_auth(FbApi *api, gpointer data)
{
    FbData *fata = data;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);

    imcb_log(ic, "Fetching contacts");
    fb_data_save(fata);
    fb_api_contacts(api);
}

static void
fb_cb_api_connect(FbApi *api, gpointer data)
{
    account_t *acct;
    FbData *fata = data;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    acct = ic->acc;

    fb_data_save(fata);
    imcb_connected(ic);

    if (set_getbool(&acct->set, "show_unread")) {
        fb_api_unread(api);
    }
}

static void
fb_cb_api_contact(FbApi *api, FbApiUser *user, gpointer data)
{
    FbData *fata = data;
    gchar uid[FB_ID_STRMAX];
    GSList *msgs;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    FB_ID_TO_STR(user->uid, uid);

    if (bee_user_by_handle(ic->bee, ic, uid) == NULL) {
        bee_user_new(ic->bee, ic, uid, BEE_USER_LOCAL);
        imcb_buddy_nick_hint(ic, uid, user->name);
        imcb_rename_buddy(ic, uid, user->name);
    }

    msgs = fb_data_take_messages(fata, user->uid);

    if (msgs != NULL) {
        fb_cb_api_messages(api, msgs, fata);
        g_slist_free_full(msgs, (GDestroyNotify) fb_api_message_free);
    }
}

static gboolean
fb_cb_sync_contacts(gpointer data, gint fd, b_input_condition cond)
{
    FbApi *api;
    FbData *fata = data;

    api = fb_data_get_api(fata);
    fb_data_clear_timeout(fata, "sync-contacts", FALSE);
    fb_api_contacts(api);
    return FALSE;
}

static void
fb_cb_api_contacts(FbApi *api, GSList *users, gboolean complete, gpointer data)
{
    account_t *acct;
    bee_user_t *bu;
    FbApiUser *user;
    FbData *fata = data;
    FbId muid;
    gchar uid[FB_ID_STRMAX];
    gint sync;
    GSList *l;
    GValue val = G_VALUE_INIT;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);

    g_value_init(&val, FB_TYPE_ID);
    g_object_get_property(G_OBJECT(api), "uid", &val);
    muid = g_value_get_int64(&val);
    g_value_unset(&val);

    for (l = users; l != NULL; l = l->next) {
        user = l->data;
        FB_ID_TO_STR(user->uid, uid);

        if (G_UNLIKELY(user->uid == muid)) {
            continue;
        }

        imcb_add_buddy(ic, uid, NULL);
        imcb_buddy_nick_hint(ic, uid, user->name);
        imcb_rename_buddy(ic, uid, user->name);

        bu = imcb_buddy_by_handle(ic, uid);
        bu->data = GINT_TO_POINTER(TRUE);
    }

    if (!complete) {
        return;
    }

    l = ic->bee->users;

    while (l != NULL) {
        bu = l->data;
        l = l->next;

        if (bu->ic != ic) {
            continue;
        }

        if (GPOINTER_TO_INT(bu->data)) {
            bu->data = NULL;
        } else {
            imcb_remove_buddy(ic, bu->handle, NULL);
        }
    }

    if (!(ic->flags & OPT_LOGGED_IN)) {
        imcb_log(ic, "Connecting");
        fb_api_connect(api, FALSE);
    }

    acct = ic->acc;
    sync = set_getint(&acct->set, "sync_interval");

    if (sync < 5) {
        set_setint(&acct->set, "sync_interval", 5);
        sync = 5;
    }

    sync *= 60 * 1000;
    fb_data_add_timeout(fata, "sync-contacts", sync, fb_cb_sync_contacts,
                        fata);
}

static void
fb_cb_api_error(FbApi *api, GError *error, gpointer data)
{
    FbData *fata = data;
    gboolean recon;
    struct im_connection *ic;

    if (g_error_matches(error, FB_API_ERROR, FB_API_ERROR_QUEUE)) {
        /* Save the reset data */
        fb_data_save(fata);
    }

    recon = ((error->domain != FB_HTTP_ERROR) ||
                (error->code < 400) ||
                (error->code > 500)) &&
            !g_error_matches(error, FB_API_ERROR, FB_API_ERROR_AUTH);

    ic = fb_data_get_connection(fata);
    fb_util_debug_error("%s", error->message);
    imcb_error(ic, "%s", error->message);
    imc_logout(ic, recon);
}

static void
fb_cb_api_events(FbApi *api, GSList *events, gpointer data)
{
    FbApiEvent *event;
    FbData *fata = data;
    gchar tid[FB_ID_STRMAX];
    gchar uid[FB_ID_STRMAX];
    GHashTable *fetch;
    GHashTableIter iter;
    GSList *l;
    struct groupchat *gc;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    fetch = g_hash_table_new(fb_id_hash, fb_id_equal);

    for (l = events; l != NULL; l = l->next) {
        event = l->data;

        FB_ID_TO_STR(event->tid, tid);
        gc = bee_chat_by_title(ic->bee, ic, tid);

        if (gc == NULL) {
            continue;
        }

        FB_ID_TO_STR(event->uid, uid);

        switch (event->type) {
        case FB_API_EVENT_TYPE_THREAD_TOPIC:
            imcb_chat_topic(gc, uid, (gchar *) event->text, 0);
            break;

        case FB_API_EVENT_TYPE_THREAD_USER_ADDED:
            if (bee_user_by_handle(ic->bee, ic, uid) == NULL) {
                g_hash_table_insert(fetch, &event->tid, event);
                break;
            }

            imcb_chat_add_buddy(gc, uid);
            break;

        case FB_API_EVENT_TYPE_THREAD_USER_REMOVED:
            imcb_chat_remove_buddy(gc, uid, NULL);
            break;
        }
    }

    g_hash_table_iter_init(&iter, fetch);

    while (g_hash_table_iter_next(&iter, NULL, (gpointer) &event)) {
        fb_api_thread(api, event->tid);
    }

    g_hash_table_destroy(fetch);
}

static void
fb_cb_api_messages(FbApi *api, GSList *msgs, gpointer data)
{
    account_t *acct;
    FbApiMessage *msg;
    FbData *fata = data;
    gboolean mark;
    gboolean open;
    gboolean selfmess;
    gchar tid[FB_ID_STRMAX];
    gchar uid[FB_ID_STRMAX];
    GSList *l;
    guint32 flags;
    struct groupchat *gc;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    acct = ic->acc;
    mark = set_getbool(&acct->set, "mark_read");
    open = set_getbool(&acct->set, "group_chat_open");
    selfmess = (set_find(&ic->bee->set, "self_messages") != NULL);

    for (l = msgs; l != NULL; l = l->next) {
        msg = l->data;
        FB_ID_TO_STR(msg->uid, uid);

        flags = 0;

        if (msg->flags & FB_API_MESSAGE_FLAG_SELF) {
            if (!selfmess) {
                continue;
            }

            flags = OPT_SELFMESSAGE;
        }

        if (bee_user_by_handle(ic->bee, ic, uid) == NULL) {
            msg = fb_api_message_dup(msg, TRUE);
            fb_data_add_message(fata, msg);
            fb_api_contact(api, msg->uid);
            continue;
        }

        if (msg->tid == 0) {
            if (mark) {
                fb_api_read(api, msg->uid, FALSE);
            }

            imcb_buddy_msg(ic, uid, (gchar*) msg->text, flags, 0);
            continue;
        }

        FB_ID_TO_STR(msg->tid, tid);
        gc = bee_chat_by_title(ic->bee, ic, tid);

        if ((gc == NULL) && open) {
            fb_channel_join(ic, msg->tid, NULL);
            gc = bee_chat_by_title(ic->bee, ic, tid);
        }

        if (gc != NULL) {
            if (mark) {
                fb_api_read(api, msg->tid, TRUE);
            }

            imcb_chat_msg(gc, uid, (gchar*) msg->text, flags, 0);
        }
    }
}

static void
fb_cb_api_presences(FbApi *api, GSList *press, gpointer data)
{
    FbApiPresence *pres;
    FbData *fata = data;
    gchar uid[FB_ID_STRMAX];
    GSList *l;
    guint flags;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);

    for (l = press; l != NULL; l = l->next) {
        pres = l->data;
        FB_ID_TO_STR(pres->uid, uid);

        if (bee_user_by_handle(ic->bee, ic, uid) == NULL) {
            continue;
        }

        if (pres->active) {
            flags = BEE_USER_ONLINE;
        } else {
            flags = 0;
        }

        FB_ID_TO_STR(pres->uid, uid);
        imcb_buddy_status(ic, uid, flags, NULL, NULL);
    }
}

static void
fb_cb_api_thread(FbApi *api, FbApiThread *thrd, gpointer data)
{
    bee_user_t *bu;
    FbApiUser *user;
    FbData *fata = data;
    gchar id[FB_ID_STRMAX];
    GList *h;
    GSList *l;
    GString *gstr;
    struct groupchat *gc;
    struct im_connection *ic;

    FB_ID_TO_STR(thrd->tid, id);
    ic = fb_data_get_connection(fata);
    gc = bee_chat_by_title(ic->bee, ic, id);

    if (G_UNLIKELY(gc == NULL)) {
        return;
    }

    if (thrd->topic == NULL) {
        gstr = g_string_new(NULL);

        for (l = thrd->users; l != NULL; l = l->next) {
            user = l->data;

            if (gstr->len > 0) {
                g_string_append(gstr, ", ");
            }

            g_string_append(gstr, user->name);
        }

        imcb_chat_topic(gc, NULL, gstr->str, 0);
        g_string_free(gstr, TRUE);
    } else {
        imcb_chat_topic(gc, NULL, (gchar *) thrd->topic, 0);
    }

    for (l = thrd->users; l != NULL; l = l->next) {
        user = l->data;
        FB_ID_TO_STR(user->uid, id);
        h = g_list_find_custom(gc->in_room, id, (GCompareFunc) g_strcmp0);

        if (h != NULL) {
            continue;
        }

        bu = bee_user_by_handle(ic->bee, ic, id);

        if (bu == NULL) {
            bee_user_new(ic->bee, ic, id, BEE_USER_LOCAL);
            imcb_buddy_nick_hint(ic, id, user->name);
            imcb_rename_buddy(ic, id, user->name);
        }

        imcb_chat_add_buddy(gc, id);
    }
}

static void
fb_cb_api_thread_create(FbApi *api, FbId tid, gpointer data)
{
    account_t *acct;
    FbData *fata = data;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    acct = ic->acc;

    fb_data_add_thread_head(fata, tid);
    imcb_log(ic, "Created chat thread %" FB_ID_FORMAT, tid);
    imcb_log(ic, "Join: fbjoin %s %d <channel-name>", acct->tag, 1);
}

static void
fb_cb_api_threads(FbApi *api, GSList *thrds, gpointer data)
{
    FbApiThread *thrd;
    FbApiUser *user;
    FbData *fata = data;
    GSList *phrds = NULL;
    GSList *l;
    GSList *m;
    GString *lines;
    guint i;
    guint j;
    struct im_connection *ic;

    ic = fb_data_get_connection(fata);
    fb_data_clear_threads(fata);

    for (l = thrds, i = 0; (l != NULL) && (i < 25); l = l->next, i++) {
        thrd = l->data;

        if (g_slist_length(thrd->users) >= 2) {
            phrds = g_slist_prepend(phrds, thrd);
        }
    }

    if (phrds == NULL) {
        imcb_log(ic, "No chats to display.");
        return;
    }

    lines = g_string_new(NULL);
    imcb_log(ic, "%2s  %-20s  %s", "ID", "Topic", "Participants");
    phrds = g_slist_reverse(phrds);

    for (l = phrds, i = 1; l != NULL; l = l->next, i++) {
        thrd = l->data;
        fb_data_add_thread_tail(fata, thrd->tid);
        g_string_printf(lines, "%2d", i);

        if (thrd->topic != NULL) {
            if (strlen(thrd->topic) > 20) {
                for (j = 16; g_ascii_isspace(thrd->topic[j]) && (j > 0); j--);
                g_string_append_printf(lines, "  %-.*s...", ++j, thrd->topic);
                g_string_append_printf(lines, "%*s", 17 - j, "");
            } else {
                g_string_append_printf(lines, "  %-20s", thrd->topic);
            }
        } else {
            g_string_append_printf(lines, "  %20s", "");
        }

        for (m = thrd->users, j = 0; (m != NULL) && (j < 3); m = m->next, j++) {
            user = m->data;
            g_string_append(lines, (j != 0) ? ", " : "  ");
            g_string_append(lines, user->name);
        }

        if (m != NULL) {
            g_string_append(lines, "...");
        }

        imcb_log(ic, "%s", lines->str);
    }

    g_string_free(lines, TRUE);
    g_slist_free(phrds);
}

static void
fb_cb_api_typing(FbApi *api, FbApiTyping *typg, gpointer data)
{
    FbData *fata = data;
    gchar uid[FB_ID_STRMAX];
    guint32 flags;
    struct im_connection *ic;

    FB_ID_TO_STR(typg->uid, uid);
    ic = fb_data_get_connection(fata);
    flags = typg->state ? OPT_TYPING : 0;
    imcb_buddy_typing(ic, uid, flags);
}

static struct groupchat *
fb_groupchat_new(struct im_connection *ic, FbId tid, const gchar *name)
{
    FbApi *api;
    FbData *fata = ic->proto_data;
    gchar stid[FB_ID_STRMAX];
    irc_channel_t *ch;
    struct groupchat *gc;

    FB_ID_TO_STR(tid, stid);

    if (bee_chat_by_title(ic->bee, ic, stid) != NULL) {
        imcb_error(ic, "Failed to create chat: %" FB_ID_FORMAT, tid);
        return NULL;
    }

    if (name != NULL) {
        if (strchr(CTYPES, name[0]) != NULL) {
            name++;
        }

        /* Let the hackery being... */
        gc = imcb_chat_new(ic, stid);
        imcb_chat_name_hint(gc, name);

        ch = gc->ui_data;
        ch->flags |= IRC_CHANNEL_CHAT_PICKME;

        /* Setup the channel as a room */
        set_setstr(&ch->set, "type",      "chat");
        set_setstr(&ch->set, "chat_type", "room");
        set_setstr(&ch->set, "account",   ic->acc->tag);
        set_setstr(&ch->set, "room",      stid);

        /* Free and recreate with new channel settings */
        imcb_chat_free(gc);
    }

    gc = imcb_chat_new(ic, stid);
    fb_data_add_groupchat(fata, gc);

    ch = gc->ui_data;
    ch->flags &= ~IRC_CHANNEL_CHAT_PICKME;

    api = fb_data_get_api(fata);
    imcb_chat_add_buddy(gc, ic->acc->user);
    fb_api_thread(api, tid);
    return gc;
}

static void
fb_init(account_t *acct)
{
    set_t *s;

    s = set_add(&acct->set, "cid", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acct->set, "did", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acct->set, "mid", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acct->set, "token", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

    s = set_add(&acct->set, "stoken", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acct->set, "uid", NULL, NULL, acct);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    set_add(&acct->set, "group_chat_open", "false", set_eval_bool, acct);
    set_add(&acct->set, "mark_read", "false", set_eval_bool, acct);
    set_add(&acct->set, "show_unread", "false", set_eval_bool, acct);
    set_add(&acct->set, "sync_interval", "30", set_eval_int, acct);
}

static void
fb_login(account_t *acc)
{
    FbApi *api;
    FbData *fata;
    struct im_connection *ic;

    fata = fb_data_new(acc);
    api = fb_data_get_api(fata);
    ic = fb_data_get_connection(fata);
    ic->proto_data = fata;

    g_signal_connect(api,
                     "auth",
                     G_CALLBACK(fb_cb_api_auth),
                     fata);
    g_signal_connect(api,
                     "connect",
                     G_CALLBACK(fb_cb_api_connect),
                     fata);
    g_signal_connect(api,
                     "contact",
                     G_CALLBACK(fb_cb_api_contact),
                     fata);
    g_signal_connect(api,
                     "contacts",
                     G_CALLBACK(fb_cb_api_contacts),
                     fata);
    g_signal_connect(api,
                     "error",
                     G_CALLBACK(fb_cb_api_error),
                     fata);
    g_signal_connect(api,
                     "events",
                     G_CALLBACK(fb_cb_api_events),
                     fata);
    g_signal_connect(api,
                     "messages",
                     G_CALLBACK(fb_cb_api_messages),
                     fata);
    g_signal_connect(api,
                     "presences",
                     G_CALLBACK(fb_cb_api_presences),
                     fata);
    g_signal_connect(api,
                     "thread",
                     G_CALLBACK(fb_cb_api_thread),
                     fata);
    g_signal_connect(api,
                     "thread-create",
                     G_CALLBACK(fb_cb_api_thread_create),
                     fata);
    g_signal_connect(api,
                     "threads",
                     G_CALLBACK(fb_cb_api_threads),
                     fata);
    g_signal_connect(api,
                     "typing",
                     G_CALLBACK(fb_cb_api_typing),
                     fata);

    if (!fb_data_load(fata)) {
        imcb_log(ic, "Authenticating");
        fb_api_auth(api, acc->user, acc->pass);
        return;
    }

    imcb_log(ic, "Fetching contacts");
    fb_api_contacts(api);
}

static void
fb_logout(struct im_connection *ic)
{
    FbApi *api;
    FbData *fata = ic->proto_data;

    api = fb_data_get_api(fata);
    ic->proto_data = NULL;

    fb_data_save(fata);
    fb_api_disconnect(api);
    g_object_unref(fata);
}

static int
fb_buddy_msg(struct im_connection *ic, char *to, char *message, int flags)
{
    FbApi *api;
    FbData *fata = ic->proto_data;
    FbId uid;

    api = fb_data_get_api(fata);
    uid = FB_ID_FROM_STR(to);
    fb_api_message(api, uid, FALSE, message);
    return 0;
}

static void
fb_set_away(struct im_connection *ic, char *state, char *message)
{
    FbApi *api;
    FbData *fata = ic->proto_data;
    gboolean invisible;

    api = fb_data_get_api(fata);
    invisible = ((state != NULL) && (*state != '\0'));

    if (fb_api_is_invisible(api) != invisible) {
        fb_api_connect(api, invisible);
    }
}

static int
fb_send_typing(struct im_connection *ic, char *who, int flags)
{
    FbApi *api;
    FbData *fata = ic->proto_data;
    FbId uid;
    gboolean state;

    api = fb_data_get_api(fata);
    uid = FB_ID_FROM_STR(who);
    state = (flags & OPT_TYPING) != 0;
    fb_api_typing(api, uid, state);
    return 0;
}

static void
fb_add_buddy(struct im_connection *ic, char *name, char *group)
{

}

static void
fb_remove_buddy(struct im_connection *ic, char *name, char *group)
{

}

static void
fb_chat_invite(struct groupchat *gc, char *who, char *message)
{
    FbApi *api;
    FbData *fata = gc->ic->proto_data;
    FbId tid;
    FbId uid;

    api = fb_data_get_api(fata);
    tid = FB_ID_FROM_STR(gc->title);
    uid = FB_ID_FROM_STR(who);

    fb_api_thread_invite(api, tid, uid);
}

static void
fb_chat_kick(struct groupchat *gc, char *who, const char *message)
{
    FbApi *api;
    FbData *fata = gc->ic->proto_data;
    FbId tid;
    FbId uid;

    api = fb_data_get_api(fata);
    tid = FB_ID_FROM_STR(gc->title);
    uid = FB_ID_FROM_STR(who);

    fb_api_thread_remove(api, tid, uid);
}

static void
fb_chat_leave(struct groupchat *gc)
{
    FbData *fata = gc->ic->proto_data;

    fb_data_remove_groupchat(fata, gc);
    imcb_chat_free(gc);
}

static void
fb_chat_msg(struct groupchat *gc, char *message, int flags)
{
    FbApi *api;
    FbData *fata = gc->ic->proto_data;
    FbId tid;

    api = fb_data_get_api(fata);
    tid = FB_ID_FROM_STR(gc->title);
    fb_api_message(api, tid, TRUE, message);
}

static struct groupchat *
fb_chat_join(struct im_connection *ic, const char *room, const char *nick,
             const char *password, set_t **sets)
{
    FbId tid;

    tid = FB_ID_FROM_STR(room);
    return fb_groupchat_new(ic, tid, NULL);
}

static void
fb_chat_topic(struct groupchat *gc, char *topic)
{
    FbApi *api;
    FbData *fata = gc->ic->proto_data;
    FbId tid;

    api = fb_data_get_api(fata);
    tid = FB_ID_FROM_STR(gc->title);
    fb_api_thread_topic(api, tid, topic);
}

static GList *
fb_away_states(struct im_connection *ic)
{
    static GList *m = NULL;

    if (G_UNLIKELY(m == NULL)) {
        m = g_list_append(m, "Away");
    }

    return m;
}

static account_t *
fb_cmd_account(irc_t *irc, char **args, guint required, guint *offset)
{
    account_t *a;
    account_t *acct;
    guint acctc;
    guint size;
    guint oset;

    for (acctc= 0, a = irc->b->accounts; a != NULL; a = a->next) {
        if ((g_ascii_strcasecmp(a->prpl->name, "facebook") == 0) &&
            (a->ic != NULL))
        {
            acct = a;
            acctc++;
        }
    }

    if (acctc == 0) {
        irc_rootmsg(irc, "There are no active Facebook accounts!");
        return NULL;
    }

    /* Calculate the size of args */
    for (size = 1; args[size] != NULL; size++);

    if (acctc > 1) {
        if (args[1] == NULL) {
            irc_rootmsg(irc, "More than one Facebook account, specify one.");
            return NULL;
        }

        /* More than one account, look up by handle */
        acct = account_get(irc->b, args[1]);
        oset = 2;

        if (acct == NULL) {
            irc_rootmsg(irc, "Unknown account: %s", args[1]);
            return NULL;
        }

        if (acct->ic == NULL) {
            irc_rootmsg(irc, "Account not online: %s", acct->tag);
            return NULL;
        }

        if (g_ascii_strcasecmp(acct->prpl->name, "facebook") != 0) {
            irc_rootmsg(irc, "Unknown Facebook account: %s", acct->tag);
            return NULL;
        }
    } else if ((size != (required + 1)) &&
               (args[1] != NULL) &&
               (account_get(irc->b, args[1]) == acct))
    {
        /* One account with an identifier */
        oset = 2;
    } else {
        /* One account without an identifier */
        oset = 1;
    }

    if (size < (oset + required)) {
        irc_rootmsg(irc, "Not enough parameters given (need %u).", required);
        return NULL;
    }

    if (offset != NULL) {
        *offset = oset;
    }

    return acct;
}

static void
fb_cmd_fbchats(irc_t *irc, char **args)
{
    account_t *acct;
    FbApi *api;
    FbData *fata;

    acct = fb_cmd_account(irc, args, 0, NULL);

    if (acct == NULL) {
        return;
    }

    fata = acct->ic->proto_data;
    api = fb_data_get_api(fata);
    fb_api_threads(api);
}

static void
fb_cmd_fbcreate(irc_t *irc, char **args)
{
    account_t *acct;
    FbApi *api;
    FbData *fata;
    FbId *duid;
    FbId uid;
    irc_user_t *iu;
    GSList *uids = NULL;
    guint oset;
    guint i;

    acct = fb_cmd_account(irc, args, 2, &oset);

    if (acct == NULL) {
        return;
    }

    fata = acct->ic->proto_data;

    for (i = oset; args[i] != NULL; i++) {
        iu = irc_user_by_name(irc, args[i]);

        if (iu != NULL) {
            uid = FB_ID_FROM_STR(iu->bu->handle);
            duid = g_memdup(&uid, sizeof uid);
            uids = g_slist_prepend(uids, duid);
        }
    }

    if (uids == NULL) {
        irc_rootmsg(irc, "No valid users specified");
        return;
    }

    api = fb_data_get_api(fata);
    fb_api_thread_create(api, uids);
    g_slist_free_full(uids, g_free);
}

static void
fb_cmd_fbjoin(irc_t *irc, char **args)
{
    const gchar *chan;
    account_t *acct;
    FbData *fata;
    FbId tid;
    gchar *name;
    guint i;
    guint oset;
    irc_channel_t *ich;
    struct groupchat *gc;
    struct im_connection *ic;

    acct = fb_cmd_account(irc, args, 2, &oset);

    if (acct == NULL) {
        return;
    }

    fata = acct->ic->proto_data;
    ic = fb_data_get_connection(fata);

    name = args[oset + 1];
    i = g_ascii_strtoll(args[oset], NULL, 10);
    tid = fb_data_get_thread(fata, i - 1);

    if ((i < 1) || (tid == 0)) {
        irc_rootmsg(irc, "Invalid index: %u", i);
        return;
    }

    if (!fb_channel_join(ic, tid, &chan)) {
        gc = fb_groupchat_new(ic, tid, name);
        ich = gc->ui_data;
        chan = ich->name;
    }

    irc_rootmsg(irc, "Joining channel %s", chan);
}

G_MODULE_EXPORT void
init_plugin(void);

G_MODULE_EXPORT void
init_plugin(void)
{
    struct prpl *dpp;

    static const struct prpl pp = {
        .name = "facebook",
        .init = fb_init,
        .login = fb_login,
        .logout = fb_logout,
        .buddy_msg = fb_buddy_msg,
        .set_away = fb_set_away,
        .send_typing = fb_send_typing,
        .add_buddy = fb_add_buddy,
        .remove_buddy = fb_remove_buddy,
        .chat_invite = fb_chat_invite,
        .chat_kick = fb_chat_kick,
        .chat_leave = fb_chat_leave,
        .chat_msg = fb_chat_msg,
        .chat_join = fb_chat_join,
        .chat_topic = fb_chat_topic,
        .away_states = fb_away_states,
        .handle_cmp = g_strcmp0
    };

#if !GLIB_CHECK_VERSION(2, 36, 0)
    g_type_init();
#endif

    dpp = g_memdup(&pp, sizeof pp);
    register_protocol(dpp);

    root_command_add("fbchats", 0, fb_cmd_fbchats, 0);
    root_command_add("fbcreate", 0, fb_cmd_fbcreate, 0);
    root_command_add("fbjoin", 0, fb_cmd_fbjoin, 0);
}

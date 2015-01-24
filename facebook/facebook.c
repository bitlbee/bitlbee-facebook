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

#include "facebook.h"
#include "facebook-util.h"

/**
 * Implemented #fb_api_funcs->error().
 *
 * @param api  The #fb_api.
 * @param err  The #GError.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_error(fb_api_t *api, GError *err, gpointer data)
{
    fb_data_t *fata = data;

    FB_UTIL_DEBUGLN("Error: %s", err->message);
    imcb_error(fata->ic, "%s", err->message);
    imc_logout(fata->ic, TRUE);
}

/**
 * Implemented #fb_api_funcs->auth().
 *
 * @param api  The #fb_api.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_auth(fb_api_t *api, gpointer data)
{
    fb_data_t *fata = data;
    account_t *acc  = fata->ic->acc;
    gchar      uid[FB_ID_STRMAX];

    FB_ID_TO_STR(api->uid, uid);
    set_setstr(&acc->set, "uid",   uid);
    set_setstr(&acc->set, "token", api->token);
    imcb_log(fata->ic, "Authentication finished");

    account_off(acc->bee, acc);
    account_on(acc->bee, acc);
}

/**
 * Implemented #fb_api_funcs->connect().
 *
 * @param api  The #fb_api.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_connect(fb_api_t *api, gpointer data)
{
    fb_data_t *fata = data;
    account_t *acc  = fata->ic->acc;

    imcb_connected(fata->ic);
    set_setstr(&acc->set, "stoken", api->stoken);
}

/**
 * Implemented #fb_api_funcs->contacts().
 *
 * @param api   The #fb_api.
 * @param users The #GSList of #fb_api_user.
 * @param data  The user defined data, which is #fb_data.
 **/
static void fb_cb_api_contacts(fb_api_t *api, GSList *users, gpointer data)
{
    fb_data_t     *fata = data;
    fb_api_user_t *user;
    GSList        *l;
    gchar          uid[FB_ID_STRMAX];

    for (l = users; l != NULL; l = l->next) {
        user = l->data;
        FB_ID_TO_STR(user->uid, uid);
        imcb_add_buddy(fata->ic, uid, NULL);
        imcb_buddy_nick_hint(fata->ic, uid, user->name);
        imcb_rename_buddy(fata->ic, uid, user->name);
    }

    imcb_log(fata->ic, "Establishing connection");
    fb_api_connect(fata->api);
}

/**
 * Implemented #fb_api_funcs->message().
 *
 * @param api  The #fb_api.
 * @param msgs The #GSList of #fb_api_msg.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_message(fb_api_t *api, GSList *msgs, gpointer data)
{
    fb_data_t        *fata = data;
    fb_api_msg_t     *msg;
    struct groupchat *gc;
    GSList           *l;
    gchar             uid[FB_ID_STRMAX];
    gchar             tid[FB_ID_STRMAX];

    for (l = msgs; l != NULL; l = l->next) {
        msg = l->data;
        FB_ID_TO_STR(msg->uid, uid);

        if (msg->tid == 0) {
            imcb_buddy_msg(fata->ic, uid, (gchar*) msg->text, 0, 0);
            continue;
        }

        FB_ID_TO_STR(msg->tid, tid);
        gc = bee_chat_by_title(fata->ic->bee, fata->ic, tid);

        if (gc != NULL)
            imcb_chat_msg(gc, uid, (gchar*) msg->text, 0, 0);
    }
}

/**
 * Implemented #fb_api_funcs->presence().
 *
 * @param api   The #fb_api.
 * @param press The #GSList of #fb_api_msg.
 * @param data  The user defined data, which is #fb_data.
 **/
static void fb_cb_api_presence(fb_api_t *api, GSList *press, gpointer data)
{
    fb_data_t     *fata = data;
    fb_api_pres_t *pres;
    GSList        *l;
    guint          flags;
    gchar          uid[FB_ID_STRMAX];

    for (l = press; l != NULL; l = l->next) {
        pres  = l->data;
        flags = 0;

        if (pres->active)
            flags |= OPT_LOGGED_IN;

        FB_ID_TO_STR(pres->uid, uid);
        imcb_buddy_status(fata->ic, uid, flags, NULL, NULL);
    }
}

/**
 * Implemented #fb_api_funcs->thread_create().
 *
 * @param api  The #fb_api.
 * @param tid  The thread #fb_id.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_thread_create(fb_api_t *api, fb_id_t tid, gpointer data)
{
    fb_data_t *fata = data;
    account_t *acc  = fata->ic->acc;

    fata->tids = g_slist_prepend(fata->tids, g_memdup(&tid, sizeof tid));
    imcb_log(fata->ic, "Created chat thread %" FB_ID_FORMAT, tid);
    imcb_log(fata->ic, "Join: fbjoin %s %d <channel-name>", acc->tag, 1);
}

/**
 * Implemented #fb_api_funcs->thread_info().
 *
 * @param api  The #fb_api.
 * @param thrd The #fb_api_thread.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_thread_info(fb_api_t *api, fb_api_thread_t *thrd,
                                  gpointer data)
{
    fb_data_t        *fata = data;
    fb_api_user_t    *user;
    bee_user_t       *bu;
    struct groupchat *gc;
    GSList           *l;
    GString          *gstr;
    gchar             id[FB_ID_STRMAX];

    FB_ID_TO_STR(thrd->tid, id);
    gc = bee_chat_by_title(fata->ic->bee, fata->ic, id);

    if (G_UNLIKELY(gc == NULL))
        return;

    if (thrd->topic == NULL) {
        gstr = g_string_new(NULL);

        for (l = thrd->users; l != NULL; l = l->next) {
            user = l->data;

            if (gstr->len > 0)
                g_string_append(gstr, ", ");

            g_string_append(gstr, user->name);
        }

        imcb_chat_topic(gc, NULL, gstr->str, 0);
        g_string_free(gstr, TRUE);
    } else {
        imcb_chat_topic(gc, NULL, (gchar*) thrd->topic, 0);
    }

    for (l = thrd->users; l != NULL; l = l->next) {
        user = l->data;
        FB_ID_TO_STR(user->uid, id);
        bu = bee_user_by_handle(fata->ic->bee, fata->ic, id);

        imcb_chat_add_buddy(gc, id);

        if (bu == NULL) {
            imcb_buddy_nick_hint(fata->ic, id, user->name);
            imcb_rename_buddy(fata->ic, id, user->name);
        }
    }
}

/**
 * Implemented #fb_api_funcs->thread_list().
 *
 * @param api   The #fb_api.
 * @param thrds The #GSList of #fb_api_thread.
 * @param data  The user defined data, which is #fb_data.
 **/
static void fb_cb_api_thread_list(fb_api_t *api, GSList *thrds, gpointer data)
{
    fb_data_t       *fata = data;
    fb_api_thread_t *thrd;
    fb_api_user_t   *user;
    GSList          *phrds;
    GSList          *l;
    GSList          *m;
    GString         *ln;
    gpointer         mptr;
    guint            i;
    guint            j;

    g_slist_free_full(fata->tids, g_free);
    fata->tids = NULL;
    phrds = NULL;

    for (l = thrds, i = 0; (l != NULL) && (i < 25); l = l->next, i++) {
        thrd = l->data;

        if (g_slist_length(thrd->users) >= 2)
            phrds = g_slist_prepend(phrds, thrd);
    }

    if (phrds == NULL) {
        imcb_log(fata->ic, "No chats to display.");
        return;
    }

    ln = g_string_new(NULL);
    imcb_log(fata->ic, "%2s  %-20s  %s", "ID", "Topic", "Participants");
    phrds = g_slist_reverse(phrds);

    for (l = phrds, i = 1; l != NULL; l = l->next, i++) {
        thrd = l->data;

        if (g_slist_length(thrd->users) < 2)
            continue;

        mptr = g_memdup(&thrd->tid, sizeof thrd->tid);
        fata->tids = g_slist_prepend(fata->tids, mptr);

        g_string_printf(ln, "%2d", i);

        if (thrd->topic != NULL) {
            if (strlen(thrd->topic) > 20) {
                for (j = 16; g_ascii_isspace(thrd->topic[j]) && (j > 0); j--);
                g_string_append_printf(ln, "  %-.*s...", ++j, thrd->topic);
                g_string_append_printf(ln, "%*s", 17 - j, "");
            } else {
                g_string_append_printf(ln, "  %-20s", thrd->topic);
            }
        } else {
            g_string_append_printf(ln, "  %20s", "");
        }

        for (m = thrd->users, j = 0; (m != NULL) && (j < 3); m = m->next, j++) {
            user = m->data;
            g_string_append(ln, (j != 0) ? ", " : "  ");
            g_string_append(ln, user->name);
        }

        if (m != NULL)
            g_string_append(ln, "...");

        imcb_log(fata->ic, "%s", ln->str);
    }

    fata->tids = g_slist_reverse(fata->tids);
    g_string_free(ln, TRUE);
    g_slist_free(phrds);
}

/**
 * Implemented #fb_api_funcs->typing().
 *
 * @param api  The #fb_api.
 * @param typg The #fb_api_typing.
 * @param data The user defined data, which is #fb_data.
 **/
static void fb_cb_api_typing(fb_api_t *api, fb_api_typing_t *typg,
                             gpointer data)
{
    fb_data_t *fata = data;
    guint32    flags;
    gchar      uid[FB_ID_STRMAX];

    FB_ID_TO_STR(typg->uid, uid);
    flags = typg->state ? OPT_TYPING : 0;
    imcb_buddy_typing(fata->ic, uid, flags);
}

/**
 * Creates a new #fb_data with an #account. The returned #fb_data
 * should be freed with #fb_data_free() when no longer needed.
 *
 * @param acc The #account.
 *
 * @return The #fb_data or NULL on error.
 **/
fb_data_t *fb_data_new(account_t *acc)
{
    fb_data_t *fata;
    gchar     *uid;

    static const fb_api_funcs_t funcs = {
        .error         = fb_cb_api_error,
        .auth          = fb_cb_api_auth,
        .connect       = fb_cb_api_connect,
        .contacts      = fb_cb_api_contacts,
        .message       = fb_cb_api_message,
        .presence      = fb_cb_api_presence,
        .thread_create = fb_cb_api_thread_create,
        .thread_info   = fb_cb_api_thread_info,
        .thread_list   = fb_cb_api_thread_list,
        .typing        = fb_cb_api_typing
    };

    g_return_val_if_fail(acc != NULL, NULL);

    fata = g_new0(fb_data_t, 1);
    fata->api = fb_api_new(&funcs, fata);

    fata->ic = imcb_new(acc);
    fata->ic->proto_data = fata;

    uid = set_getstr(&acc->set, "uid");

    if (uid != NULL)
        fata->api->uid = FB_ID_FROM_STR(uid);

    fata->api->token  = g_strdup(set_getstr(&acc->set, "token"));
    fata->api->stoken = g_strdup(set_getstr(&acc->set, "stoken"));
    fata->api->cid    = g_strdup(set_getstr(&acc->set, "cid"));
    fata->api->mid    = g_strdup(set_getstr(&acc->set, "mid"));
    fata->api->cuid   = g_strdup(set_getstr(&acc->set, "cuid"));

    fb_api_rehash(fata->api);

    set_setstr(&acc->set, "cid",  fata->api->cid);
    set_setstr(&acc->set, "mid",  fata->api->mid);
    set_setstr(&acc->set, "cuid", fata->api->cuid);

    return fata;
}

/**
 * Frees all memory used by a #fb_data.
 *
 * @param sata The #fb_data.
 **/
void fb_data_free(fb_data_t *fata)
{
    if (G_UNLIKELY(fata == NULL))
        return;

    fb_api_free(fata->api);
    g_slist_free_full(fata->tids, g_free);
    g_slist_free_full(fata->gcs,  (GDestroyNotify) imcb_chat_free);
    g_free(fata);
}

/**
 * Creates a new #groupchat and adds it to the #fb_data. The returned
 * #groupchat should be freed with #fb_data_groupchat_free() when no
 * longer needed.
 *
 * @param ic   The #im_connection.
 * @param tid  The thread #fb_id.
 * @param name The name of the channel.
 *
 * @return The #groupchat or NULL on error.
 **/
struct groupchat *fb_data_groupchat_new(struct im_connection *ic,
                                        fb_id_t tid,
                                        const gchar *name)
{
    fb_data_t        *fata = ic->proto_data;
    struct groupchat *gc;
    gchar             stid[FB_ID_STRMAX];

    FB_ID_TO_STR(tid, stid);

    if (bee_chat_by_title(ic->bee, ic, stid) != NULL)
        return NULL;

    gc = imcb_chat_new(ic, stid);
    fata->gcs = g_slist_prepend(fata->gcs, gc);

    if (name != NULL)
        imcb_chat_name_hint(gc, name);

    imcb_chat_add_buddy(gc, ic->acc->user);
    fb_api_thread_info(fata->api, tid);

    return gc;
}

/**
 * Frees all memory used by a #groupchat and removes it from the
 * #fb_data.
 *
 * @param gc The #groupchat.
 **/
void fb_data_groupchat_free(struct groupchat *gc)
{
    fb_data_t *fata;

    if (G_UNLIKELY(gc == NULL))
        return;

    if (G_LIKELY(gc->ic != NULL)) {
        fata = gc->ic->proto_data;
        fata->gcs = g_slist_remove(fata->gcs, gc);
    }

    imcb_chat_free(gc);
}

/**
 * Implements #prpl->init(). This initializes an account.
 *
 * @param acc The #account.
 **/
static void fb_init(account_t *acc)
{
    set_t *s;

    s = set_add(&acc->set, "cid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "cuid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "mid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "token", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN | SET_PASSWORD;

    s = set_add(&acc->set, "stoken", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;

    s = set_add(&acc->set, "uid", NULL, NULL, acc);
    s->flags = SET_NULL_OK | SET_HIDDEN;
}

/**
 * Implements #prpl->login(). This logins an account in.
 *
 * @param acc The #account.
 **/
static void fb_login(account_t *acc)
{
    fb_data_t *fata;

    fata = fb_data_new(acc);
    imcb_log(fata->ic, "Connecting");

    if (fata->api->token == NULL) {
        imcb_log(fata->ic, "Requesting authentication token");
        fb_api_auth(fata->api, acc->user, acc->pass);
        return;
    }

    imcb_log(fata->ic, "Fetching contacts");
    fb_api_contacts(fata->api);
}

/**
 * Implements #prpl->logout(). This logs an account out.
 *
 * @param ic The #im_connection.
 **/
static void fb_logout(struct im_connection *ic)
{
    fb_data_t *fata = ic->proto_data;

    fb_api_disconnect(fata->api);
    fb_data_free(fata);
}

/**
 * Implements #prpl->buddy_msg(). This sends a message to a buddy.
 *
 * @param ic      The #im_connection.
 * @param to      The handle of the buddy.
 * @param message The message to send.
 * @param flags   The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbee does nothing with this)
 **/
static int fb_buddy_msg(struct im_connection *ic, char *to, char *message,
                        int flags)
{
    fb_data_t *fata = ic->proto_data;
    fb_id_t    uid;

    uid = FB_ID_FROM_STR(to);
    fb_api_message(fata->api, uid, FALSE, message);
    return 0;
}

/**
 * Implements #prpl->send_typing(). This sends the typing state message.
 *
 * @param ic    The #im_connection.
 * @param who   The handle of the buddy.
 * @param flags The message flags. (Irrelevant to this plugin)
 *
 * @return 0. (Upstream bitlbe does nothing with this)
 **/
static int fb_send_typing(struct im_connection *ic, char *who, int flags)
{
    fb_data_t *fata = ic->proto_data;
    fb_id_t    uid;
    gboolean   state;

    uid   = FB_ID_FROM_STR(who);
    state = (flags & OPT_TYPING) != 0;
    fb_api_typing(fata->api, uid, state);
    return 0;
}

/**
 * Implements #prpl->add_buddy(). This adds a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void fb_add_buddy(struct im_connection *ic, char *name, char *group)
{

}

/**
 * Implements #prpl->remove_buddy(). This removes a buddy.
 *
 * @param ic    The #im_connection.
 * @param name  The name of the buddy to add.
 * @param group The group of the buddy. (Irrelevant to this plugin)
 **/
static void fb_remove_buddy(struct im_connection *ic, char *name, char *group)
{

}

/**
 * Implements #prpl->add_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_add_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->add_deny(). This blocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_add_deny(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->rem_permit(). This is not used by the plugin.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_rem_permit(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->rem_deny(). This unblocks a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_rem_deny(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->get_info(). This retrieves the info of a buddy.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_get_info(struct im_connection *ic, char *who)
{

}

/**
 * Implements #prpl->chat_invite(). This invites a user to a #groupchat.
 *
 * @param gc      The #groupchat.
 * @param who     Ignored.
 * @param message The handle to invite.
 **/
void fb_chat_invite(struct groupchat *gc, char *who, char *message)
{
    fb_data_t *fata = gc->ic->proto_data;
    fb_id_t    tid;
    fb_id_t    uid;

    tid = FB_ID_FROM_STR(gc->title);
    uid = FB_ID_FROM_STR(who);
    fb_api_thread_invite(fata->api, tid, uid);
    imcb_chat_add_buddy(gc, who);
}

/**
 * Implements #prpl->chat_leave(). This leaves a #groupchat.
 *
 * @param gc The #groupchat.
 **/
void fb_chat_leave(struct groupchat *gc)
{
    fb_data_groupchat_free(gc);
}

/**
 * Implements #prpl->chat_msg(). This sends a message to a #groupchat.
 *
 * @param gc      The #groupchat.
 * @param message The message to send.
 * @param flags   Ignored.
 **/
void fb_chat_msg(struct groupchat *gc, char *message, int flags)
{
    fb_data_t *fata = gc->ic->proto_data;
    fb_id_t    tid;

    tid = FB_ID_FROM_STR(gc->title);
    fb_api_message(fata->api, tid, TRUE, message);
}

/**
 * Implements #prpl->chat_join(). This joins a #groupchat.
 *
 * @param ic       The #im_connection.
 * @param room     The room name.
 * @param nick     The nick name.
 * @param password The password.
 * @param sets     The #set array.
 **/
struct groupchat *fb_chat_join(struct im_connection *ic, const char *room,
                               const char *nick, const char *password,
                               set_t **sets)
{
    fb_data_t        *fata = ic->proto_data;
    fb_id_t           tid;
    struct groupchat *gc;

    tid = FB_ID_FROM_STR(room);
    gc  = fb_data_groupchat_new(ic, tid, NULL);

    if (gc == NULL) {
        imcb_error(fata->ic, "Failed to join chat: %" FB_ID_FORMAT, tid);
        return NULL;
    }

    fb_api_thread_info(fata->api, tid);
    return gc;
}

/**
 * Implements #prpl->chat_topic(). This sets a #groupchat topic.
 *
 * @param gc    The #groupchat.
 * @param topic The topic
 **/
void fb_chat_topic(struct groupchat *gc, char *topic)
{
    fb_data_t *fata = gc->ic->proto_data;
    fb_id_t    tid;

    tid = FB_ID_FROM_STR(gc->title);
    fb_api_thread_topic(fata->api, tid, topic);
    imcb_chat_topic(gc, NULL, topic, 0);
}

/**
 * Implements #prpl->auth_allow(). This accepts buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_auth_allow(struct im_connection *ic, const char *who)
{

}

/**
 * Implements #prpl->auth_allow(). This denies buddy requests.
 *
 * @param ic  The #im_connection.
 * @param who The handle of the buddy.
 **/
static void fb_auth_deny(struct im_connection *ic, const char *who)
{

}

/**
 * Implements #prpl->buddy_data_add(). This adds data to the buddy.
 *
 * @param bu The #bee_user.
 **/
static void fb_buddy_data_add(struct bee_user *bu)
{

}

/**
 * Implements #prpl->buddy_data_free(). This frees the buddy data.
 *
 * @param bu The #bee_user.
 **/
static void fb_buddy_data_free(struct bee_user *bu)
{

}

/**
 * Obtains a #account from command arguments.
 *
 * @param irc      The #irc.
 * @param args     The command arguments.
 * @param required The amount of required arguments.
 * @param offset   The return location for the args offset.
 *
 * @return The #account or NULL on error.
 **/
static account_t *fb_cmd_account(irc_t *irc, char **args, guint required,
                                 guint *offset)
{
    account_t *a;
    account_t *acc;
    guint      accs;
    guint      size;
    guint      oset;

    for (accs = 0, a = irc->b->accounts; a != NULL; a = a->next) {
        if ((g_ascii_strcasecmp(a->prpl->name, "facebook") == 0) &&
            (a->ic != NULL))
        {
            acc = a;
            accs++;
        }
    }

    if (accs == 0) {
        irc_rootmsg(irc, "There are no active Facebook accounts!");
        return NULL;
    }

    /* Calculate the size of args */
    for (size = 1; args[size] != NULL; size++);

    if (accs > 1) {
        if (args[1] == NULL) {
            irc_rootmsg(irc, "More than one Facebook account, specify one.");
            return NULL;
        }

        /* More than one account, look up by handle */
        acc  = account_get(irc->b, args[1]);
        oset = 2;

        if (acc == NULL) {
            irc_rootmsg(irc, "Unknown account: %s", args[1]);
            return NULL;
        }

        if (acc->ic == NULL) {
            irc_rootmsg(irc, "Account not online: %s", acc->tag);
            return NULL;
        }

        if (g_ascii_strcasecmp(acc->prpl->name, "facebook") != 0) {
            irc_rootmsg(irc, "Unknown Facebook account: %s", acc->tag);
            return NULL;
        }
    } else if ((size != (required + 1)) &&
               (args[1] != NULL) &&
               (account_get(irc->b, args[1]) == acc))
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

    if (offset != NULL)
        *offset = oset;

    return acc;
}

/**
 * Implemented #root_command_add() callback for the 'fbchats' command.
 *
 * @param irc  The #irc.
 * @param args The command arguments.
 **/
static void fb_cmd_fbchats(irc_t *irc, char **args)
{
    account_t *acc;
    fb_data_t *fata;

    acc = fb_cmd_account(irc, args, 0, NULL);

    if (acc == NULL)
        return;

    fata = acc->ic->proto_data;
    fb_api_thread_list(fata->api, 25);
}

/**
 * Implemented #root_command_add() callback for the 'fbcreate' command.
 *
 * @param irc  The #irc.
 * @param args The command arguments.
 **/
static void fb_cmd_fbcreate(irc_t *irc, char **args)
{
    account_t  *acc;
    fb_data_t  *fata;
    fb_id_t     uid;
    irc_user_t *iu;
    GSList     *uids;
    guint       oset;
    guint       i;

    acc  = fb_cmd_account(irc, args, 2, &oset);
    uids = NULL;

    if (acc == NULL)
        return;

    fata = acc->ic->proto_data;

    for (i = oset; args[i] != NULL; i++) {
        iu = irc_user_by_name(irc, args[i]);

        if (iu != NULL) {
            uid = FB_ID_FROM_STR(iu->bu->handle);
            uids = g_slist_prepend(uids, g_memdup(&uid, sizeof uid));
        }
    }

    if (uids == NULL) {
        imcb_error(fata->ic, "No valid users specified");
        return;
    }

    fb_api_thread_create(fata->api, uids);
    g_slist_free_full(uids, g_free);
}

/**
 * Implemented #root_command_add() callback for the 'fbjoin' command.
 *
 * @param irc  The #irc.
 * @param args The command arguments.
 **/
static void fb_cmd_fbjoin(irc_t *irc, char **args)
{
    account_t *acc;
    fb_data_t *fata;
    fb_id_t   *tid;
    gchar     *name;
    guint      oset;
    gint64     indx;

    acc = fb_cmd_account(irc, args, 2, &oset);

    if (acc == NULL)
        return;

    fata = acc->ic->proto_data;
    name = args[oset + 1];
    indx = g_ascii_strtoll(args[oset], NULL, 10);
    tid  = g_slist_nth_data(fata->tids, indx - 1);

    if ((indx < 1) || (tid == NULL)) {
        imcb_error(fata->ic, "Invalid index: %" G_GINT64_FORMAT, indx);
        return;
    }

    if (fb_data_groupchat_new(acc->ic, *tid, name) == NULL) {
        imcb_error(fata->ic, "Failed to join chat: %s (%" FB_ID_FORMAT ")",
                   name, *tid);
    }
}

/**
 * Implements the #init_plugin() function. BitlBee looks for this
 * function and executes it to register the protocol and its related
 * callbacks.
 **/
void init_plugin()
{
    struct prpl *pp;

    pp = g_new0(struct prpl, 1);

    pp->name            = "facebook";
    pp->options         = OPT_NOOTR;
    pp->init            = fb_init;
    pp->login           = fb_login;
    pp->logout          = fb_logout;
    pp->buddy_msg       = fb_buddy_msg;
    pp->send_typing     = fb_send_typing;
    pp->add_buddy       = fb_add_buddy;
    pp->remove_buddy    = fb_remove_buddy;
    pp->add_permit      = fb_add_permit;
    pp->add_deny        = fb_add_deny;
    pp->rem_permit      = fb_rem_permit;
    pp->rem_deny        = fb_rem_deny;
    pp->get_info        = fb_get_info;
    pp->chat_invite     = fb_chat_invite;
    pp->chat_leave      = fb_chat_leave;
    pp->chat_msg        = fb_chat_msg;
    pp->chat_join       = fb_chat_join;
    pp->chat_topic      = fb_chat_topic;
    pp->handle_cmp      = g_ascii_strcasecmp;
    pp->auth_allow      = fb_auth_allow;
    pp->auth_deny       = fb_auth_deny;
    pp->buddy_data_add  = fb_buddy_data_add;
    pp->buddy_data_free = fb_buddy_data_free;

    register_protocol(pp);

    root_command_add("fbchats",  0, fb_cmd_fbchats,  0);
    root_command_add("fbcreate", 0, fb_cmd_fbcreate, 0);
    root_command_add("fbjoin",   0, fb_cmd_fbjoin,   0);
}

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

    set_setstr(&acc->set, "uid",   api->uid);
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
    fb_data_t  *fata = data;
    GSList     *l;
    bee_user_t *bu;

    imcb_connected(fata->ic);

    for (l = fata->ic->bee->users; l != NULL; l = l->next) {
        bu = l->data;

        /* For now, all users are online */
        imcb_buddy_status(fata->ic, bu->handle, OPT_LOGGED_IN, NULL, NULL);
    }
}

/**
 * Implemented #fb_api_funcs->contacts().
 *
 * @param api   The #fb_api.
 * @param users The #GSList of #fb_api_user.
 * @param data  The user defined data, which is #fb_data.
 **/
static void fb_cb_api_contacts(fb_api_t *api, const GSList *users,
                               gpointer data)
{
    fb_data_t     *fata = data;
    fb_api_user_t *user;
    const GSList  *l;

    for (l = users; l != NULL; l = l->next) {
        user = l->data;
        imcb_add_buddy(fata->ic, user->uid, NULL);
        imcb_buddy_nick_hint(fata->ic, user->uid, user->name);
        imcb_rename_buddy(fata->ic, user->uid, user->name);
    }

    imcb_log(fata->ic, "Establishing connection");
    fb_api_connect(fata->api);
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

    static const fb_api_funcs_t funcs = {
        .error    = fb_cb_api_error,
        .auth     = fb_cb_api_auth,
        .connect  = fb_cb_api_connect,
        .contacts = fb_cb_api_contacts
    };

    g_return_val_if_fail(acc != NULL, NULL);

    fata = g_new0(fb_data_t, 1);
    fata->api = fb_api_new(&funcs, fata);

    fata->ic = imcb_new(acc);
    fata->ic->proto_data = fata;

    fata->api->uid   = g_strdup(set_getstr(&acc->set, "uid"));
    fata->api->token = g_strdup(set_getstr(&acc->set, "token"));
    fata->api->cid   = g_strdup(set_getstr(&acc->set, "cid"));
    fata->api->mid   = g_strdup(set_getstr(&acc->set, "mid"));
    fata->api->cuid  = g_strdup(set_getstr(&acc->set, "cuid"));

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
    g_free(fata);
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
    pp->handle_cmp      = g_ascii_strcasecmp;
    pp->auth_allow      = fb_auth_allow;
    pp->auth_deny       = fb_auth_deny;
    pp->buddy_data_add  = fb_buddy_data_add;
    pp->buddy_data_free = fb_buddy_data_free;

    register_protocol(pp);
}

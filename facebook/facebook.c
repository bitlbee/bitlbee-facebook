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

/**
 * Creates a new #fb_data with an #account. The returned #fb_data
 * should be freed with #fb_data_free() when no longer needed.
 *
 * @param acc The #account.
 *
 * @return The #fb_data_t or NULL on error.
 **/
fb_data_t *fb_data_new(account_t *acc)
{
    fb_data_t *fata;

    g_return_val_if_fail(acc != NULL, NULL);

    fata = g_new0(fb_data_t, 1);

    fata->ic = imcb_new(acc);
    fata->ic->proto_data = fata;

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

    g_free(fata);
}

/**
 * Implements #prpl->init(). This initializes an account.
 *
 * @param acc The #account.
 **/
static void fb_init(account_t *acc)
{

}

/**
 * Implements #prpl->login(). This logins an account in.
 *
 * @param acc The #account.
 **/
static void fb_login(account_t *acc)
{

}

/**
 * Implements #prpl->logout(). This logs an account out.
 *
 * @param ic The #im_connection.
 **/
static void fb_logout(struct im_connection *ic)
{

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
 * @param bu The #bee_user_t.
 **/
static void fb_buddy_data_add(struct bee_user *bu)
{

}

/**
 * Implements #prpl->buddy_data_free(). This frees the buddy data.
 *
 * @param bu The #bee_user_t.
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

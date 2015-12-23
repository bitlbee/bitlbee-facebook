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

#ifndef _FACEBOOK_DATA_H_
#define _FACEBOOK_DATA_H_

/**
 * SECTION:data
 * @section_id: facebook-data
 * @short_description: <filename>facebook-data.h</filename>
 * @title: Connection Data
 *
 * The Connection Data.
 */

#include <bitlbee.h>

#include "facebook-api.h"
#include "facebook-glib.h"
#include "facebook-http.h"
#include "facebook-id.h"

#define FB_TYPE_DATA  (fb_data_get_type())
#define FB_DATA(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_DATA, FbData))
#define FB_DATA_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_DATA, FbDataClass))
#define FB_IS_DATA(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_DATA))
#define FB_IS_DATA_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_DATA))
#define FB_DATA_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_DATA, FbDataClass))

typedef struct _FbData FbData;
typedef struct _FbDataClass FbDataClass;
typedef struct _FbDataPrivate FbDataPrivate;

/**
 * FbData:
 *
 * Represents the connection data used by #FacebookProtocol.
 */
struct _FbData
{
    /*< private >*/
    GObject parent;
    FbDataPrivate *priv;
};

/**
 * FbDataClass:
 *
 * The base class for all #FbData's.
 */
struct _FbDataClass
{
    /*< private >*/
    GObjectClass parent_class;
};

/**
 * fb_data_get_type:
 *
 * Returns: The #GType for an #FbData.
 */
GType
fb_data_get_type(void);

/**
 * fb_data_new:
 * @acct: The #account_t.
 *
 * Creates a new #FbData. The returned #FbData should be freed with
 * #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbData.
 */
FbData *
fb_data_new(account_t *acct);

/**
 * fb_data_load:
 * @fata: The #FbData.
 *
 * Loads the internal data from the underlying #account_t.
 *
 * Return: TRUE if all of the data was loaded, otherwise FALSE.
 */
gboolean
fb_data_load(FbData *fata);

/**
 * fb_data_save:
 * @fata: The #FbData.
 *
 * Saves the internal data to the underlying #account_t.
 */
void
fb_data_save(FbData *fata);

/**
 * fb_data_add_groupchat:
 * @fata: The #FbData.
 * @gc: The #groupchat.
 *
 * Adds a #groupchat to the the #FbData.
 */
void
fb_data_add_groupchat(FbData *fata, struct groupchat *gc);

/**
 * fb_data_remove_groupchat:
 * @fata: The #FbData.
 * @gc: The #groupchat.
 *
 * Removes a #groupchat from the the #FbData.
 */
void
fb_data_remove_groupchat(FbData *fata, struct groupchat *gc);

/**
 * fb_data_add_thread_head:
 * @fata: The #FbData.
 * @tid: The thread #FbId.
 *
 * Adds a thread identifier to the head of the list in the #FbData.
 */
void
fb_data_add_thread_head(FbData *fata, FbId tid);

/**
 * fb_data_add_thread_tail:
 * @fata: The #FbData.
 * @tid: The thread #FbId.
 *
 * Adds a thread identifier to the tail of the list in the #FbData.
 */
void
fb_data_add_thread_tail(FbData *fata, FbId tid);

/**
 * fb_data_clear_threads:
 * @fata: The #FbData.
 *
 * Clears the thread identifier list in the #FbData.
 */
void
fb_data_clear_threads(FbData *fata);

/**
 * fb_data_get_thread:
 * @fata: The #FbData.
 * @index: The thread index.
 *
 * Gets the #FbId of a thread at @index from the #FbData.
 *
 * Returns: The #FbId at @index.
 */
FbId
fb_data_get_thread(FbData *fata, guint index);

/**
 * fb_data_add_timeout:
 * @fata: The #FbData.
 * @name: The name of the timeout.
 * @interval: The time, in milliseconds, between calls to @func.
 * @func: The #b_event_handler.
 * @data: The data passed to @func.
 *
 * Adds a new callback timer. The callback is called repeatedly on the
 * basis of @interval, until @func returns #FALSE. The timeout should
 * be cleared with #fb_data_clear_timeout() when no longer needed.
 */
void
fb_data_add_timeout(FbData *fata, const gchar *name, guint interval,
                    b_event_handler func, gpointer data);

/**
 * fb_data_clear_timeout:
 * @fata: The #FbData.
 * @name: The name of the timeout.
 * @remove: #TRUE to remove from the event loop, otherwise #FALSE.
 *
 * Clears and removes a callback timer. The only time @remove should be
 * #FALSE, is when being called from a #GSourceFunc, which is returning
 * #FALSE.
 */
void
fb_data_clear_timeout(FbData *fata, const gchar *name, gboolean remove);

/**
 * fb_data_get_api:
 * @fata: The #FbData.
 *
 * Gets the #FbApi from the #FbData.
 *
 * Return: The #FbApi.
 */
FbApi *
fb_data_get_api(FbData *fata);

/**
 * fb_data_get_connection:
 * @fata: The #FbData.
 *
 * Gets the #im_connection from the #FbData.
 *
 * Return: The #im_connection.
 */
struct im_connection *
fb_data_get_connection(FbData *fata);

/**
 * fb_data_add_message:
 * @fata: The #FbData.
 * @msg: The #FbApiMessage.
 *
 * Adds an #FbApiMessage to the #FbData.
 */
void
fb_data_add_message(FbData *fata, FbApiMessage *msg);

/**
 * fb_data_remove_message:
 * @fata: The #FbData.
 * @msg: The #FbApiMessage.
 *
 * Removes an #FbApiMessage from the #FbData.
 */
void
fb_data_remove_message(FbData *fata, FbApiMessage *msg);

/**
 * fb_data_take_messages:
 * @fata: The #FbData.
 * @uid: The user #FbId.
 *
 * Gets a #GSList of messages by the user #FbId from the #FbData. The
 * #FbApiMessage's are removed from the #FbData. The returned #GSList
 * and its #FbApiMessage's should be freed with #fb_api_message_free()
 * and #g_slist_free_full() when no longer needed.
 */
GSList *
fb_data_take_messages(FbData *fata, FbId uid);

#endif /* _FACEBOOK_DATA_H_ */

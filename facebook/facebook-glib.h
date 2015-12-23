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

#ifndef _FACEBOOK_GLIB_H_
#define _FACEBOOK_GLIB_H_

#include <gio/gio.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <glib-object.h>

#if !GLIB_CHECK_VERSION(2, 30, 0)
#define G_VALUE_INIT  {0, {{0}}}
#endif /* 2.30.0 */

#if !GLIB_CHECK_VERSION(2, 32, 0)
static inline GByteArray *
g_byte_array_new_take(guint8 *data, gsize len)
{
	GByteArray *bytes;

	bytes = g_byte_array_new();
	g_byte_array_append(bytes, data, len);
	g_free(data);

	return bytes;
}

static inline void
g_queue_free_full(GQueue *queue, GDestroyNotify free_func)
{
    g_queue_foreach(queue, (GFunc) free_func, NULL);
    g_queue_free(queue);
}
#endif /* 2.32.0 */

#endif /* _FACEBOOK_GLIB_H_ */

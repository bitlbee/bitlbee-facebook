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

/** @file **/

#ifndef _FACEBOOK_ID_H
#define _FACEBOOK_ID_H

#include <glib.h>
#include <glib/gprintf.h>

#define FB_ID_CONSTANT(v) G_GINT64_CONSTANT(v)
#define FB_ID_FORMAT      G_GINT64_FORMAT
#define FB_ID_MODIFIER    G_GINT64_MODIFIER
#define FB_ID_STRMAX      21
#define fb_id_hash        g_int64_hash
#define fb_id_equal       g_int64_equal

/**
 * Converts a string to a #fb_id.
 *
 * @param s The string.
 *
 * @return The resulting #fb_id.
 **/
#define FB_ID_FROM_STR(s) \
    g_ascii_strtoll(s, NULL, 10)

/**
 * Converts a #f_uid to a string. The buffer should be at least
 * #FB_ID_STRMAX in length.
 *
 * @param i The #fb_id.
 * @param s The string buffer.
 **/
#define FB_ID_TO_STR(i, s) \
    g_sprintf(s, "%" FB_ID_FORMAT, (fb_id_t) i)


/** The 64-bit Facebook identifier. **/
typedef gint64 fb_id_t;

#endif /* _FACEBOOK_ID_H */

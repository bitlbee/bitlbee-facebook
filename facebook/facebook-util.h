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

#ifndef _FACEBOOK_UTIL_H
#define _FACEBOOK_UTIL_H

#include <glib.h>

/**
 * Prints a debugging line to stdout.
 *
 * @param f   The format string literal.
 * @param ... The arguments for the format string.
 **/
#ifdef DEBUG_FACEBOOK
#define FB_UTIL_DEBUGLN(f, ...)                                   \
    G_STMT_START {                                                \
        if (fb_util_debugging()) {                                \
            g_print("[" PACKAGE_NAME "] " f "\n", ##__VA_ARGS__); \
        }                                                         \
    } G_STMT_END
#else /* DEBUG_FACEBOOK */
#define FB_UTIL_DEBUGLN(f, ...)
#endif /* DEBUG_FACEBOOK */


#ifdef DEBUG_FACEBOOK
gboolean fb_util_debugging(void);
#endif /* DEBUG_FACEBOOK */

#ifdef DEBUG_FACEBOOK
void fb_util_hexdump(const GByteArray *bytes, guint indent,
                     const gchar *fmt, ...)
    G_GNUC_PRINTF(3, 4);
#else /* DEBUG_FACEBOOK */
#define fb_util_hexdump(bs, i, f, ...)
#endif /* DEBUG_FACEBOOK */

gboolean fb_util_str_iequal(const gchar *s1, const gchar *s2);

gboolean fb_util_zcompressed(const GByteArray *bytes);

GByteArray *fb_util_zcompress(const GByteArray *bytes);

GByteArray *fb_util_zuncompress(const GByteArray *bytes);

#endif /* _FACEBOOK_UTIL_H */

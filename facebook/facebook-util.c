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

#include <string.h>

#include "facebook-util.h"

/**
 * Determines the debugging state of the plugin.
 *
 * @return TRUE if debugging is enabled, otherwise FALSE.
 **/
#ifdef DEBUG_FACEBOOK
gboolean fb_util_debugging(void)
{
    static gboolean debug = FALSE;
    static gboolean setup = FALSE;

    if (G_UNLIKELY(!setup)) {
        debug = g_getenv("BITLBEE_DEBUG") ||
                g_getenv("BITLBEE_DEBUG_FACEBOOK");
        setup = TRUE;
    }

    return debug;
}
#endif /* DEBUG_FACEBOOK */

/**
 * Compare two strings case insensitively. This is useful for where
 * the return value must be a boolean, such as with a #GEqualFunc.
 *
 * @param s1 The first string.
 * @param s2 The second string.
 *
 * @return TRUE if the strings are equal, otherwise FALSE.
 **/
gboolean fb_util_str_iequal(const gchar *s1, const gchar *s2)
{
    return g_ascii_strcasecmp(s1, s2) == 0;
}

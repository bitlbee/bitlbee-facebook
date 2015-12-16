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

#ifndef _FACEBOOK_UTIL_H_
#define _FACEBOOK_UTIL_H_

/**
 * SECTION:util
 * @section_id: facebook-util
 * @short_description: <filename>facebook-util.h</filename>
 * @title: General Utilities
 *
 * The general utilities.
 */

#include <glib.h>
#include <glib-object.h>

/**
 * FB_UTIL_ERROR:
 *
 * The #GQuark of the domain of utility errors.
 */
#define FB_UTIL_ERROR fb_util_error_quark()

typedef enum
{
    FB_UTIL_DEBUG_LEVEL_MISC,
    FB_UTIL_DEBUG_LEVEL_INFO,
    FB_UTIL_DEBUG_LEVEL_WARN,
    FB_UTIL_DEBUG_LEVEL_ERROR,
    FB_UTIL_DEBUG_LEVEL_FATAL
} FbDebugLevel;

/**
 * FbUtilError:
 * @FB_UTIL_ERROR_GENERAL: General failure.
 *
 * The error codes for the #FB_UTIL_ERROR domain.
 */
typedef enum
{
    FB_UTIL_ERROR_GENERAL
} FbUtilError;

/**
 * fb_util_error_quark:
 *
 * Gets the #GQuark of the domain of utility errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_util_error_quark(void);

/**
 * fb_util_debug:
 * @level: The #FbDebugLevel.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message.
 */
void
fb_util_debug(FbDebugLevel level, const gchar *format, ...)
              G_GNUC_PRINTF(2, 3);

/**
 * fb_util_vdebug:
 * @level: The #FbDebugLevel.
 * @format: The format string literal.
 * @ap: The #va_list.
 *
 * Logs a debugging message.
 */
void
fb_util_vdebug(FbDebugLevel level, const gchar *format, va_list ap);

/**
 * fb_util_debug_misc:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #FB_UTIL_DEBUG_LEVEL_MISC.
 */
void
fb_util_debug_misc(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_info:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #FB_UTIL_DEBUG_LEVEL_INFO.
 */
void
fb_util_debug_info(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_warn:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #FB_UTIL_DEBUG_LEVEL_WARN.
 */
void
fb_util_debug_warn(const gchar *format, ...)
                   G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_error:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #FB_UTIL_DEBUG_LEVEL_ERROR.
 */
void
fb_util_debug_error(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_fatal:
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a debugging message with the level of
 * #FB_UTIL_DEBUG_LEVEL_FATAL.
 */
void
fb_util_debug_fatal(const gchar *format, ...)
                    G_GNUC_PRINTF(1, 2);

/**
 * fb_util_debug_hexdump:
 * @level: The #FbDebugLevel.
 * @bytes: The #GByteArray.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Logs a hexdump of a #GByteArray.
 */
void
fb_util_debug_hexdump(FbDebugLevel level, const GByteArray *bytes,
                      const gchar *format, ...)
                      G_GNUC_PRINTF(3, 4);

/**
 * fb_util_locale_str:
 *
 * Gets the locale string (ex: en_US) from the system. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The locale string.
 */
gchar *
fb_util_locale_str(void);

/**
 * fb_util_randstr:
 * @size: The size of the string.
 *
 * Gets a random alphanumeric string. The returned string should be
 * freed with #g_free() when no longer needed.
 *
 * Returns: The random string.
 */
gchar *
fb_util_randstr(gsize size);

/**
 * fb_util_str_is:
 * @str: The string.
 * @type: The #GAsciiType.
 *
 * Determines if @str abides to the #GAsciiType.
 *
 * Returns: #TRUE if the string abides to @type, otherwise #FALSE.
 */
gboolean
fb_util_str_is(const gchar *str, GAsciiType type);

/**
 * fb_util_uuid:
 *
 * Gets a random UUID string. The returned string should be freed with
 * #g_free() when no longer needed.
 *
 * Returns: The UUID string.
 */
gchar *
fb_util_uuid(void);

/**
 * fb_util_zcompressed:
 * @bytes: The #GByteArray.
 *
 * Determines if the #GByteArray is zlib compressed.
 *
 * Returns: #TRUE if the #GByteArray is compressed, otherwise #FALSE.
 */
gboolean
fb_util_zcompressed(const GByteArray *bytes);

/**
 * fb_util_zcompress:
 * @bytes: The #GByteArray.
 * @error: The return location for the #GError, or #NULL.
 *
 * Compresses a #GByteArray with zlib. The returned #GByteArray should
 * be freed with #g_byte_array_free() when no longer needed.
 *
 * Returns: The compressed #GByteArray.
 */
GByteArray *
fb_util_zcompress(const GByteArray *bytes, GError **error);

/**
 * fb_util_zuncompress:
 * @bytes: The #GByteArray.
 * @error: The return location for the #GError, or #NULL.
 *
 * Uncompresses a #GByteArray with zlib. The returned #GByteArray
 * should be freed with #g_byte_array_free() when no longer needed.
 *
 * Returns: The uncompressed #GByteArray, or #NULL on error.
 */
GByteArray *
fb_util_zuncompress(const GByteArray *bytes, GError **error);

#endif /* _FACEBOOK_UTIL_H_ */

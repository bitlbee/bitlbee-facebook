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

#include <stdarg.h>
#include <string.h>
#include <zlib.h>

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
 * Dumps a #GByteArray to the debugging stream. This formats the output
 * similar to that of `hexdump -C`.
 *
 * @param bytes  The #GByteArray.
 * @param indent The indent width.
 * @param fmt    The format string or NULL.
 * @param ...    The format arguments.
 **/
#ifdef DEBUG_FACEBOOK
void fb_util_hexdump(const GByteArray *bytes, guint indent,
                     const gchar *fmt, ...)
{
    GString *gstr;
    va_list  ap;
    gchar   *instr;
    guint    i;
    guint    j;
    gchar    c;

    if (fmt != NULL) {
        va_start(ap, fmt);
        instr = g_strdup_vprintf(fmt, ap);
        FB_UTIL_DEBUGLN("%s", instr);
        g_free(instr);
        va_end(ap);
    }

    instr = g_strnfill(indent, ' ');
    gstr  = g_string_sized_new(80);
    i     = 0;

    if (G_UNLIKELY(bytes == NULL))
        goto finish;

    for (; i < bytes->len; i += 16) {
        g_string_append_printf(gstr, "%s%08x  ", instr, i);

        for (j = 0; j < 16; j++) {
            if ((i + j) < bytes->len) {
                g_string_append_printf(gstr, "%02x ", bytes->data[i + j]);
            } else {
                g_string_append(gstr, "   ");
            }

            if (j == 7)
                g_string_append_c(gstr, ' ');
        }

        g_string_append(gstr, " |");

        for (j = 0; (j < 16) && ((i + j) < bytes->len); j++) {
            c = bytes->data[i + j];

            if (!g_ascii_isprint(c) || g_ascii_isspace(c))
                c = '.';

            g_string_append_c(gstr, c);
        }

        g_string_append_c(gstr, '|');
        FB_UTIL_DEBUGLN("%s", gstr->str);
        g_string_erase(gstr, 0, -1);
    }

finish:
    g_string_append_printf(gstr, "%s%08x", instr, i);
    FB_UTIL_DEBUGLN("%s", gstr->str);

    g_string_free(gstr, TRUE);
    g_free(instr);
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

/**
 * Implemented #alloc_func for #g_malloc().
 *
 * @param opaque The user-defined data, which is NULL.
 * @param items  The number of items.
 * @param size   The size of each item.
 *
 * @return The pointer to the allocated memory.
 **/
static voidpf fb_util_zalloc(voidpf opaque, uInt items, uInt size)
{
    return g_malloc(size * items);
}

/**
 * Implemented #free_func for #g_free().
 *
 * @param opaque  The user-defined data, which is NULL.
 * @param address The pointer address.
 **/
static void fb_util_zfree(voidpf opaque, voidpf address)
{
    g_free(address);
}

/**
 * Determines if a #GByteArray is zlib compressed.
 *
 * @param bytes The #GByteArray.
 *
 * @return TRUE if the #GByteArray is compressed, otherwise FALSE.
 **/
gboolean fb_util_zcompressed(const GByteArray *bytes)
{
    guint8 b0;
    guint8 b1;

    g_return_val_if_fail(bytes != NULL, FALSE);

    if (bytes->len < 2)
        return FALSE;

    b0 = *(bytes->data + 0);
    b1 = *(bytes->data + 1);

    return ((((b0 << 8) | b1) % 31) == 0) && /* Check the header */
           ((b0 & 0x0F) == Z_DEFLATED);      /* Check the method */
}

/**
 * Compresses a #GByteArray with zlib. The returned #GByteArray should
 * be freed with #g_byte_array_free() when no longer needed.
 *
 * @param bytes The #GByteArray.
 *
 * @return The resulting #GByteArray, or NULL on error.
 **/
GByteArray *fb_util_zcompress(const GByteArray *bytes)
{
    GByteArray *ret;
    z_stream    zs;
    gsize       size;
    gint        res;

    g_return_val_if_fail(bytes != NULL, NULL);

    memset(&zs, 0, sizeof zs);
    zs.zalloc   = fb_util_zalloc;
    zs.zfree    = fb_util_zfree;
    zs.next_in  = bytes->data;
    zs.avail_in = bytes->len;

    if (deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK)
        return NULL;

    size = compressBound(bytes->len);
    ret  = g_byte_array_new();

    g_byte_array_set_size(ret, size);

    zs.next_out  = ret->data;
    zs.avail_out = size;

    res = deflate(&zs, Z_FINISH);

    if (res != Z_STREAM_END) {
        deflateEnd(&zs);
        g_byte_array_free(ret, TRUE);
        return NULL;
    }

    size -= zs.avail_out;
    g_byte_array_remove_range(ret, size, ret->len - size);

    deflateEnd(&zs);
    return ret;
}

/**
 * Uncompresses a zlib compressed #GByteArray. The returned #GByteArray
 * should be freed with #g_byte_array_free() when no longer needed.
 *
 * @param bytes The #GByteArray.
 *
 * @return The resulting #GByteArray, or NULL on error.
 **/
GByteArray *fb_util_zuncompress(const GByteArray *bytes)
{
    GByteArray *ret;
    z_stream    zs;
    guint8      out[1024];
    gint        res;

    g_return_val_if_fail(bytes != NULL, NULL);

    memset(&zs, 0, sizeof zs);
    zs.zalloc   = fb_util_zalloc;
    zs.zfree    = fb_util_zfree;
    zs.next_in  = bytes->data;
    zs.avail_in = bytes->len;

    if (inflateInit(&zs) != Z_OK)
        return NULL;

    ret = g_byte_array_new();

    do {
        zs.next_out  = out;
        zs.avail_out = sizeof out;

        res = inflate(&zs, Z_NO_FLUSH);

        if ((res != Z_OK) && (res != Z_STREAM_END)) {
            inflateEnd(&zs);
            g_byte_array_free(ret, TRUE);
            return NULL;
        }

        g_byte_array_append(ret, out, sizeof out - zs.avail_out);
    } while (res != Z_STREAM_END);

    inflateEnd(&zs);
    return ret;
}

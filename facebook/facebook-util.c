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

#include <bitlbee.h>
#include <sha1.h>
#include <stdarg.h>
#include <string.h>
#include <zlib.h>

#include "facebook-util.h"

GQuark
fb_util_error_quark(void)
{
    static GQuark q = 0;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("fb-util-error-quark");
    }

    return q;
}

void
fb_util_debug(FbDebugLevel level, const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(level, format, ap);
    va_end(ap);
}

void
fb_util_vdebug(FbDebugLevel level, const gchar *format, va_list ap)
{
    const gchar *lstr;
    gchar *str;

    static gboolean debug = FALSE;
    static gboolean setup = FALSE;

    g_return_if_fail(format != NULL);

    if (G_UNLIKELY(!setup)) {
        debug = (g_getenv("BITLBEE_DEBUG") != NULL) ||
                (g_getenv("BITLBEE_DEBUG_FACEBOOK") != NULL);
        setup = TRUE;
    }

    if (!debug) {
        return;
    }

    switch (level) {
    case FB_UTIL_DEBUG_LEVEL_MISC:
        lstr = "MISC";
        break;
    case FB_UTIL_DEBUG_LEVEL_INFO:
        lstr = "INFO";
        break;
    case FB_UTIL_DEBUG_LEVEL_WARN:
        lstr = "WARN";
        break;
    case FB_UTIL_DEBUG_LEVEL_ERROR:
        lstr = "ERROR";
        break;
    case FB_UTIL_DEBUG_LEVEL_FATAL:
        lstr = "FATAL";
        break;

    default:
        g_return_if_reached();
        return;
    }

    str = g_strdup_vprintf(format, ap);
    g_print("[%s] %s: %s\n", lstr, "facebook", str);
    g_free(str);
}

void
fb_util_debug_misc(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(FB_UTIL_DEBUG_LEVEL_MISC, format, ap);
    va_end(ap);
}

void
fb_util_debug_info(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(FB_UTIL_DEBUG_LEVEL_INFO, format, ap);
    va_end(ap);
}

void
fb_util_debug_warn(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(FB_UTIL_DEBUG_LEVEL_WARN, format, ap);
    va_end(ap);
}

void
fb_util_debug_error(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(FB_UTIL_DEBUG_LEVEL_ERROR, format, ap);
    va_end(ap);
}

void
fb_util_debug_fatal(const gchar *format, ...)
{
    va_list ap;

    va_start(ap, format);
    fb_util_vdebug(FB_UTIL_DEBUG_LEVEL_FATAL, format, ap);
    va_end(ap);
}

void
fb_util_debug_hexdump(FbDebugLevel level, const GByteArray *bytes,
                      const gchar *format, ...)
{
    gchar c;
    guint i;
    guint j;
    GString *gstr;
    va_list ap;

    static const gchar *indent = "  ";

    g_return_if_fail(bytes != NULL);

    if (format != NULL) {
        va_start(ap, format);
        fb_util_vdebug(level, format, ap);
        va_end(ap);
    }

    gstr = g_string_sized_new(80);

    for (i = 0; i < bytes->len; i += 16) {
        g_string_append_printf(gstr, "%s%08x  ", indent, i);

        for (j = 0; j < 16; j++) {
            if ((i + j) < bytes->len) {
                g_string_append_printf(gstr, "%02x ",
                                       bytes->data[i + j]);
            } else {
                g_string_append(gstr, "   ");
            }

            if (j == 7) {
                g_string_append_c(gstr, ' ');
            }
        }

        g_string_append(gstr, " |");

        for (j = 0; (j < 16) && ((i + j) < bytes->len); j++) {
            c = bytes->data[i + j];

            if (!g_ascii_isprint(c) || g_ascii_isspace(c)) {
                c = '.';
            }

            g_string_append_c(gstr, c);
        }

        g_string_append_c(gstr, '|');
        fb_util_debug(level, "%s", gstr->str);
        g_string_erase(gstr, 0, -1);
    }

    g_string_append_printf(gstr, "%s%08x", indent, i);
    fb_util_debug(level, "%s", gstr->str);
    g_string_free(gstr, TRUE);
}

gchar *
fb_util_locale_str(void)
{
    const gchar * const *langs;
    const gchar *lang;
    gchar *chr;
    guint i;

    static const gchar chrs[] = {'.', '@'};

    langs = g_get_language_names();
    lang = langs[0];

    if (g_strcmp0(lang, "C") == 0) {
        return g_strdup("en_US");
    }

    for (i = 0; i < G_N_ELEMENTS(chrs); i++) {
        chr = strchr(lang, chrs[i]);

        if (chr != NULL) {
            return g_strndup(lang, chr - lang);
        }
    }

    return g_strdup(lang);
}

gchar *
fb_util_randstr(gsize size)
{
    gchar *ret;
    GRand *rand;
    guint i;
    guint j;

    static const gchar chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789";
    static const gsize charc = G_N_ELEMENTS(chars) - 1;

    if (G_UNLIKELY(size < 1)) {
        return NULL;
    }

    rand = g_rand_new();
    ret = g_new(gchar, size + 1);

    for (i = 0; i < size; i++) {
        j = g_rand_int_range(rand, 0, charc);
        ret[i] = chars[j];
    }

    ret[size] = 0;
    g_rand_free(rand);
    return ret;
}

gboolean
fb_util_str_is(const gchar *str, GAsciiType type)
{
    gsize i;
    gsize size;
    guchar c;

    g_return_val_if_fail(str != NULL, FALSE);
    size = strlen(str);

    for (i = 0; i < size; i++) {
        c = (guchar) str[i];

        if ((g_ascii_table[c] & type) == 0) {
            return FALSE;
        }
    }

    return TRUE;
}

gchar *
fb_util_uuid(void)
{
    guint8 buf[50];
    sha1_state_t sha;

    sha1_init(&sha);
    random_bytes(buf, sizeof buf);
    sha1_append(&sha, buf, sizeof buf);
    return sha1_random_uuid(&sha);
}

static voidpf
fb_util_zalloc(voidpf opaque, uInt items, uInt size)
{
    return g_malloc(size * items);
}

static void
fb_util_zfree(voidpf opaque, voidpf address)
{
    g_free(address);
}

gboolean
fb_util_zcompressed(const GByteArray *bytes)
{
    guint8 b0;
    guint8 b1;

    g_return_val_if_fail(bytes != NULL, FALSE);

    if (bytes->len < 2) {
        return FALSE;
    }

    b0 = *(bytes->data + 0);
    b1 = *(bytes->data + 1);

    return ((((b0 << 8) | b1) % 31) == 0) && /* Check the header */
           ((b0 & 0x0F) == Z_DEFLATED);      /* Check the method */
}

GByteArray *
fb_util_zcompress(const GByteArray *bytes)
{
    GByteArray *ret;
    gint res;
    gsize size;
    z_stream zs;

    g_return_val_if_fail(bytes != NULL, NULL);

    memset(&zs, 0, sizeof zs);
    zs.zalloc = fb_util_zalloc;
    zs.zfree = fb_util_zfree;
    zs.next_in = bytes->data;
    zs.avail_in = bytes->len;

    if (deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK) {
        return NULL;
    }

    size = compressBound(bytes->len);
    ret = g_byte_array_new();

    g_byte_array_set_size(ret, size);

    zs.next_out = ret->data;
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

GByteArray *
fb_util_zuncompress(const GByteArray *bytes)
{
    GByteArray *ret;
    gint res;
    guint8 out[1024];
    z_stream zs;

    g_return_val_if_fail(bytes != NULL, NULL);

    memset(&zs, 0, sizeof zs);
    zs.zalloc = fb_util_zalloc;
    zs.zfree = fb_util_zfree;
    zs.next_in = bytes->data;
    zs.avail_in = bytes->len;

    if (inflateInit(&zs) != Z_OK) {
        return NULL;
    }

    ret = g_byte_array_new();

    do {
        zs.next_out = out;
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

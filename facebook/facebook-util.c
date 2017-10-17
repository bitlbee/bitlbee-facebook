/*
 * Copyright 2014-2016 James Geboski <jgeboski@gmail.com>
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
fb_util_get_locale(void)
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
fb_util_rand_alnum(guint len)
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

    g_return_val_if_fail(len > 0, NULL);
    rand = g_rand_new();
    ret = g_new(gchar, len + 1);

    for (i = 0; i < len; i++) {
        j = g_rand_int_range(rand, 0, charc);
        ret[i] = chars[j];
    }

    ret[len] = 0;
    g_rand_free(rand);
    return ret;
}

gchar *
fb_util_rand_uuid(void)
{
    guint8 buf[50];
    sha1_state_t sha;

    sha1_init(&sha);
    random_bytes(buf, sizeof buf);
    sha1_append(&sha, buf, sizeof buf);
    return sha1_random_uuid(&sha);
}

gboolean
fb_util_strtest(const gchar *str, GAsciiType type)
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

gboolean
fb_util_zlib_test(const GByteArray *bytes)
{
    guint8 b0;
    guint8 b1;

    g_return_val_if_fail(bytes != NULL, FALSE);

    if (bytes->len < 2) {
        return FALSE;
    }

    b0 = *(bytes->data + 0);
    b1 = *(bytes->data + 1);

    return ((((b0 << 8) | b1) % 31) == 0) &&    /* Check the header */
           ((b0 & 0x0F) == 8 /* Z_DEFLATED */); /* Check the method */
}

static GByteArray *
fb_util_zlib_conv(GConverter *conv, const GByteArray *bytes, GError **error)
{
    GByteArray *ret;
    GConverterResult res;
    gsize cize = 0;
    gsize rize;
    gsize wize;
    guint8 data[1024];

    ret = g_byte_array_new();

    while (TRUE) {
        rize = 0;
        wize = 0;

        res = g_converter_convert(conv,
                                  bytes->data + cize,
                                  bytes->len - cize,
                                  data, sizeof data,
                                  G_CONVERTER_INPUT_AT_END,
                                  &rize, &wize, error);

        switch (res) {
        case G_CONVERTER_CONVERTED:
            g_byte_array_append(ret, data, wize);
            cize += rize;
            break;

        case G_CONVERTER_ERROR:
            g_byte_array_free(ret, TRUE);
            return NULL;

        case G_CONVERTER_FINISHED:
            g_byte_array_append(ret, data, wize);
            return ret;

        default:
            break;
        }
    }
}

GByteArray *
fb_util_zlib_deflate(const GByteArray *bytes, GError **error)
{
    GByteArray *ret;
    GZlibCompressor *conv;

    conv = g_zlib_compressor_new(G_ZLIB_COMPRESSOR_FORMAT_ZLIB, -1);
    ret = fb_util_zlib_conv(G_CONVERTER(conv), bytes, error);
    g_object_unref(conv);
    return ret;
}

GByteArray *
fb_util_zlib_inflate(const GByteArray *bytes, GError **error)
{
    GByteArray *ret;
    GZlibDecompressor *conv;

    conv = g_zlib_decompressor_new(G_ZLIB_COMPRESSOR_FORMAT_ZLIB);
    ret = fb_util_zlib_conv(G_CONVERTER(conv), bytes, error);
    g_object_unref(conv);
    return ret;
}

gchar *
fb_util_urlsafe_base64_encode(const guchar *data, gsize len)
{
    gchar *out = g_base64_encode(data, len);
    gchar *c;

    for (c = out; *c; c++) {
        if (*c == '+') {
            *c = '-';
        } else if (*c == '/') {
            *c = '_';
        } else if (*c == '=') {
            *c = '\0';
            break;
        }
    }

    return out;
}

void
fb_util_gen_sso_verifier(gchar **challenge, gchar **verifier, gchar **req_id)
{
    guint8 buf[32];
    GChecksum *gc;
    gsize digest_len = sizeof buf;

    random_bytes(buf, sizeof buf);

    *verifier = fb_util_urlsafe_base64_encode(buf, sizeof buf);

    gc = g_checksum_new(G_CHECKSUM_SHA256);
    g_checksum_update(gc, (guchar *) *verifier, -1);
    g_checksum_get_digest(gc, buf, &digest_len);
    g_checksum_free(gc);

    *challenge = fb_util_urlsafe_base64_encode(buf, sizeof buf);

    random_bytes(buf, 3);

    *req_id = fb_util_urlsafe_base64_encode(buf, 3);
}

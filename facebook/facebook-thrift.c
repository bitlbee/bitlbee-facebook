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

#include <string.h>

#include "facebook-thrift.h"

/**
 * Creates a new #fb_thrift. The returned #fb_thrift should be freed
 * with #fb_thrift_free() when no longer needed. If #GByteArray passed
 * to this function is not NULL, then it MUST exist for the lifetime
 * of the #fb_thrift.
 *
 * @param bytes   The #GByteArray or NULL.
 * @param offset  The data offset.
 * @param compact TRUE for compact types.
 *
 * @return The #fb_thrift or NULL on error.
 **/
fb_thrift_t *fb_thrift_new(GByteArray *bytes, guint offset, gboolean compact)
{
    fb_thrift_t *thft;

    thft = g_new0(fb_thrift_t, 1);

    if (bytes == NULL) {
        thft->bytes  = g_byte_array_new();
        thft->flags |= FB_THRIFT_FLAG_INTERNAL;
    } else {
        thft->bytes  = bytes;
        thft->offset = offset;
    }

    if (compact)
        thft->flags |= FB_THRIFT_FLAG_COMPACT;

    thft->pos = thft->offset;
    return thft;
}

/**
 * Frees all memory used by a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 **/
void fb_thrift_free(fb_thrift_t *thft)
{
    if (G_UNLIKELY(thft == NULL))
        return;

    if (thft->flags & FB_THRIFT_FLAG_INTERNAL)
        g_byte_array_free(thft->bytes, TRUE);

    g_free(thft);
}

/**
 * Frees all memory used by a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 **/
void fb_thrift_reset(fb_thrift_t *thft)
{
    g_return_if_fail(thft != NULL);

    thft->pos = thft->offset;
}

/**
 * Reads raw data from a #fb_thrift. If the return location is NULL,
 * only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param data The data buffer or NULL.
 * @param size The size of data to read.
 *
 * @return TRUE if the data was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read(fb_thrift_t *thft, gpointer data, guint size)
{
    g_return_val_if_fail(thft != NULL, FALSE);

    if ((thft->pos + size) > thft->bytes->len)
        return FALSE;

    if ((data != NULL) && (size > 0))
        memcpy(data, thft->bytes->data + thft->pos, size);

    thft->pos += size;
    return TRUE;
}

/**
 * Reads a boolean from a #fb_thrift. If the return location is NULL,
 * only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param bln  The return location for the boolean or NULL.
 *
 * @return TRUE if the boolean was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_bool(fb_thrift_t *thft, gboolean *bln)
{
    guint8 byte;

    g_return_val_if_fail(thft != NULL, FALSE);

    if (bln != NULL)
        *bln = FALSE;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read_byte(thft, &byte))
            return FALSE;

        if (bln != NULL)
            *bln = byte != 0;

        return TRUE;
    }

    if ((thft->lastbool & 0x03) != 0x01) {
        if (!fb_thrift_read_byte(thft, &byte))
            return FALSE;

        if (bln != NULL)
            *bln = (byte & 0x0F) == 0x01;

        return TRUE;
    }

    if (bln != NULL)
        *bln = ((thft->lastbool & 0x04) >> 2) != 0;

    thft->lastbool = 0;
    return TRUE;
}

/**
 * Reads a single byte from a #fb_thrift. If the return location is
 * NULL, only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param byte The return location for the byte or NULL.
 *
 * @return TRUE if the byte was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_byte(fb_thrift_t *thft, guint8 *byte)
{
    if (byte != NULL)
        *byte = 0;

    return fb_thrift_read(thft, byte, sizeof *byte);
}

/**
 * Reads a double from a #fb_thrift. If the return location is NULL,
 * only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param dbl  The return location for the double or NULL.
 *
 * @return TRUE if the double was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_dbl(fb_thrift_t *thft, gdouble *dbl)
{
    gint64 i64;

    /* Almost always 8, but check anyways */
    static const gsize size = MIN(sizeof dbl, sizeof i64);

    if (dbl != NULL)
        *dbl = 0;

    if (!fb_thrift_read_i64(thft, &i64))
        return FALSE;

    if (dbl != NULL)
        memcpy(&dbl, &i64, size);

    return TRUE;
}

/**
 * Reads a 16-bit integer from a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer from the zigzag format
 * after reading. If the return location is NULL, only the cursor is
 * advanced.
 *
 * @param thft The #fb_thrift.
 * @param i16  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_i16(fb_thrift_t *thft, gint16 *i16)
{
    gint64 i64;

    g_return_val_if_fail(thft != NULL, FALSE);

    if (i16 != NULL)
        *i16 = 0;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read(thft, i16, sizeof *i16))
            return FALSE;

        if (i16 != NULL)
            *i16 = GINT16_FROM_BE(*i16);

        return TRUE;
    }

    if (!fb_thrift_read_i64(thft, &i64))
        return FALSE;

    if (i16 != NULL)
        *i16 = i64;

    return TRUE;
}

/**
 * Reads a 16-bit variable integer from a #fb_thrift. This function
 * only reads if the #fb_thrift is in compact mode. This only reads
 * the raw integer value without converting from the zigzag format.
 * If the return location is NULL, only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param u16  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_vi16(fb_thrift_t *thft, guint16 *u16)
{
    guint64 u64;

    if (u16 != NULL)
        *u16 = 0;

    if (!fb_thrift_read_vi64(thft, &u64))
        return FALSE;

    if (u16 != NULL)
        *u16 = u64;

    return TRUE;
}

/**
 * Reads a 32-bit integer from a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer from the zigzag format
 * after reading. If the return location is NULL, only the cursor is
 * advanced.
 *
 * @param thft The #fb_thrift.
 * @param i32  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_i32(fb_thrift_t *thft, gint32 *i32)
{
    gint64 i64;

    g_return_val_if_fail(thft != NULL, FALSE);

    if (i32 != NULL)
        *i32 = 0;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read(thft, i32, sizeof *i32))
            return FALSE;

        if (i32 != NULL)
            *i32 = GINT32_FROM_BE(*i32);

        return TRUE;
    }

    if (!fb_thrift_read_i64(thft, &i64))
        return FALSE;

    if (i32 != NULL)
        *i32 = i64;

    return TRUE;
}

/**
 * Reads a 32-bit variable integer from a #fb_thrift. This function
 * only reads if the #fb_thrift is in compact mode. This only reads
 * the raw integer value without converting from the zigzag format.
 * If the return location is NULL, only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param u32  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_vi32(fb_thrift_t *thft, guint32 *u32)
{
    guint64 u64;

    if (u32 != NULL)
        *u32 = 0;

    if (!fb_thrift_read_vi64(thft, &u64))
        return FALSE;

    if (u32 != NULL)
        *u32 = u64;

    return TRUE;
}

/**
 * Reads a 64-bit integer from a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer from the zigzag format
 * after reading. If the return location is NULL, only the cursor is
 * advanced.
 *
 * @param thft The #fb_thrift.
 * @param i64  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_i64(fb_thrift_t *thft, gint64 *i64)
{
    guint64 u64;

    g_return_val_if_fail(thft != NULL, FALSE);

    if (i64 != NULL)
        *i64 = 0;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read(thft, i64, sizeof *i64))
            return FALSE;

        if (i64 != NULL)
            *i64 = GINT64_FROM_BE(*i64);

        return TRUE;
    }

    if (!fb_thrift_read_vi64(thft, &u64))
        return FALSE;

    if (i64 != NULL) {
        /* Convert from zigzag to integer */
        *i64 = (u64 >> 0x01) ^ -(u64 & 0x01);
    }

    return TRUE;
}

/**
 * Reads a 64-bit variable integer from a #fb_thrift. This function
 * only reads if the #fb_thrift is in compact mode. This only reads
 * the raw integer value without converting from the zigzag format.
 * If the return location is NULL, only the cursor is advanced.
 *
 * @param thft The #fb_thrift.
 * @param u64  The return location for the integer or NULL.
 *
 * @return TRUE if the integer was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_vi64(fb_thrift_t *thft, guint64 *u64)
{
    guint8 byte;
    guint  i;

    g_return_val_if_fail(thft != NULL, FALSE);

    if (u64 != NULL) {
        *u64 = 0;
         i   = 0;
    }

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT))
        return FALSE;

    do {
        if (!fb_thrift_read_byte(thft, &byte)) {
            if (u64 != NULL)
                *u64 = 0;

            return FALSE;
        }

        if (u64 != NULL) {
            *u64 |= ((guint64) (byte & 0x7F)) << i;
             i   += 7;
        }
    } while ((byte & 0x80) == 0x80);

    return TRUE;
}

/**
 * Reads a string from a #fb_thrift. If the return location is NULL,
 * only the cursor is advanced. The returned string should be freed
 * with #g_free() when no longer needed.
 *
 * @param thft The #fb_thrift.
 * @param str  The return location for the string or NULL.
 *
 * @return TRUE if the string was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_str(fb_thrift_t *thft, gchar **str)
{
    guint32   size;
    guint8   *data;
    gboolean  res;

    if (str != NULL)
        *str = NULL;

    if (thft->flags & FB_THRIFT_FLAG_COMPACT)
        res = fb_thrift_read_vi32(thft, &size);
    else
        res = fb_thrift_read_i32(thft, (gint32*) &size);

    if (!res)
        return FALSE;

    if (str != NULL) {
        data = g_new(guint8, size + 1);
        data[size] = 0;
    } else {
        data = NULL;
    }

    if (!fb_thrift_read(thft, data, size)) {
        g_free(data);
        return FALSE;
    }

    if (str != NULL)
        *str = (gchar*) data;

    return TRUE;
}

/**
 * Reads a field header from a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The return location for the #fb_thrift_type.
 * @param id   The return location for the identifier or NULL.
 *
 * @return TRUE if the header was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_field(fb_thrift_t *thft, fb_thrift_type_t *type,
                              gint16 *id)
{
    guint8 byte;
    gint16 i16;

    g_return_val_if_fail(thft != NULL, FALSE);
    g_return_val_if_fail(type != NULL, FALSE);

    if (id != NULL)
        *id = 0;

    if (!fb_thrift_read_byte(thft, &byte)) {
        *type = 0;
        return FALSE;
    }

    if (byte == FB_THRIFT_TYPE_STOP) {
        *type = byte;
        return FALSE;
    }

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        *type = byte;

        if (!fb_thrift_read_i16(thft, &i16))
            return FALSE;

        if (id != NULL)
            *id = i16;

        return TRUE;
    }

    *type = fb_thrift_ct2t(byte & 0x0F);
    i16   = (byte & 0xF0) >> 4;

    if (*type == FB_THRIFT_TYPE_BOOL) {
        thft->lastbool = 0x01;

        if ((byte & 0x0F) == 0x01)
            thft->lastbool |= 0x01 << 2;

        return TRUE;
    }

    if (i16 == 0) {
        if (!fb_thrift_read_i16(thft, &i16))
            return FALSE;
    } else {
        i16 = thft->lastid + i16;
    }

    if (id != NULL)
        *id = i16;

    thft->lastid = i16;
    return TRUE;
}

/**
 * Reads a field stop from a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 *
 * @return TRUE if the stop was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_stop(fb_thrift_t *thft)
{
    guint8 byte;

    return fb_thrift_read_byte(thft, &byte) &&
           (byte == FB_THRIFT_TYPE_STOP);
}

/**
 * Determines if the next byte is a field stop without advancing the
 * cursor.
 *
 * @param thft The #fb_thrift.
 *
 * @return TRUE if the next byte is a field stop, otherwise FALSE.
 **/
gboolean fb_thrift_read_isstop(fb_thrift_t *thft)
{
    guint8 byte;

    if (!fb_thrift_read_byte(thft, &byte))
        return FALSE;

    thft->pos--;
    return byte == FB_THRIFT_TYPE_STOP;
}

/**
 * Reads a list header from a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The return location for the #fb_thrift_type.
 * @param size The return location for the size.
 *
 * @return TRUE if the header was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_list(fb_thrift_t *thft, fb_thrift_type_t *type,
                             guint *size)
{
    guint8  byte;
    gint32  i32;
    guint32 u32;

    g_return_val_if_fail(thft != NULL, FALSE);
    g_return_val_if_fail(type != NULL, FALSE);
    g_return_val_if_fail(size != NULL, FALSE);

    *type = 0;
    *size = 0;

    if (!fb_thrift_read_byte(thft, &byte))
        return FALSE;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read_i32(thft, &i32))
            return FALSE;

        *type = byte;
        *size = i32;
        return TRUE;
    }

    *type = fb_thrift_ct2t(byte & 0x0F);
    *size = (byte & 0xF0) >> 4;

    if (*size == 15) {
        if (!fb_thrift_read_vi32(thft, &u32))
            return FALSE;

        *size = u32;
    }

    return TRUE;
}

/**
 * Reads a map header from a #fb_thrift.
 *
 * @param thft  The #fb_thrift.
 * @param ktype The return location for the key #fb_thrift_type.
 * @param vtype The return location for the value #fb_thrift_type.
 * @param size  The return location for the size.
 *
 * @return TRUE if the header was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_map(fb_thrift_t *thft, fb_thrift_type_t *ktype,
                            fb_thrift_type_t *vtype, guint *size)
{
    guint8 byte;
    gint32 i32;

    g_return_val_if_fail(thft  != NULL, FALSE);
    g_return_val_if_fail(ktype != NULL, FALSE);
    g_return_val_if_fail(vtype != NULL, FALSE);
    g_return_val_if_fail(size  != NULL, FALSE);

    *ktype = 0;
    *vtype = 0;
    *size  = 0;

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        if (!fb_thrift_read_byte(thft, &byte))
            return FALSE;

        *ktype = byte;

        if (!fb_thrift_read_byte(thft, &byte))
            return FALSE;

        *vtype = byte;

        if (!fb_thrift_read_i32(thft, &i32))
            return FALSE;

        *size = i32;
        return TRUE;
    }

    if (!fb_thrift_read_i32(thft, &i32))
        return FALSE;

    *size = i32;

    if (*size != 0) {
        if (!fb_thrift_read_byte(thft, &byte))
            return FALSE;

        *ktype = fb_thrift_ct2t((byte & 0xF0) >> 4);
        *vtype = fb_thrift_ct2t(byte & 0x0F);
    } else {
        *ktype = 0;
        *vtype = 0;
    }

    return TRUE;
}

/**
 * Reads a set header from a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The return location for the #fb_thrift_type.
 * @param size The return location for the size.
 *
 * @return TRUE if the header was completely read, otherwise FALSE.
 **/
gboolean fb_thrift_read_set(fb_thrift_t *thft, fb_thrift_type_t *type,
                            guint *size)
{
    return fb_thrift_read_list(thft, type, size);
}

/**
 * Writes raw data to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param data The data.
 * @param size The size of the data.
 **/
void fb_thrift_write(fb_thrift_t *thft, gconstpointer data, guint size)
{
    g_return_if_fail(thft != NULL);

    g_byte_array_append(thft->bytes, data, size);
    thft->pos += size;
}

/**
 * Writes a boolean to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param bln  The boolean.
 **/
void fb_thrift_write_bool(fb_thrift_t *thft, gboolean bln)
{
    guint pos;

    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        fb_thrift_write_byte(thft, bln != 0);
        return;
    }

    if ((thft->lastbool & 0x03) != 0x02) {
        fb_thrift_write_byte(thft, bln ? 0x01 : 0x02);
        return;
    }

    pos = thft->lastbool >> 3;
    thft->lastbool = 0;

    if ((pos >= thft->offset) && (pos < thft->bytes->len)) {
        thft->bytes->data[pos] &= ~0x0F;
        thft->bytes->data[pos] |= bln ? 0x01 : 0x02;
    }
}

/**
 * Writes a single byte to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param byte The byte.
 **/
void fb_thrift_write_byte(fb_thrift_t *thft, guint8 byte)
{
    fb_thrift_write(thft, &byte, sizeof byte);
}

/**
 * Writes a double to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param dbl  The double.
 **/
void fb_thrift_write_dbl(fb_thrift_t *thft, gdouble dbl)
{
    gint64 i64;

    /* Almost always 8, but check anyways */
    static const gsize size = MIN(sizeof dbl, sizeof i64);

    memcpy(&i64, &dbl, size);
    fb_thrift_write_i64(thft, i64);
}

/**
 * Writes a 16-bit integer to a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer to the zigzag format
 * before writing.
 *
 * @param thft The #fb_thrift.
 * @param i16  The integer.
 **/
void fb_thrift_write_i16(fb_thrift_t *thft, gint16 i16)
{
    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        i16 = GINT16_TO_BE(i16);
        fb_thrift_write(thft, &i16, sizeof i16);
        return;
    }

    fb_thrift_write_i32(thft, i16);
}

/**
 * Writes a 16-bit variable integer to a #fb_thrift. This function only
 * writes if the #fb_thrift is in compact mode. This only writes the
 * raw integer value without converting to the zigzag format.
 *
 * @param thft The #fb_thrift.
 * @param u16  The integer.
 **/
void fb_thrift_write_vi16(fb_thrift_t *thft, guint16 u16)
{
    fb_thrift_write_vi32(thft, u16);
}

/**
 * Writes a 32-bit integer to a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer to the zigzag format
 * before writing.
 *
 * @param thft The #fb_thrift.
 * @param i32  The integer.
 **/
void fb_thrift_write_i32(fb_thrift_t *thft, gint32 i32)
{
    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        i32 = GINT32_TO_BE(i32);
        fb_thrift_write(thft, &i32, sizeof i32);
        return;
    }

    i32 = (i32 << 1) ^ (i32 >> 31);
    fb_thrift_write_vi64(thft, i32);
}

/**
 * Writes a 32-bit variable integer to a #fb_thrift. This function only
 * writes if the #fb_thrift is in compact mode. This only writes the
 * raw integer value without converting to the zigzag format.
 *
 * @param thft The #fb_thrift.
 * @param u32  The integer.
 **/
void fb_thrift_write_vi32(fb_thrift_t *thft, guint32 u32)
{
    fb_thrift_write_vi64(thft, u32);
}


/**
 * Writes a 64-bit integer to a #fb_thrift. If the #fb_thrift is in
 * compact mode, this will convert the integer to the zigzag format
 * before writing.
 *
 * @param thft The #fb_thrift.
 * @param i64  The integer.
 **/
void fb_thrift_write_i64(fb_thrift_t *thft, gint64 i64)
{
    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        i64 = GINT64_TO_BE(i64);
        fb_thrift_write(thft, &i64, sizeof i64);
        return;
    }

    i64 = (i64 << 1) ^ (i64 >> 63);
    fb_thrift_write_vi64(thft, i64);
}

/**
 * Writes a 64-bit variable integer to a #fb_thrift. This function only
 * writes if the #fb_thrift is in compact mode. This only writes the
 * raw integer value without converting to the zigzag format.
 *
 * @param thft The #fb_thrift.
 * @param u64  The integer.
 **/
void fb_thrift_write_vi64(fb_thrift_t *thft, guint64 u64)
{
    gboolean last;
    guint8   byte;

    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT))
        return;

    do {
        last = (u64 & ~0x7F) == 0;
        byte = !last ? ((u64 & 0x7F) | 0x80) : (u64 & 0x0F);

        fb_thrift_write_byte(thft, byte);
        u64 >>= 7;
    } while (!last);
}

/**
 * Writes a string to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param str  The string.
 **/
void fb_thrift_write_str(fb_thrift_t *thft, const gchar *str)
{
    guint32 size;

    g_return_if_fail(str != NULL);

    size = strlen(str);

    if (thft->flags & FB_THRIFT_FLAG_COMPACT)
        fb_thrift_write_vi32(thft, size);
    else
        fb_thrift_write_i32(thft, size);

    fb_thrift_write(thft, str, size);
}

/**
 * Writes a field header to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The #fb_thrift_type.
 * @param id   The identifier.
 **/
void fb_thrift_write_field(fb_thrift_t *thft, fb_thrift_type_t type,
                           gint16 id)
{
    gint16 iddf;

    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        fb_thrift_write_byte(thft, type);
        fb_thrift_write_i16(thft, id);
        return;
    }

    if (type == FB_THRIFT_TYPE_BOOL)
        thft->lastbool = (thft->pos << 3) | 0x02;

    type = fb_thrift_t2ct(type);
    iddf = id - thft->lastid;

    if ((id <= thft->lastid) || (iddf > 15)) {
        fb_thrift_write_byte(thft, type);
        fb_thrift_write_i16(thft, id);
    } else {
        fb_thrift_write_byte(thft, (iddf << 4) | type);
    }

    thft->lastid = id;
}

/**
 * Writes a field stop to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 **/
void fb_thrift_write_stop(fb_thrift_t *thft)
{
    fb_thrift_write_byte(thft, FB_THRIFT_TYPE_STOP);
}

/**
 * Writes a list header to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The #fb_thrift_type.
 * @param size The size.
 **/
void fb_thrift_write_list(fb_thrift_t *thft, fb_thrift_type_t type,
                          guint size)
{
    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        fb_thrift_write_byte(thft, type);
        fb_thrift_write_i32(thft, size);
        return;
    }

    type = fb_thrift_t2ct(type);

    if (size <= 14) {
        fb_thrift_write_byte(thft, (size << 4) | type);
        return;
    }

    fb_thrift_write_vi32(thft, size);
    fb_thrift_write_byte(thft, 0xF0 | type);
}

/**
 * Writes a map header to a #fb_thrift.
 *
 * @param thft  The #fb_thrift.
 * @param ktype The key #fb_thrift_type.
 * @param vtype The value #fb_thrift_type.
 * @param size  The size.
 **/
void fb_thrift_write_map(fb_thrift_t *thft, fb_thrift_type_t ktype,
                         fb_thrift_type_t vtype, guint size)
{
    g_return_if_fail(thft != NULL);

    if (!(thft->flags & FB_THRIFT_FLAG_COMPACT)) {
        fb_thrift_write_byte(thft, ktype);
        fb_thrift_write_byte(thft, vtype);
        fb_thrift_write_i32(thft, size);
        return;
    }

    if (size == 0) {
        fb_thrift_write_byte(thft, 0);
        return;
    }

    ktype = fb_thrift_t2ct(ktype);
    vtype = fb_thrift_t2ct(vtype);

    fb_thrift_write_vi32(thft, size);
    fb_thrift_write_byte(thft, (ktype << 4) | vtype);
}

/**
 * Writes a set header to a #fb_thrift.
 *
 * @param thft The #fb_thrift.
 * @param type The #fb_thrift_type.
 * @param size The size.
 **/
void fb_thrift_write_set(fb_thrift_t *thft, fb_thrift_type_t type,
                         guint size)
{
    fb_thrift_write_list(thft, type, size);
}

/**
 * Converts a #fb_thrift_type to a compact type.
 *
 * @param type The #fb_thrift_type.
 *
 * @return The equivalent compact type.
 **/
guint8 fb_thrift_t2ct(fb_thrift_type_t type)
{
    static const guint8 types[] = {
        [FB_THRIFT_TYPE_STOP]   = 0,
        [FB_THRIFT_TYPE_VOID]   = 0,
        [FB_THRIFT_TYPE_BOOL]   = 2,
        [FB_THRIFT_TYPE_BYTE]   = 3,
        [FB_THRIFT_TYPE_DOUBLE] = 7,
        [5]                     = 0,
        [FB_THRIFT_TYPE_I16]    = 4,
        [7]                     = 0,
        [FB_THRIFT_TYPE_I32]    = 5,
        [9]                     = 0,
        [FB_THRIFT_TYPE_I64]    = 6,
        [FB_THRIFT_TYPE_STRING] = 8,
        [FB_THRIFT_TYPE_STRUCT] = 12,
        [FB_THRIFT_TYPE_MAP]    = 11,
        [FB_THRIFT_TYPE_SET]    = 10,
        [FB_THRIFT_TYPE_LIST]   = 9
    };

    if (G_UNLIKELY(type >= G_N_ELEMENTS(types)))
        return 0;

    return types[type];
}

/**
 * Converts a compact type to a #fb_thrift_type.
 *
 * @param type The compact type.
 *
 * @return The equivalent #fb_thrift_type.
 **/
fb_thrift_type_t fb_thrift_ct2t(guint8 type)
{
    static const guint8 types[] = {
        [0]  = FB_THRIFT_TYPE_STOP,
        [1]  = FB_THRIFT_TYPE_BOOL,
        [2]  = FB_THRIFT_TYPE_BOOL,
        [3]  = FB_THRIFT_TYPE_BYTE,
        [4]  = FB_THRIFT_TYPE_I16,
        [5]  = FB_THRIFT_TYPE_I32,
        [6]  = FB_THRIFT_TYPE_I64,
        [7]  = FB_THRIFT_TYPE_DOUBLE,
        [8]  = FB_THRIFT_TYPE_STRING,
        [9]  = FB_THRIFT_TYPE_LIST,
        [10] = FB_THRIFT_TYPE_SET,
        [11] = FB_THRIFT_TYPE_MAP,
        [12] = FB_THRIFT_TYPE_STRUCT
    };

    if (G_UNLIKELY(type >= G_N_ELEMENTS(types)))
        return 0;

    return types[type];

}

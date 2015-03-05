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

#ifndef _FACEBOOK_THRIFT_H
#define _FACEBOOK_THRIFT_H

#include <glib.h>


/** The flags of a #fb_thrift. **/
typedef enum fb_thrift_flags fb_thrift_flags_t;

/** The #fb_thrift data types. **/
typedef enum fb_thrift_type fb_thrift_type_t;

/** The main structure for Thrift IO. **/
typedef struct fb_thrift fb_thrift_t;


/**
 * The flags of a #fb_thrift.
 **/
enum fb_thrift_flags
{
    FB_THRIFT_FLAG_COMPACT  = 1 << 0, /** Compact types. **/
    FB_THRIFT_FLAG_INTERNAL = 1 << 1  /** Internal #GByteArray. **/
};

/**
 * The #fb_thrift data types.
 **/
enum fb_thrift_type
{
    FB_THRIFT_TYPE_STOP   = 0,  /** Stop. **/
    FB_THRIFT_TYPE_VOID   = 1,  /** Void. **/
    FB_THRIFT_TYPE_BOOL   = 2,  /** Boolean. **/
    FB_THRIFT_TYPE_BYTE   = 3,  /** Byte. **/
    FB_THRIFT_TYPE_DOUBLE = 4,  /** Double. **/
    FB_THRIFT_TYPE_I16    = 6,  /** Integer (16-bit). **/
    FB_THRIFT_TYPE_I32    = 8,  /** Integer (32-bit). **/
    FB_THRIFT_TYPE_I64    = 10, /** Integer (64-bit). **/
    FB_THRIFT_TYPE_STRING = 11, /** String. **/
    FB_THRIFT_TYPE_STRUCT = 12, /** Structure. **/
    FB_THRIFT_TYPE_MAP    = 13, /** Map. **/
    FB_THRIFT_TYPE_SET    = 14, /** Set. **/
    FB_THRIFT_TYPE_LIST   = 15, /** List. **/
    FB_THRIFT_TYPE_ENUM   = 16, /** Enumerator. **/

    FB_THRIFT_TYPE_UNKNOWN      /** Unknown. **/

};

/**
 * The main structure for Thrift IO.
 **/
struct fb_thrift
{
    fb_thrift_flags_t flags; /** The #fb_thrift_flags. **/

    gint16 lastid;           /** The last identifier. **/
    guint  lastbool;         /** The last boolean value. **/

    GByteArray *bytes;       /** The #GByteArray of data. **/
    guint       offset;      /** The data offset. **/
    guint       pos;         /** The cursor position. **/
};


fb_thrift_t *fb_thrift_new(GByteArray *bytes, guint offset, gboolean compact);

void fb_thrift_free(fb_thrift_t *thft);

void fb_thrift_reset(fb_thrift_t *thft);

gboolean fb_thrift_read(fb_thrift_t *thft, gpointer data, guint size);

gboolean fb_thrift_read_bool(fb_thrift_t *thft, gboolean *bln);

gboolean fb_thrift_read_byte(fb_thrift_t *thft, guint8 *byte);

gboolean fb_thrift_read_dbl(fb_thrift_t *thft, gdouble *dbl);

gboolean fb_thrift_read_i16(fb_thrift_t *thft, gint16 *i16);

gboolean fb_thrift_read_vi16(fb_thrift_t *thft, guint16 *u16);

gboolean fb_thrift_read_i32(fb_thrift_t *thft, gint32 *i32);

gboolean fb_thrift_read_vi32(fb_thrift_t *thft, guint32 *u32);

gboolean fb_thrift_read_i64(fb_thrift_t *thft, gint64 *i64);

gboolean fb_thrift_read_vi64(fb_thrift_t *thft, guint64 *u64);

gboolean fb_thrift_read_str(fb_thrift_t *thft, gchar **str);

gboolean fb_thrift_read_field(fb_thrift_t *thft, fb_thrift_type_t *type,
                              gint16 *id);

gboolean fb_thrift_read_stop(fb_thrift_t *thft);

gboolean fb_thrift_read_isstop(fb_thrift_t *thft);

gboolean fb_thrift_read_list(fb_thrift_t *thft, fb_thrift_type_t *type,
                             guint *size);

gboolean fb_thrift_read_map(fb_thrift_t *thft, fb_thrift_type_t *ktype,
                            fb_thrift_type_t *vtype, guint *size);

gboolean fb_thrift_read_set(fb_thrift_t *thft, fb_thrift_type_t *type,
                            guint *size);

void fb_thrift_write(fb_thrift_t *thft, gconstpointer data, guint size);

void fb_thrift_write_bool(fb_thrift_t *thft, gboolean bln);

void fb_thrift_write_byte(fb_thrift_t *thft, guint8 byte);

void fb_thrift_write_dbl(fb_thrift_t *thft, gdouble dbl);

void fb_thrift_write_i16(fb_thrift_t *thft, gint16 i16);

void fb_thrift_write_vi16(fb_thrift_t *thft, guint16 u16);

void fb_thrift_write_i32(fb_thrift_t *thft, gint32 i32);

void fb_thrift_write_vi32(fb_thrift_t *thft, guint32 u32);

void fb_thrift_write_i64(fb_thrift_t *thft, gint64 i64);

void fb_thrift_write_vi64(fb_thrift_t *thft, guint64 u64);

void fb_thrift_write_str(fb_thrift_t *thft, const gchar *str);

void fb_thrift_write_field(fb_thrift_t *thft, fb_thrift_type_t type,
                           gint16 id);

void fb_thrift_write_stop(fb_thrift_t *thft);

void fb_thrift_write_list(fb_thrift_t *thft, fb_thrift_type_t type,
                          guint size);

void fb_thrift_write_map(fb_thrift_t *thft, fb_thrift_type_t ktype,
                         fb_thrift_type_t vtype, guint size);

void fb_thrift_write_set(fb_thrift_t *thft, fb_thrift_type_t type,
                         guint size);

guint8 fb_thrift_t2ct(fb_thrift_type_t type);

fb_thrift_type_t fb_thrift_ct2t(guint8 type);

#endif /* _FACEBOOK_THRIFT_H */

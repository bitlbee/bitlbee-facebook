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

/** @file **/

#ifndef _FACEBOOK_JSON_H
#define _FACEBOOK_JSON_H

#include <glib.h>
#include <json_util.h>


/** The #GError codes of the JSON parser. **/
typedef enum fb_json_error fb_json_error_t;


/**
 * The #GError codes of JSON parser.
 **/
enum fb_json_error
{
    FB_JSON_ERROR_PARSER
};


#define FB_JSON_ERROR fb_json_error_quark()

GQuark fb_json_error_quark(void);

json_value *fb_json_new(const gchar *data, gsize length, GError **err);

gchar *fb_json_valstr(const json_value *json);

json_value *fb_json_val(const json_value *json, const gchar *name,
                        json_type type);

gboolean fb_json_val_chk(const json_value *json, const gchar *name,
                         json_type type, json_value **val);

json_value *fb_json_array(const json_value *json, const gchar *name);

gboolean fb_json_array_chk(const json_value *json, const gchar *name,
                           json_value **val);

gboolean fb_json_bool(const json_value *json, const gchar *name);

gboolean fb_json_bool_chk(const json_value *json, const gchar *name,
                          gboolean *val);

gint64 fb_json_int(const json_value *json, const gchar *name);

gboolean fb_json_int_chk(const json_value *json, const gchar *name,
                         gint64 *val);

const gchar *fb_json_str(const json_value *json, const gchar *name);

gboolean fb_json_str_chk(const json_value *json, const gchar *name,
                         const gchar **val);

#endif /* _FACEBOOK_JSON_H */

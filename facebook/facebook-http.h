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

#ifndef _FACEBOOK_HTTP_H_
#define _FACEBOOK_HTTP_H_

/**
 * SECTION:api
 * @section_id: facebook-http
 * @short_description: <filename>facebook-http.h</filename>
 * @title: HTTP Client
 *
 * The HTTP client.
 */

#include <glib.h>
#include <glib-object.h>
#include <http_client.h>

#define FB_TYPE_HTTP  (fb_http_get_type())
#define FB_HTTP(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_HTTP, FbHttp))
#define FB_HTTP_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_HTTP, FbHttpClass))
#define FB_IS_HTTP(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_HTTP))
#define FB_IS_HTTP_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_HTTP))
#define FB_HTTP_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_HTTP, FbHttpClass))

#define FB_TYPE_HTTP_REQUEST  (fb_http_request_get_type())
#define FB_HTTP_REQUEST(obj)  (G_TYPE_CHECK_INSTANCE_CAST((obj), FB_TYPE_HTTP_REQUEST, FbHttpRequest))
#define FB_HTTP_REQUEST_CLASS(klass)  (G_TYPE_CHECK_CLASS_CAST((klass), FB_TYPE_HTTP_REQUEST, FbHttpRequestClass))
#define FB_IS_HTTP_REQUEST(obj)  (G_TYPE_CHECK_INSTANCE_TYPE((obj), FB_TYPE_HTTP_REQUEST))
#define FB_IS_HTTP_REQUEST_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE((klass), FB_TYPE_HTTP_REQUEST))
#define FB_HTTP_REQUEST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), FB_TYPE_HTTP_REQUEST, FbHttpRequestClass))

/**
 * FB_HTTP_ERROR:
 *
 * The #GQuark of the domain of HTTP errors.
 */
#define FB_HTTP_ERROR fb_http_error_quark()

typedef struct _FbHttp FbHttp;
typedef struct _FbHttpClass FbHttpClass;
typedef struct _FbHttpPrivate FbHttpPrivate;
typedef struct _FbHttpRequest FbHttpRequest;
typedef struct _FbHttpRequestClass FbHttpRequestClass;
typedef struct _FbHttpRequestPrivate FbHttpRequestPrivate;

/**
 * FbHttpValues:
 *
 * Represents a set of key/value HTTP values.
 */
typedef GHashTable FbHttpValues;

/**
 * FbHttpFunc:
 * @req: The #FbHttpRequest.
 * @data: The user-defined data.
 *
 * The callback for HTTP requests.
 */
typedef void (*FbHttpFunc) (FbHttpRequest *req, gpointer data);

/**
 * FbHttpError:
 * @FB_HTTP_ERROR_SUCCESS: There is no error.
 * @FB_HTTP_ERROR_INIT: The request failed to initialize.
 * @FB_HTTP_ERROR_NOMATCH: The name does not match anything.
 *
 * The error codes for the #FB_HTTP_ERROR domain.
 */
typedef enum
{
    FB_HTTP_ERROR_SUCCESS = 0,
    FB_HTTP_ERROR_INIT,
    FB_HTTP_ERROR_NOMATCH
} FbHttpError;

/**
 * FbHttp:
 *
 * Represents an HTTP client.
 */
struct _FbHttp
{
    /*< private >*/
    GObject parent;
    FbHttpPrivate *priv;
};

/**
 * FbHttpClass:
 *
 * The base class for all #FbHttp's.
 */
struct _FbHttpClass
{
    /*< private >*/
    GObjectClass parent_class;
};

/**
 * FbHttpRequest:
 *
 * Represents an HTTP request.
 */
struct _FbHttpRequest
{
    /*< private >*/
    GObject parent;
    FbHttpRequestPrivate *priv;
};

/**
 * FbHttpRequestClass:
 *
 * The base class for all #FbHttpRequest's.
 */
struct _FbHttpRequestClass
{
    /*< private >*/
    GObjectClass parent_class;
};

/**
 * fb_http_get_type:
 *
 * Returns: The #GType for an #FbHttp.
 */
GType
fb_http_get_type(void);

/**
 * fb_http_request_get_type:
 *
 * Returns: The #GType for an #FbHttpRequest.
 */
GType
fb_http_request_get_type(void);

/**
 * fb_http_error_quark:
 *
 * Gets the #GQuark of the domain of HTTP errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
fb_http_error_quark(void);

/**
 * fb_http_new:
 * @agent: The User-Agent.
 *
 * Creates a new #FbHttp. The returned #FbHttp should be freed with
 * #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbHttp.
 */
FbHttp *
fb_http_new(const gchar *agent);

/**
 * fb_http_get_cookies:
 * @http: The #FbHttp.
 *
 * Gets the #FbHttpValues for cookies from the #FbHttp. The returned
 * #FbHttpValues should not be freed.
 *
 * Returns: The #FbHttpValues.
 */
FbHttpValues *
fb_http_get_cookies(FbHttp *http);

/**
 * fb_http_close_requests:
 * @http: The #FbHttp.
 *
 * Closes all active #FbHttpRequest from the #FbHttp.
 */
void
fb_http_close_requests(FbHttp *http);

/**
 * fb_http_cookies_parse_request:
 * @http: The #FbHttp.
 * @data: The string to parse.
 *
 * Parses and loads cookies from the #FbHttpRequest into the #FbHttp.
 */
void
fb_http_cookies_parse_request(FbHttp *http, FbHttpRequest *req);

/**
 * fb_http_request_new:
 * @http: The #FbHttp.
 * @url: The url.
 * @post: #TRUE for the POST, otherwise #FALSE for GET.
 * @func: The #FbHttpFunc.
 * @data: The user-defined data.
 *
 * Creates a new #FbHttpRequest. The returned #FbHttpRequest should be
 * freed with #g_object_unref() when no longer needed.
 *
 * Returns: The new #FbHttpRequest.
 */
FbHttpRequest *
fb_http_request_new(FbHttp *http, const gchar *url, gboolean post,
                    FbHttpFunc func, gpointer data);

/**
 * fb_http_request_get_data:
 * @req: The #FbHttpRequest.
 * @code: The return location for size or #NULL.
 *
 * Gets the request data from the #FbHttpRequest. This should only be
 * inside #FbHttpFunc passed to #fb_http_request_new().
 *
 * Returns: The request data string.
 */
const gchar *
fb_http_request_get_data(FbHttpRequest *req, gsize *size);

/**
 * fb_http_request_get_headers:
 * @req: The #FbHttpRequest.
 *
 * Gets the #FbHttpValues for headers from the #FbHttpRequest. The
 * returned #FbHttpValues should not be freed.
 *
 * Returns: The #FbHttpValues.
 */
FbHttpValues *
fb_http_request_get_headers(FbHttpRequest *req);

/**
 * fb_http_request_get_params:
 * @req: The #FbHttpRequest.
 *
 * Gets the #FbHttpValues for parameters from the #FbHttpRequest. The
 * returned #FbHttpValues should not be freed.
 *
 * Returns: The #FbHttpValues.
 */
FbHttpValues *
fb_http_request_get_params(FbHttpRequest *req);

/**
 * fb_http_request_get_status:
 * @req: The #FbHttpRequest.
 * @code: The return location for the status code or #NULL.
 *
 * Gets the request status from the #FbHttpRequest. This should only be
 * inside #FbHttpFunc passed to #fb_http_request_new().
 *
 * Returns: The status string.
 */
const gchar *
fb_http_request_get_status(FbHttpRequest *req, gint *code);

/**
 * fb_http_request_take_error:
 * @req: The #FbHttpRequest.
 *
 * Gets the #GError from the #FbHttpRequest. This should only be
 * inside #FbHttpFunc passed to #fb_http_request_new(). The returned
 * #GError should be freed with #g_error_free() when no longer needed.
 *
 * Returns: The #GError or #NULL.
 */
GError *
fb_http_request_take_error(FbHttpRequest *req);

/**
 * fb_http_request_send:
 * @req: The #FbHttpRequest.
 *
 * Sends the #FbHttpRequest to the remote server.
 */
void
fb_http_request_send(FbHttpRequest *req);

/**
 * fb_http_urlcmp:
 * @url1: The first URL.
 * @url2: The second URL.
 * @protocol: #TRUE to match the protocols, otherwise #FALSE.
 *
 * Compares two URLs. This is more reliable than just comparing two URL
 * strings, as it avoids casing in some areas, while not in others. It
 * can also, optionally, ignore the matching of the URL protocol.
 *
 * Returns: #TRUE if the URLs match, otherwise #FALSE.
 */
gboolean
fb_http_urlcmp(const gchar *url1, const gchar *url2, gboolean protocol);

/**
 * fb_http_values_new:
 *
 * Creates a new #FbHttpValues. The returned #FbHttpValues should be
 * freed with #fb_http_values_free() when no longer needed.
 *
 * Returns: The new #FbHttpValues.
 */
FbHttpValues *
fb_http_values_new(void);

/**
 * fb_http_values_free:
 * @values: The #FbHttpValues.
 *
 * Frees all memory used by the #FbHttpValues.
 */
void
fb_http_values_free(FbHttpValues *values);

/**
 * fb_http_values_consume:
 * @values: The #FbHttpValues.
 * @consume: The #FbHttpValues to consume.
 *
 * Consumes another #FbHttpValues into the #FbHttpValues. This will
 * overwrite any existing values. This will free the consumed
 * #FbHttpValues.
 */
void
fb_http_values_consume(FbHttpValues *values, FbHttpValues *consume);

/**
 * fb_http_values_parse:
 * @values: The #FbHttpValues.
 * @data: The data string.
 * @isurl: TRUE if @data is a URL, otherwise FALSE.
 *
 * Parses and loads a parameter string into the #FbHttpValues.
 */
void
fb_http_values_parse(FbHttpValues *values, const gchar *data, gboolean isurl);

/**
 * fb_http_values_str_cookies:
 * @values: The #FbHttpValues.
 *
 * Creates a cookie string for the Set-Cookie header. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The cookie string.
 */
gchar *
fb_http_values_str_cookies(FbHttpValues *values);

/**
 * fb_http_values_str_headers:
 * @values: The #FbHttpValues.
 *
 * Creates a header string for a raw HTTP request. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * Returns: The header string.
 */
gchar *
fb_http_values_str_headers(FbHttpValues *values);

/**
 * fb_http_values_str_params:
 * @values: The #FbHttpValues.
 * @url: The URL or #NULL.
 *
 * Creates a parameter string for a raw HTTP request. If @url is
 * non-#NULL, then the parameters are appended to @url. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The parameter string.
 */
gchar *
fb_http_values_str_params(FbHttpValues *values, const gchar *url);

/**
 * fb_http_values_remove:
 * @values: The #FbHttpValues.
 * @name: The value name.
 *
 * Removes a value from the #FbHttpValues.
 *
 * Returns: #TRUE if the value was removed, otherwise #FALSE.
 */
gboolean
fb_http_values_remove(FbHttpValues *values, const gchar *name);

/**
 * fb_http_values_get_keys:
 * @values: The #FbHttpValues.
 *
 * Gets a #GList of keys from the #FbHttpValues.
 *
 * Returns: The #GList of keys.
 */
GList *
fb_http_values_get_keys(FbHttpValues *values);

/**
 * fb_http_values_get_bool:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @error: The return location for the #GError or #NULL.
 *
 * Gets a boolean value from the #FbHttpValues. This optionally assigns
 * an appropriate #GError upon failure.
 *
 * Return: The boolean value.
 */
gboolean
fb_http_values_get_bool(FbHttpValues *values, const gchar *name,
                        GError **error);

/**
 * fb_http_values_get_dbl:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @error: The return location for the #GError or #NULL.
 *
 * Gets a floating point value from the #FbHttpValues. This optionally
 * assigns an appropriate #GError upon failure.
 *
 * Return: The floating point value.
 */
gdouble
fb_http_values_get_dbl(FbHttpValues *values, const gchar *name,
                       GError **error);

/**
 * fb_http_values_get_int:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @error: The return location for the #GError or #NULL.
 *
 * Gets an integer value from the #FbHttpValues. This optionally
 * assigns an appropriate #GError upon failure.
 *
 * Return: The integer value.
 */
gint64
fb_http_values_get_int(FbHttpValues *values, const gchar *name,
                       GError **error);

/**
 * fb_http_values_get_str:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @error: The return location for the #GError or #NULL.
 *
 * Gets a string value from the #FbHttpValues. This optionally assigns
 * an appropriate #GError upon failure.
 *
 * Return: The string value.
 */
const gchar *
fb_http_values_get_str(FbHttpValues *values, const gchar *name,
                       GError **error);

/**
 * fb_http_values_dup_str:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @error: The return location for the #GError or #NULL.
 *
 * Gets a duplicated string value from the #FbHttpValues. This
 * optionally assigns an appropriate #GError upon failure. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Return: The duplicated string value.
 */
gchar *
fb_http_values_dup_str(FbHttpValues *values, const gchar *name,
                       GError **error);

/**
 * fb_http_values_set_bool:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @value: The value.
 *
 * Sets a boolean value to the #FbHttpValues.
 */
void
fb_http_values_set_bool(FbHttpValues *values, const gchar *name,
                        gboolean value);

/**
 * fb_http_values_set_dbl:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @value: The value.
 *
 * Sets a floating point value to the #FbHttpValues.
 */
void
fb_http_values_set_dbl(FbHttpValues *values, const gchar *name, gdouble value);

/**
 * fb_http_values_set_int:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @value: The value.
 *
 * Sets an integer value to the #FbHttpValues.
 */
void
fb_http_values_set_int(FbHttpValues *values, const gchar *name, gint64 value);

/**
 * fb_http_values_set_str:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @value: The value.
 *
 * Sets a string value to the #FbHttpValues.
 */
void
fb_http_values_set_str(FbHttpValues *values, const gchar *name,
                       const gchar *value);

/**
 * fb_http_values_set_strf:
 * @values: The #FbHttpValues.
 * @name: The value name.
 * @format: The format string literal.
 * @...: The arguments for @format.
 *
 * Sets a formatted string value to the #FbHttpValues.
 */
void
fb_http_values_set_strf(FbHttpValues *values, const gchar *name,
                        const gchar *format, ...)
                        G_GNUC_PRINTF(3, 4);

#endif /* _FACEBOOK_HTTP_H_ */

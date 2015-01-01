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

#ifndef _FACEBOOK_H
#define _FACEBOOK_H

#include <bitlbee.h>

#include "facebook-api.h"

/** The main structure for the plugin. **/
typedef struct fb_data fb_data_t;


/**
 * The main structure for the plugin.
 **/
struct fb_data
{
    struct im_connection *ic; /** The #im_connection. **/
    fb_api_t *api;            /** The #fb_api. **/
};


fb_data_t *fb_data_new(account_t *acc);

void fb_data_free(fb_data_t *fata);

#endif /* _FACEBOOK_H */

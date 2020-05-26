/*
 * obfs_http.h - Interfaces of http obfuscating function
 *
 * Copyright (C) 2013 - 2016, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the simple-obfs.
 *
 * simple-obfs is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * simple-obfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with simple-obfs; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef OBFS_HTTP_H
#define OBFS_HTTP_H

#include "obfs.h"

#ifndef SS_NG
extern obfs_para_t *obfs_http;
#else
int obfs_http_request(buffer_t *, size_t, obfs_t *, void *);
int obfs_http_response(buffer_t *, size_t, obfs_t *, void *);
int deobfs_http_header(buffer_t *, size_t, obfs_t *, void *);
int check_http_header(buffer_t *buf, void *);
void disable_http(obfs_t *obfs, void *);
int is_enable_http(obfs_t *obfs, void *);
#endif

#endif

/*
 * obfs_http.c - Implementation of http obfuscating
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <strings.h>
#include <ctype.h> /* isblank() */

#include "base64.h"
#include "utils.h"
#include "obfs_http.h"

static const char *http_request_template =
    "%s %s HTTP/1.1\r\n"
    "Host: %s\r\n"
    "User-Agent: curl/7.%d.%d\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: %s\r\n"
    "Content-Length: %lu\r\n"
    "\r\n";

static const char *http_response_template =
    "HTTP/1.1 101 Switching Protocols\r\n"
    "Server: nginx/1.%d.%d\r\n"
    "Date: %s\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Accept: %s\r\n"
    "\r\n";

static int get_header(const char *, const char *, int, char **);
static int next_header(const char **, int *);

int obfs_http_request(buffer_t *buf, size_t cap, obfs_t *obfs, obfs_para_t *obfs_para)
{

    if (obfs == NULL || obfs->obfs_stage != 0) return 0;
    obfs->obfs_stage++;

    static int major_version = 0;
    static int minor_version = 0;

    major_version = major_version ? major_version : rand() % 51;
    minor_version = minor_version ? minor_version : rand() % 2;

    char host_port[256];
    char http_header[512];
    uint8_t key[16];
    char b64[64];

    if (obfs_para->port != 80)
        snprintf(host_port, sizeof(host_port), "%s:%d", obfs_para->host, obfs_para->port);
    else
        snprintf(host_port, sizeof(host_port), "%s", obfs_para->host);

    rand_bytes(key, 16);
    base64_encode(b64, 64, key, 16);

    size_t obfs_len =
        snprintf(http_header, sizeof(http_header), http_request_template, obfs_para->method,
                 obfs_para->uri, host_port, major_version, minor_version, b64, buf->len);
    size_t buf_len = buf->len;

    brealloc(buf, obfs_len + buf_len, cap);

    memmove(buf->data + obfs_len, buf->data, buf_len);
    memcpy(buf->data, http_header, obfs_len);

    buf->len = obfs_len + buf_len;

    return buf->len;
}

int deobfs_http_header(buffer_t *buf, size_t cap, obfs_t *obfs)
{
    if (obfs == NULL || obfs->deobfs_stage != 0) return 0;

    char *data = buf->data;
    int len    = buf->len;
    int err    = -1;

    // Allow empty content
    while (len >= 4) {
        if (data[0] == '\r' && data[1] == '\n'
            && data[2] == '\r' && data[3] == '\n') {
            len  -= 4;
            data += 4;
            err   = 0;
            break;
        }
        len--;
        data++;
    }

    if (!err) {
        memmove(buf->data, data, len);
        buf->len = len;
        obfs->deobfs_stage++;
    }

    return err;
}

static int
get_header(const char *header, const char *data, int data_len, char **value)
{
    int len, header_len;

    header_len = strlen(header);

    /* loop through headers stopping at first blank line */
    while ((len = next_header(&data, &data_len)) != 0)
        if (len > header_len && strncasecmp(header, data, header_len) == 0) {
            /* Eat leading whitespace */
            while (header_len < len && isblank((unsigned char)data[header_len]))
                header_len++;

            *value = malloc(len - header_len + 1);
            if (*value == NULL)
                return -4;

            strncpy(*value, data + header_len, len - header_len);
            (*value)[len - header_len] = '\0';

            return len - header_len;
        }

    /* If there is no data left after reading all the headers then we do not
     * have a complete HTTP request, there must be a blank line */
    if (data_len == 0)
        return -1;

    return -2;
}

static int
next_header(const char **data, int *len)
{
    int header_len;

    /* perhaps we can optimize this to reuse the value of header_len, rather
     * than scanning twice.
     * Walk our data stream until the end of the header */
    while (*len > 2 && (*data)[0] != '\r' && (*data)[1] != '\n') {
        (*len)--;
        (*data)++;
    }

    /* advanced past the <CR><LF> pair */
    *data += 2;
    *len  -= 2;

    /* Find the length of the next header */
    header_len = 0;
    while (*len > header_len + 1
           && (*data)[header_len] != '\r'
           && (*data)[header_len + 1] != '\n')
        header_len++;

    return header_len;
}

void disable_http(obfs_t *obfs)
{
    obfs->obfs_stage = -1;
    obfs->deobfs_stage = -1;
}

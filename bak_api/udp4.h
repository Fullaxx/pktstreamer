/*
	Copyright (C) 2022 Brett Kuskie <fullaxx@gmail.com>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; version 2 of the License.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef __UDP4_H__
#define __UDP4_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SA   struct sockaddr
#define SAI  struct sockaddr_in

typedef struct {
	int socket;
	SAI addr;
} u4clnt_t;

ssize_t as_udp4_client_write(u4clnt_t *c, void *data, int data_len);
int as_udp4_connect(u4clnt_t *c, char *address, unsigned short port);

#ifdef __cplusplus
}
#endif

#endif

/*
	Copyright (C) 2023 Brett Kuskie <fullaxx@gmail.com>

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

#ifndef __ASYNC_ZMQ_PUBLISHER_H__
#define __ASYNC_ZMQ_PUBLISHER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	void *zContext;
	void *zSocket;
	int connected;
} zmq_pub_t;

int as_zmq_pub_send(zmq_pub_t *, void *, size_t, int);
zmq_pub_t* as_zmq_pub_create(char *, int, int);
void as_zmq_pub_destroy(zmq_pub_t *);

#ifdef __cplusplus
}
#endif

#endif

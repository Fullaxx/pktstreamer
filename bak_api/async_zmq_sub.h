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

#ifndef __ASYNC_ZMQ_SUBSCRIBER_H__
#define __ASYNC_ZMQ_SUBSCRIBER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "async_zmq_mpm.h"

#define AS_ZMQ_SUB_THREADNAME ("zmq_sub_thread")

typedef struct {
	void *zContext;
	void *zSocket;
	int connected;
	int do_close;
	int closed;
} zmq_sub_t;

#define ZS_READ_CALLBACK(CB) void (CB)(zmq_sub_t *, zmq_mf_t **, int, void *);

typedef struct {
	zmq_sub_t *q;
	ZS_READ_CALLBACK(*cb);
	void *user_data;
} ZSParam_t;

zmq_sub_t* as_zmq_sub_create(char *zSockAddr, char *filter, void *func, int recv_hwm, void *user);
void as_zmq_sub_destroy(zmq_sub_t *sub);

#ifdef __cplusplus
}
#endif

#endif

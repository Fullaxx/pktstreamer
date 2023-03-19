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

#ifdef DEBUG
#include <stdio.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <zmq.h>

#include "async_zmq_pub.h"

int as_zmq_pub_send(zmq_pub_t *pub, void *msg, size_t len, int more)
{
	int r;
	zmq_msg_t message;

	if(!pub->connected) { return -1; }

	r = zmq_msg_init_size(&message, len);
	if(r != 0) {
#ifdef DEBUG
		if(errno == ENOMEM) {
			fprintf(stderr, "zmq_msg_init_size() returned ENOMEM!\n");
		} else {
			fprintf(stderr, "zmq_msg_init_size() returned an error!\n");
		}
#endif
		return -2;
	}

	memcpy(zmq_msg_data(&message), msg, len);
	zmq_msg_send(&message, pub->zSocket, (more ? ZMQ_SNDMORE : 0));

	return 0;
}

zmq_pub_t* as_zmq_pub_create(char *zSockAddr, int send_hwm, int do_connect)
{
	int r;
	zmq_pub_t *pub = calloc(1, sizeof(zmq_pub_t));
	if(!pub) { return NULL; }

	pub->zContext = zmq_ctx_new();
	pub->zSocket = zmq_socket(pub->zContext, ZMQ_PUB);

	r = zmq_setsockopt(pub->zSocket, ZMQ_SNDHWM, &send_hwm, sizeof(send_hwm));
	if(r != 0) {
		free(pub);
		return NULL;
	}

	if(do_connect) { r = zmq_connect(pub->zSocket, zSockAddr); }
	else		{ r = zmq_bind(pub->zSocket, zSockAddr); }
	if(r != 0) {
		free(pub);
		return NULL;
	}

	pub->connected = 1;

	return pub;
}

void as_zmq_pub_destroy(zmq_pub_t *pub)
{
	if(!pub) { return; }

	if(pub->connected) {
		zmq_close(pub->zSocket);
		zmq_ctx_term(pub->zContext);
		pub->connected = 0;
	}

	free(pub);
}

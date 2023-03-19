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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <zmq.h>

#include "async_zmq_sub.h"

static void* zmq_sub_thread(void *param)
{
	int mpi, msgsize, more, i;
	size_t smore;
	zmq_msg_t zMessage;
	zmq_mf_t **mpa;
	zmq_mf_t *thispart;
	ZSParam_t *p = (ZSParam_t *)param;
	zmq_sub_t *sub = p->q;

	smore = sizeof(more);
	prctl(PR_SET_NAME, AS_ZMQ_SUB_THREADNAME, 0, 0, 0);

	// we repeat until the connection has been closed
	zmq_msg_init(&zMessage);
	sub->connected = 1;
	while(!sub->do_close) {
		msgsize = zmq_msg_recv(&zMessage, sub->zSocket, ZMQ_DONTWAIT);
		if(msgsize == -1) {
			if(errno == EAGAIN) { usleep(100); continue; }
			else { break; }
		}

		mpa = calloc(AS_ZMQ_MAX_PARTS, sizeof(zmq_mf_t *));
		mpi = 0;
		do {
			if(mpi > 0) { msgsize = zmq_msg_recv(&zMessage, sub->zSocket, 0); }
			thispart = mpa[mpi++] = calloc(1, sizeof(zmq_mf_t));
			thispart->size = msgsize;
			thispart->buf = calloc(1, msgsize);
			memcpy(thispart->buf, zmq_msg_data(&zMessage), msgsize);
			zmq_msg_close(&zMessage); zmq_msg_init(&zMessage);
			zmq_getsockopt(sub->zSocket, ZMQ_RCVMORE, &more, &smore);
		} while(more && (mpi<AS_ZMQ_MAX_PARTS));

		p->cb(sub, mpa, mpi, p->user_data);

		for(i=0; i<AS_ZMQ_MAX_PARTS; i++) {
			if(mpa[i]) { free(mpa[i]->buf); free(mpa[i]); }
		}
		free(mpa);
	}

	zmq_msg_close(&zMessage);
	p->cb(sub, NULL, 0, p->user_data);
	sub->closed = 1;
	free(p);
/*#ifdef DEBUG
	fprintf(stderr, "%s() exiting\n", __func__);
#endif*/
	return NULL;
}

static int as_zmq_sub_attach(zmq_sub_t *sub, void *func, void *user)
{
	pthread_t thr_id;
	ZSParam_t *p = (ZSParam_t *)calloc(1, sizeof(ZSParam_t));

	if(!p) {
#ifdef DEBUG
		fprintf(stderr, "calloc(1, %lu) failed!\n", sizeof(ZSParam_t));
#endif
		return -1;
	}

	p->q = sub;
	p->cb = func;
	p->user_data = user;

	if( pthread_create(&thr_id, NULL, &zmq_sub_thread, p) ) { free(p); return -2; }
	if( pthread_detach(thr_id) ) { free(p); return -3; }

	return 0;
}

static void handle_error(zmq_sub_t *sub)
{
	zmq_close(sub->zSocket);
	zmq_ctx_term(sub->zContext);
	free(sub);
}

zmq_sub_t* as_zmq_sub_create(char *zSockAddr, char *filter, void *func, int recv_hwm, void *user)
{
	int r;
	zmq_sub_t *sub = calloc(1, sizeof(zmq_sub_t));
	if(!sub) { return NULL; }

	sub->zContext = zmq_ctx_new();
	sub->zSocket = zmq_socket(sub->zContext, ZMQ_SUB);

	r = zmq_setsockopt(sub->zSocket, ZMQ_RCVHWM, &recv_hwm, sizeof(recv_hwm));
	if(r != 0) { handle_error(sub); return NULL; }

	r = zmq_connect(sub->zSocket, zSockAddr);
	if(r != 0) { handle_error(sub); return NULL; }

	r = zmq_setsockopt(sub->zSocket, ZMQ_SUBSCRIBE, filter, strlen(filter));
	if(r != 0) { handle_error(sub); return NULL; }

	r = as_zmq_sub_attach(sub, func, user);
	if(r != 0) { handle_error(sub); return NULL; }

	return sub;
}

void as_zmq_sub_destroy(zmq_sub_t *sub)
{
	if(!sub) { return; }

	if(sub->connected) {
		sub->do_close = 1;
		while(!sub->closed) { usleep(1000); }
		zmq_close(sub->zSocket);
		zmq_ctx_term(sub->zContext);
	}

	free(sub);
}

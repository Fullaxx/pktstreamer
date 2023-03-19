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

#ifndef __ASYNC_ZMQ_MPM_H__
#define __ASYNC_ZMQ_MPM_H__

#ifdef __cplusplus
extern "C" {
#endif

#define AS_ZMQ_MAX_PARTS (256)

typedef struct {
	void *buf;
	unsigned long size;
} zmq_mf_t;

#ifdef __cplusplus
}
#endif

#endif /* __ASYNC_ZMQ_MPM_H__ */

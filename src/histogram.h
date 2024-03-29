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

#ifndef __HISTOGRAM_H__
#define __HISTOGRAM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "async_zmq_sub.h"

void pkt_cb(zmq_sub_t *, zmq_mf_t **, int, void *);
void print_stats(void);
void init_hist(void);
void fini_hist(int, int);

#ifdef __cplusplus
}
#endif

#endif /* __HISTOGRAM_H__ */

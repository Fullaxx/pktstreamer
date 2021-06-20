/*
	Copyright (C) 2021 Brett Kuskie <fullaxx@gmail.com>

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

#ifndef __ASYNC_PCAPTURE_H__
#define __ASYNC_PCAPTURE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <net/if.h>		// IFNAMSIZ
#include <pcap.h>		// pcap_*()

#define AS_PKT_CALLBACK(CB) void (CB)(u_char *, const struct pcap_pkthdr *, const u_char *);

typedef struct async_capture_thread {
	pcap_t *h;
	AS_PKT_CALLBACK(*cb);
	void *user_data;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	char dev[IFNAMSIZ+1];
	int linktype;
	unsigned int max_pkts;
	int do_close;			//trigger to stop the capturing thread
	int closed;				//trigger to let the main program know the thread has exited
	int dispatch_error;		//this will be a trigger to tell the main that our thread had a problem and had to exit
} acap_t;

int as_pcapture_launch(acap_t *, char *, char *, int, int, unsigned int, void *, void *);
void as_pcapture_stop(acap_t *);
void as_pcapture_wait4close(acap_t *);

#ifdef __cplusplus
}
#endif

#endif

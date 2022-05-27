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
	char dev[IFNAMSIZ+1];
	char pcap_errbuf[PCAP_ERRBUF_SIZE];

	AS_PKT_CALLBACK(*cb);	// Callback that will process packets
	void *user_data;

	int max_pkts;		// Pass this to pcap_dispatch

	int linktype;		// Get the linktype from the pcap handle
	int tsprecision;	// Get the timestamp precision from the pcap handle
	unsigned int magic;	// Store the associated magic number

	int do_close;		//trigger to stop the capturing thread
	int closed;			//trigger to let the main program know the thread has exited
	int dispatch_error;	//this will be a trigger to tell main that pcap_dispatch had a problem and had to exit
} acap_t;

typedef struct {
	int snaplen;
	int promisc;
	int timeout;
	int max_pkts;

	int prefer_adapter_ts;
	int prefer_nanosec_ts;

	int direction;
} acap_opt_t;

int as_pcapture_launch(acap_t *, acap_opt_t *, char *, char *, void *, void *);
void as_pcapture_stop(acap_t *);

#ifdef __cplusplus
}
#endif

#endif

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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>	// pthread_*()
#include <sys/prctl.h>	// prctl()

#ifdef YIELDFORSPEED
#include <sched.h>
#endif

#include "async_pcapture.h"

static void inline idlehands(void)
{
#ifdef YIELDFORSPEED
	sched_yield();
#else
	usleep(25);
#endif
}

void *pcap_thread_watch(void *param)
{
	int z = 0;
	acap_t *ac = (acap_t *)param;

	prctl(PR_SET_NAME, "async_pcapture", 0, 0, 0);

#ifdef DEBUG
	printf("%s capture started: %lu\n", ac->dev, pthread_self());
#endif

	while(!ac->do_close) {
		z = pcap_dispatch(ac->h, ac->max_pkts, ac->cb, (u_char *)ac);
		if(z < 0) {
			fprintf(stderr, "pcap_dispatch(%s) error: %s", ac->dev, pcap_geterr(ac->h));
			ac->dispatch_error = 1;
			ac->do_close = 1;
		} else if(z == 0) {
			idlehands();
		} //else { printf("pkts processed: %d\n", z); }
	}

#ifdef DEBUG
	printf("%s capture stopped: %lu\n", ac->dev, pthread_self());
#endif

	pcap_close(ac->h);
	ac->closed = 1;

	return NULL;
}

int as_pcapture_launch(acap_t *ac, char *dev, char *filter, int snaplen, int promisc, int max_pkts, void *cb, void *user_data)
{
	int err;
	pthread_t thr_id;
	struct bpf_program fp;

	if((!ac) || (!cb)) { return -1; }

	memset(ac, 0, sizeof(acap_t));
	snprintf(ac->dev, sizeof(ac->dev), "%s", (dev ? dev : "ANY"));
	ac->cb = cb;
	ac->user_data = user_data;
	ac->max_pkts = ((max_pkts > 0) ? max_pkts : 100);
	snaplen = ((snaplen > 0) ? snaplen : 262144);

	ac->h = pcap_create(dev, ac->pcap_errbuf);
	if(ac->h == NULL) {
		fprintf(stderr, "pcap_open_live(%s) failed: %s\n", ac->dev, ac->pcap_errbuf);
		return -2;
	}

	err = pcap_set_snaplen(ac->h, snaplen);
	if(err) {
		fprintf(stderr, "pcap_set_snaplen(%s) failed: %d\n", ac->dev, err);
		return -3;
	}

	err = pcap_set_promisc(ac->h, promisc);
	if(err) {
		fprintf(stderr, "pcap_set_promisc(%s) failed: %d\n", ac->dev, err);
		return -4;
	}

	err = pcap_set_timeout(ac->h, 10);
	if(err) {
		fprintf(stderr, "pcap_set_timeout(%s) failed: %d\n", ac->dev, err);
		return -5;
	}

	err = pcap_activate(ac->h);
	if(err) {
		fprintf(stderr, "pcap_activate(%s) failed: %d\n", ac->dev, err);
		return -6;
	}

	ac->linktype = pcap_datalink(ac->h);

	if(filter) {
		if(pcap_compile(ac->h, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "pcap_compile(%s) failed: %s\n", filter, ac->pcap_errbuf);
			return -7;
		}

		if(pcap_setfilter(ac->h, &fp) == -1) {
			fprintf(stderr, "pcap_setfilter(%s) failed: %s\n", filter, ac->pcap_errbuf);
			return -8;
		}
	}

	if(pcap_setnonblock(ac->h, 1, ac->pcap_errbuf) == -1) {
		fprintf(stderr, "pcap_setnonblock(%s) failed: %s\n", ac->dev, ac->pcap_errbuf);
		return -9;
	}

	if(pthread_create(&thr_id, NULL, &pcap_thread_watch, ac)) {
		fprintf(stderr, "pthread_create() failed!\n");
		return -10;
	}

	if(pthread_detach(thr_id)) {
		fprintf(stderr, "pthread_detach() failed!\n");
		return -11;
	}

	return 0;
}

void as_pcapture_stop(acap_t *ac)
{
	if(ac->h) {
		ac->do_close = 1;
		while(!ac->closed) { usleep(1000); }
		ac->h = NULL;
	}
}

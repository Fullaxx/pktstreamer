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

static void *pcap_thread_watch(void *param)
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
			fprintf(stderr, "pcap_dispatch(%s) error: %s\n", ac->dev, pcap_geterr(ac->h));
			ac->dispatch_error = 1;
			ac->do_close = 1;
		} else if(z == 0) { idlehands(); }
		//else { printf("pkts processed: %d\n", z); }
	}

#ifdef DEBUG
	printf("%s capture stopped: %lu\n", ac->dev, pthread_self());
#endif

	pcap_close(ac->h);
	ac->closed = 1;

	return NULL;
}

int as_pcapture_launch(acap_t *ac, acap_opt_t *opt, char *dev, char *filter, void *cb, void *user_data)
{
	int err;
	char *err_str = NULL;
	pthread_t thr_id;
	struct bpf_program fp;
	int snaplen = 0;
	int promisc = 1;
	int timeout = 0;
	int max_pkts = 0;
	int prefer_adapter_ts = 0;
	int prefer_nanosec_ts = 0;

	if((!ac) || (!cb)) { return -1; }

	if(opt) {
		snaplen = opt->snaplen;
		promisc = opt->promisc;
		timeout = opt->timeout;
		max_pkts = opt->max_pkts;
		prefer_adapter_ts = opt->prefer_adapter_ts;
		prefer_nanosec_ts = opt->prefer_nanosec_ts;
	}

	memset(ac, 0, sizeof(acap_t));
	snprintf(ac->dev, sizeof(ac->dev), "%s", (dev ? dev : "ANY"));
	ac->cb = cb;
	ac->user_data = user_data;
	ac->max_pkts = ((max_pkts > 0) ? max_pkts : 100);
	snaplen = ((snaplen > 0) ? snaplen : 262144);
	timeout = ((timeout > 0) ? timeout : 10);

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

	err = pcap_set_timeout(ac->h, timeout);
	if(err) {
		fprintf(stderr, "pcap_set_timeout(%s) failed: %d\n", ac->dev, err);
		return -5;
	}

	if(prefer_adapter_ts) {
		// Attempt to use timestamps from the adapter
		err = pcap_set_tstamp_type(ac->h, PCAP_TSTAMP_ADAPTER);
		if(err) {
			if(err == PCAP_WARNING_TSTAMP_TYPE_NOTSUP) {
				fprintf(stderr, "pcap_set_tstamp_type(%s, PCAP_TSTAMP_ADAPTER) failed: not supported\n", ac->dev);
			} else {
				fprintf(stderr, "pcap_set_tstamp_type(%s, PCAP_TSTAMP_ADAPTER) failed: %d\n", ac->dev, err);
			}
		}
	}

	if(prefer_nanosec_ts) {
		// Attempt to use timestamps with nanoseconds
		err = pcap_set_tstamp_precision(ac->h, PCAP_TSTAMP_PRECISION_NANO);
		if(err) {
			if(err == PCAP_ERROR_TSTAMP_PRECISION_NOTSUP) {
				fprintf(stderr, "pcap_set_tstamp_precision(%s, PCAP_TSTAMP_PRECISION_NANO) failed: not supported\n", ac->dev);
			} else {
				fprintf(stderr, "pcap_set_tstamp_precision(%s, PCAP_TSTAMP_PRECISION_NANO) failed: %d\n", ac->dev, err);
			}
		}
	}

	err = pcap_activate(ac->h);
	if(err) {
		switch(err) {
			case PCAP_ERROR_ACTIVATED: err_str = "handle is active"; break;
			case PCAP_ERROR_NO_SUCH_DEVICE: err_str = "no such device"; break;
			case PCAP_ERROR_RFMON_NOTSUP: err_str = "rfmon not supported"; break;
			case PCAP_ERROR_NOT_RFMON: err_str = "not in monitor mode"; break;
			case PCAP_ERROR_PERM_DENIED: err_str = "permission denied"; break;
			case PCAP_ERROR_IFACE_NOT_UP: err_str = "interface not up"; break;
			case PCAP_ERROR_PROMISC_PERM_DENIED: err_str = "promisc permission denied"; break;
		}
		if(err_str) {
			fprintf(stderr, "pcap_activate(%s) failed: %s\n", ac->dev, err_str);
		} else {
			fprintf(stderr, "pcap_activate(%s) failed: %d\n", ac->dev, err);
		}
		return -6;
	}

	ac->linktype = pcap_datalink(ac->h);
	ac->tsprecision = pcap_get_tstamp_precision(ac->h);
	if(ac->tsprecision == PCAP_TSTAMP_PRECISION_MICRO) {
		ac->magic = 0xA1B2C3D4;
	} else if(ac->tsprecision == PCAP_TSTAMP_PRECISION_NANO) {
		ac->magic = 0xA1B23C4D;
	} else {
		fprintf(stderr, "Could not determine magic value!\n");
		return -7;
	}

	if(filter) {
		if(pcap_compile(ac->h, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "pcap_compile(%s) failed: %s\n", filter, ac->pcap_errbuf);
			return -8;
		}

		if(pcap_setfilter(ac->h, &fp) == -1) {
			fprintf(stderr, "pcap_setfilter(%s) failed: %s\n", filter, ac->pcap_errbuf);
			return -9;
		}
	}

	if(pcap_setnonblock(ac->h, 1, ac->pcap_errbuf) == -1) {
		fprintf(stderr, "pcap_setnonblock(%s) failed: %s\n", ac->dev, ac->pcap_errbuf);
		return -10;
	}

	if(pthread_create(&thr_id, NULL, &pcap_thread_watch, ac)) {
		fprintf(stderr, "pthread_create() failed!\n");
		return -11;
	}

	if(pthread_detach(thr_id)) {
		fprintf(stderr, "pthread_detach() failed!\n");
		return -12;
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

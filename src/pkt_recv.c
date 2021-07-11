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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "getopts.h"
#include "async_zmq_sub.h"

// Prototypes
static void parse_args(int argc, char *argv[]);
void pkt_cb(zmq_sub_t *s, zmq_mf_t **mpa, int msgcnt, void *user_data);
int init_output(char *filename);
void fini_output(void);

// Globals
unsigned int g_shutdown = 0;
char *g_zmqsockaddr = NULL;
char *g_filename = NULL;
unsigned int g_stats = 0;
unsigned int g_us_ts = 0;
unsigned int g_ns_ts = 0;

// Status Variables
unsigned long g_zmqerr_count = 0;
unsigned long g_zmqpkt_count = 0;
unsigned long g_pcap_count = 0;
unsigned long g_pcap_size = 0;
unsigned long g_bw_count = 0;
unsigned long g_bw_size = 0;

// Stop Conditionals
time_t g_stoptime = 0;
unsigned long g_maxpkts = 0;
unsigned long g_maxsize = 0;

void count_packet(unsigned int pkts, unsigned int bytes)
{
	g_pcap_count += pkts;
	g_bw_count += pkts;
	g_pcap_size += bytes;
	g_bw_size += bytes;
}

static void alarm_handler(int signum)
{
	char *bw_units;
	unsigned long bw;

	bw = g_bw_size;
	g_bw_size = 0;

	if(bw >= 1000000000000) {
		bw_units = "TB/s";
		bw = bw/1000000000000;
	} else if(bw >= 1000000000) {
		bw_units = "GB/s";
		bw = bw/1000000000;
	} else if(bw >= 1000000) {
		bw_units = "MB/s";
		bw = bw/1000000;
	} else if(bw >= 1000) {
		bw_units = "KB/s";
		bw = bw/1000;
	} else {
		bw_units = "B/s";
	}

	fprintf(stderr, "%lu/%lu", g_zmqerr_count, g_zmqpkt_count);
	g_zmqpkt_count = g_zmqerr_count = 0;
	fprintf(stderr, " [%lu%s]", bw, bw_units);
	fprintf(stderr, "\n");
	fflush(stderr);

	(void) alarm(1);
}

static void sig_handler(int signum)
{
	switch(signum) {
		/*case SIGPIPE:
			fprintf(stderr, "SIGPIPE recvd!\n");
			g_shutdown = 1;*/
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
		case SIGQUIT:
			g_shutdown = 1;
			break;
	}
}

static void check_for_stop_condition(void)
{
	if(g_stoptime) {
		if(time(NULL) >= g_stoptime) { g_shutdown = 1; }
	}

	if(g_maxpkts) {
		if(g_pcap_count >= g_maxpkts) { g_shutdown = 1; }
	}

	if(g_maxsize) {
		if(g_pcap_size >= g_maxsize*1e6) { g_shutdown = 1; }
	}
}

int main(int argc, char *argv[])
{
	int z;
	char *filter = "";
	zmq_sub_t *sub;

	parse_args(argc, argv);

	// Initialize output stream
	z = init_output(g_filename);
	if(z) { exit(EXIT_FAILURE); }

	// Initialize ZMQ SUB
	sub = as_zmq_sub_create(g_zmqsockaddr, filter, pkt_cb, 0, NULL);
	if(!sub) {
		fprintf(stderr, "as_zmq_sub_create(%s) failed!\n", g_zmqsockaddr);
		exit(EXIT_FAILURE);
	}

	signal(SIGHUP,  sig_handler);
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGQUIT, sig_handler);
	if(g_stats) {
		signal(SIGALRM, alarm_handler);
		(void) alarm(1);
	}

	// wait for the slow release of death
	while(!g_shutdown) {
		// We will check roughly 1000 times per second
		check_for_stop_condition();
		usleep(1000);	// NOT an exact timer
	}

	// Shutdown the ZMQ SUB bus
	as_zmq_sub_destroy(sub);

	// Close the PCAP file if opened
	fini_output();

	if(g_zmqsockaddr)	{ free(g_zmqsockaddr); }
	if(g_filename)		{ free(g_filename); }
	return 0;
}

struct options opts[] = {
	{ 1, "ZMQ",		"Set the ZMQ bus to listen on",		"Z",  1 },
	{ 2, "PCAP",	"Write data to pcap file",			"P",  1 },
	{ 3, "stats",	"Display stats on stderr", 			NULL, 0 },
	{ 4, "us",		"Force Microsecond Timestamps",		NULL, 0 },
	{ 5, "ns",		"Force Nanosecond Timestamps",		NULL, 0 },
	{ 6, "maxtime",	"Stop after X seconds",				NULL, 1 },
	{ 7, "maxpkts",	"Stop after X pkts",				NULL, 1 },
	{ 8, "maxsize",	"Stop after X MB",					NULL, 1 },
	{ 0, NULL,		NULL,								NULL, 0 }
};

static void parse_args(int argc, char *argv[])
{
	int c;
	char *args;

	while ((c = getopts(argc, argv, opts, &args)) != 0) {
		switch(c) {
			case -2:
				// Special Case: Recognize options that we didn't set above.
				fprintf(stderr, "Unknown Getopts Option: %s\n", args);
				exit(EXIT_FAILURE);
				break;
			case -1:
				// Special Case: getopts() can't allocate memory.
				fprintf(stderr, "Unable to allocate memory for getopts().\n");
				exit(EXIT_FAILURE);
				break;
			case 1:
				g_zmqsockaddr = strdup(args);
				break;
			case 2:
				g_filename = strdup(args);
				break;
			case 3:
				g_stats = 1;
				break;
			case 4:
				g_us_ts = 1;
				break;
			case 5:
				g_ns_ts = 1;
				break;
			case 6:
				g_stoptime = time(NULL) + strtoul(args, NULL, 10);
				break;
			case 7:
				g_maxpkts = strtoul(args, NULL, 10);
				break;
			case 8:
				g_maxsize = strtoul(args, NULL, 10);
				break;
			default:
				fprintf(stderr, "Unknown command line argument %i\n", c);
		}
		free(args);
	}

	if(!g_zmqsockaddr) {
		fprintf(stderr, "I need a ZMQ bus to listen to! (Fix with -Z)\n");
		exit(EXIT_FAILURE);
	}

	if(g_us_ts && g_ns_ts) {
		fprintf(stderr, "Cannot force us and ns timestamps!\n");
		exit(EXIT_FAILURE);
	}
}

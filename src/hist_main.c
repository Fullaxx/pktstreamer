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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "getopts.h"
#include "async_zmq_sub.h"
#include "histogram.h"

// Prototypes
static void parse_args(int argc, char *argv[]);

// Globals
unsigned int g_shutdown = 0;
char *g_zmqsockaddr = NULL;
int g_all = 0;
int g_csv = 0;
int g_verbose = 0;
int g_stats = 0;

static void alarm_handler(int signum)
{
	print_stats();
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

int main(int argc, char *argv[])
{
	int z;
	char *filter = "";
	zmq_sub_t *sub;

	parse_args(argc, argv);

	// Initialize Histogram
	init_hist();

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

	z=0; // wait for the slow release of death
	while(!g_shutdown) {
		if(z>999) { z=0; }
		usleep(1000);
		z++;
	}

	// Shutdown the ZMQ SUB bus
	as_zmq_sub_destroy(sub);

	// Finalize Histogram
	fini_hist(g_all, g_csv);

	if(g_zmqsockaddr)	{ free(g_zmqsockaddr); }
	return 0;
}

struct options opts[] = {
	{ 1, "ZMQ",		"Set the ZMQ bus to listen on",		"Z",  1 },
	{ 2, "all",		"Display entire histogram", 		NULL, 0 },
	{ 3, "csv",		"Format histogram as csv", 			NULL, 0 },
	{ 8, "verbose",	"Be more verbose", 					"v",  0 },
	{ 9, "stats",	"Display stats on stderr", 			NULL, 0 },
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
				g_all = 1;
				break;
			case 3:
				g_csv = 1;
				break;
			case 8:
				g_verbose = 1;
				break;
			case 9:
				g_stats = 1;
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
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

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
unsigned int g_ns_ts = 0;

unsigned long g_zmqerr_count = 0;
unsigned long g_zmqpkt_count = 0;

static void alarm_handler(int signum)
{
	fprintf(stderr, "%lu/%lu\n", g_zmqerr_count, g_zmqpkt_count);
	g_zmqpkt_count = g_zmqerr_count = 0;
	(void) alarm(1);

	fflush(stderr);
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

	z=0; // wait for the slow release of death
	while(!g_shutdown) {
		if(z>999) { z=0; }
		usleep(1000);
		z++;
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
	{ 4, "ns",		"Nanosecond Precision Timestamps",	NULL, 0 },
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
				g_ns_ts = 1;
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

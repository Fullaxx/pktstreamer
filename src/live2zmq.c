#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "getopts.h"
#include "async_zmq_pub.h"
#include "async_pcapture.h"

// Prototypes
static void parse_args(int argc, char **argv);

// Globals
int g_shutdown = 0;

char *g_dev = NULL;
char *g_zmqsockaddr = NULL;
char *g_filter = NULL;
int g_verbosity = 0;

zmq_pub_t *g_pktpub = NULL;
unsigned long g_pkt_id = 0;
unsigned int g_magic = 0xA1B2C3D4;

static void sig_handler(int signum)
{
	switch(signum) {
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
		case SIGQUIT:
			g_shutdown = 1;
			break;
	}
}


/*
	as_zmq_pub_send(g_pktpub, ac->dev, strlen(ac->dev)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%d/%d/%u/%u", ac->linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_usec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	as_zmq_pub_send(g_pktpub, buf, len, 0);
*/
static void publish_packet(acap_t *ac, unsigned char *buf, int len, struct timespec *ts)
{
	char zbuf[256];

	// Drop the device on the ZMQ stream
	as_zmq_pub_send(g_pktpub, ac->dev, strlen(ac->dev)+1, 1);

	// Drop the File Header on the ZMQ stream
	snprintf(zbuf, sizeof(zbuf), "%u/%d/%d/%u/%u", g_magic, ac->linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	// Drop the Packet Timestamp on the ZMQ stream
	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_nsec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	// Drop the Packet Data on the ZMQ stream
	as_zmq_pub_send(g_pktpub, buf, len, 0);
}

static void recv_packet(acap_t *ac, const struct pcap_pkthdr *pcap_hdr, u_char *raw_pkt)
{
	struct timespec myts;

	// Convert fractional seconds to nanoseconds
	myts.tv_sec  = pcap_hdr->ts.tv_sec;
	if(g_magic == 0xA1B2C3D4) {
		myts.tv_nsec = pcap_hdr->ts.tv_usec*1000;
	}

	g_pkt_id++;
	publish_packet(ac, raw_pkt, pcap_hdr->caplen, &myts);

	if(g_verbosity == 1) {
		printf(".");
		fflush(stdout);
	}

	if(g_verbosity == 2) {
		printf("%ld.%09ld\n", myts.tv_sec, myts.tv_nsec);
		fflush(stdout);
	}
}

int main(int argc, char *argv[])
{
	int p = 1, snaplen = 0;
	unsigned int max_pkts = 0;
	int retval;
	acap_t ac;

	memset(&ac, 0, sizeof(ac));
	parse_args(argc, argv);

	g_pktpub = as_zmq_pub_create(g_zmqsockaddr, 0, 0);
	if(!g_pktpub) {
		fprintf(stderr, "as_zmq_pub_create(%s) failed!\n", g_zmqsockaddr);
		return 1;
	}

	printf("Opening %s ...\n", (g_dev ? g_dev : "ANY"));
	retval = as_pcapture_launch(&ac, g_dev, g_filter, snaplen, p, max_pkts, &recv_packet, NULL);
	if(retval < 0) {
		as_zmq_pub_destroy(g_pktpub);
		fprintf(stderr, "as_pcapture_launch(%s) failed!!\n", g_dev);
		return 2;
	}

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGHUP,  sig_handler);
	//signal(SIGALRM, alarm_handler);
	//(void) alarm(30);

	while(!g_shutdown) { usleep(100); }

	if(g_verbosity == 1) { printf("\n"); }
	as_pcapture_stop(&ac);

	// Shutdown the ZMQ PUB bus
	if(g_pktpub) {
		as_zmq_pub_destroy(g_pktpub);
		g_pktpub = NULL;
	}

	if(g_dev)			{ free(g_dev); }
	if(g_zmqsockaddr)	{ free(g_zmqsockaddr); }
	if(g_filter)		{ free(g_filter); }

	if(g_verbosity > 0) {
		printf("\nPackets Sent: %lu\n", g_pkt_id);
	}

	return 0;
}

struct options opts[] = 
{
	{ 1, "dev",			"Network device to sniff",		"i",  1 },
	{ 2, "ZMQ",			"Set the ZMQ PUB",				"Z",  1 },
	{ 3, "filter",		"Apply this filter",			"f",  1 },
	{ 4, "verbosity",	"Set verbosity (-v 1 / -v 2)",	"v",  1 },
	{ 0, NULL,			NULL,							NULL, 0 }
};

static void parse_args(int argc, char **argv)
{
	char *args;
	int c;

	while ((c = getopts(argc, argv, opts, &args)) != 0) {
		switch(c) {
			case -2:
				// Special Case: Recognize options that we didn't set above.
				fprintf(stderr, "Unknown Getopts Option: %s\n", args);
				break;
			case -1:
				// Special Case: getopts() can't allocate memory.
				fprintf(stderr, "Unable to allocate memory for getopts()\n");
				exit(EXIT_FAILURE);
				break;
			case 1:
				g_dev = strdup(args);
				break;
			case 2:
				g_zmqsockaddr = strdup(args);
				break;
			case 3:
				g_filter = strdup(args);
				break;
			case 4:
				g_verbosity = atoi(args);
				break;
			default:
				fprintf(stderr, "Unexpected getopts Error! (%d)\n", c);
				break;
		}

		//This free() is required since getopts() automagically allocates space for "args" everytime it's called.
		free(args);
	}

	if(!g_zmqsockaddr) {
		fprintf(stderr, "I need a ZMQ bus to drop packets onto! (Fix with -Z)\n");
		exit(EXIT_FAILURE);
	}

	if(!g_dev && !g_filter) {
		fprintf(stderr, "If you wish to capture on ALL interfaces, you MUST implement a proper filter! (Fix with -f)\n");
		exit(EXIT_FAILURE);
	}
}

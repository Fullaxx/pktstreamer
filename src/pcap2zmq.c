#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
//#include <signal.h>
#include <pcap.h>

#include "getopts.h"
#include "async_zmq_pub.h"

// Prototypes
static void parse_args(int argc, char **argv);

// Globals
int g_shutdown = 0;

char *g_pcap = NULL;
char *g_zmqsockaddr = NULL;
char *g_filter = NULL;
int g_verbosity = 0;

zmq_pub_t *g_pktpub = NULL;
unsigned long g_pkt_id = 0;
unsigned int g_magic = 0xA1B2C3D4;
int g_linktype = 0;
int g_pktdelay = 1;

struct timespec g_lastts = { 0, 0 };

/*
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
*/

/*
	as_zmq_pub_send(g_pktpub, ac->dev, strlen(ac->dev)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%d/%d/%u/%u", ac->linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_usec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	as_zmq_pub_send(g_pktpub, buf, len, 0);
*/
static void publish_packet(unsigned char *buf, int len, struct timespec *ts)
{
	char zbuf[256];

	// Drop the device on the ZMQ stream
	as_zmq_pub_send(g_pktpub, g_pcap, strlen(g_pcap)+1, 1);

	// Drop the File Header on the ZMQ stream
	snprintf(zbuf, sizeof(zbuf), "%u/%d/%d/%u/%u", g_magic, g_linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	// Drop the Packet Timestamp on the ZMQ stream
	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_nsec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	// Drop the Packet Data on the ZMQ stream
	as_zmq_pub_send(g_pktpub, buf, len, 0);
}

static void process_packet(u_char *user, const struct pcap_pkthdr *pcap_hdr, const u_char *raw_pkt)
{
	long ns_diff;
	struct timespec myts;

	// Convert fractional seconds to nanoseconds for ZMQ
	myts.tv_sec  = pcap_hdr->ts.tv_sec;
	myts.tv_nsec = pcap_hdr->ts.tv_usec;
	if(g_magic == 0xA1B2C3D4) { myts.tv_nsec *= 1000; }

	// Attempt to replay the PCAP with proper packet delay
	if((g_lastts.tv_sec > 0) && (g_lastts.tv_nsec > 0)) {
		ns_diff = (myts.tv_sec - g_lastts.tv_sec) * 1e9;
		ns_diff += (myts.tv_nsec - g_lastts.tv_nsec);
		//printf("diff: %lu\n", ns_diff);
		if(g_pktdelay) { usleep(ns_diff/1000); }
	}

	g_pkt_id++;
	publish_packet((u_char *)raw_pkt, pcap_hdr->caplen, &myts);

	if(g_verbosity == 1) {
		printf(".");
		fflush(stdout);
	}

	if(g_verbosity == 2) {
		printf("%ld.%09ld\n", myts.tv_sec, myts.tv_nsec);
		fflush(stdout);
	}

	memcpy(&g_lastts, &myts, sizeof(struct timespec));
}

int main(int argc, char *argv[])
{
	int z;
	pcap_t *h;
	char errbuf[PCAP_ERRBUF_SIZE];

	parse_args(argc, argv);

	g_pktpub = as_zmq_pub_create(g_zmqsockaddr, 0, 0);
	if(!g_pktpub) {
		fprintf(stderr, "as_zmq_pub_create(%s) failed!\n", g_zmqsockaddr);
		return 1;
	}

	h = pcap_open_offline(g_pcap, &errbuf[0]);
	if(!h) {
		fprintf(stderr, "pcap_open_offline(%s) failed: %s\n", g_pcap, &errbuf[0]);
		return 2;
	}

	g_linktype = pcap_datalink(h);

	// Give subscribers a chance to hook up before the packet flood
	usleep(100000);

	z = pcap_loop(h, -1, &process_packet, NULL);
	if(z < 0) {
		if(z != PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_loop(%s) failed: %s", g_pcap, pcap_geterr(h));
		}
	}

/*
	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGHUP,  sig_handler);
	//signal(SIGALRM, alarm_handler);
	//(void) alarm(30);

	while(!g_shutdown) { usleep(100); }
*/

	if(g_verbosity == 1) { printf("\n"); }
	pcap_close(h);

	// Shutdown the ZMQ PUB bus
	if(g_pktpub) {
		as_zmq_pub_destroy(g_pktpub);
		g_pktpub = NULL;
	}

	if(g_pcap)			{ free(g_pcap); }
	if(g_zmqsockaddr)	{ free(g_zmqsockaddr); }
	if(g_filter)		{ free(g_filter); }

	if(g_verbosity > 0) {
		printf("\nPackets Sent: %lu\n", g_pkt_id);
	}

	return 0;
}

struct options opts[] = 
{
	{ 1, "PCAP",		"PCAP file to read from",		"P",  1 },
	{ 2, "ZMQ",			"Set the ZMQ PUB",				"Z",  1 },
	{ 3, "filter",		"Apply this filter",			"f",  1 },
	{ 4, "verbosity",	"Set verbosity (-v 1 / -v 2)",	"v",  1 },
	{ 5, "nodelay",		"Replay with no packet delay",	NULL, 0 },
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
				g_pcap = strdup(args);
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
			case 5:
				g_pktdelay = 0;
				break;
			default:
				fprintf(stderr, "Unexpected getopts Error! (%d)\n", c);
				break;
		}

		//This free() is required since getopts() automagically allocates space for "args" everytime it's called.
		free(args);
	}

	if(!g_pcap) {
		fprintf(stderr, "I need a PCAP file to read from! (Fix with -P)\n");
		exit(EXIT_FAILURE);
	}

	if(!g_zmqsockaddr) {
		fprintf(stderr, "I need a ZMQ bus to drop packets onto! (Fix with -Z)\n");
		exit(EXIT_FAILURE);
	}
}

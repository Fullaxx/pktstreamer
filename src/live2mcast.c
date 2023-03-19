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
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>			// gethostbyname()

#include "getopts.h"
#include "async_pcapture.h"
#include "udp4.h"

// Prototypes
static void parse_args(int argc, char **argv);

// Globals
int g_shutdown = 0;

char *g_dev = NULL;
char *g_mcastaddr = NULL;
char *g_filter = NULL;
int g_verbosity = 0;

u4clnt_t g_msock;
unsigned long g_pkt_id = 0;

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

ssize_t as_udp4_client_write(u4clnt_t *c, void *data, int data_len)
{
	ssize_t z;

	if(!c) { return 0; }

	z = sendto(c->socket, data, data_len, 0, (SA *)&c->addr, sizeof(c->addr));
	if(z < 0) {
		fprintf(stderr, "error: sendto() [as_udp4_client_write()] (errno: %i)\n", errno);
		perror("sendto");
	}

	return z;
}

int as_udp4_connect(u4clnt_t *c, char *address, unsigned short port)
{
	struct hostent *host = NULL;

	c->socket = socket(PF_INET, SOCK_DGRAM, 0);
	if(c->socket < 0) {
		fprintf(stderr, "error: socket() [as_udp4_client_write()] (errno: %i)\n", errno);
		perror("socket");
		return -1;
	}

	// The gethostbyname*() and gethostbyaddr*() functions are obsolete.
	// Applications should use  getaddrinfo(3) and getnameinfo(3) instead.
	if (!(host = gethostbyname(address))) {
		fprintf(stderr, "gethostbyname(): %s could not be resolved\n", address);
		perror("gethostbyname");
		return -2;
	}

	memset(&c->addr, 0, sizeof(c->addr));
	c->addr.sin_family = AF_INET;
	c->addr.sin_port = htons(port);
	//c->addr.sin_addr = host->h_addr;
	memcpy(&c->addr.sin_addr, host->h_addr, sizeof(c->addr.sin_addr));

	return 0;
}

static void recv_packet(acap_t *ac, const struct pcap_pkthdr *pcap_hdr, u_char *raw_pkt)
{
	struct timespec myts;

	// Convert fractional seconds to nanoseconds
	myts.tv_sec = pcap_hdr->ts.tv_sec;
	myts.tv_nsec = pcap_hdr->ts.tv_usec;
	if(ac->tsprecision == PCAP_TSTAMP_PRECISION_MICRO) {
		myts.tv_nsec *= 1000;
	}

	g_pkt_id++;
	as_udp4_client_write(&g_msock, raw_pkt, pcap_hdr->caplen);

	if(g_verbosity == 1) {
		printf(".");
		fflush(stdout);
	}

	if(g_verbosity == 2) {
		if(ac->tsprecision == PCAP_TSTAMP_PRECISION_MICRO) {
			printf("%ld.%06ld\n", pcap_hdr->ts.tv_sec, pcap_hdr->ts.tv_usec);
		}
		if(ac->tsprecision == PCAP_TSTAMP_PRECISION_NANO) {
			printf("%ld.%09ld\n", myts.tv_sec, myts.tv_nsec);
		}
		fflush(stdout);
	}
}

int main(int argc, char *argv[])
{
	int retval;
	char *colon;
	acap_t ac;
	acap_opt_t asopt;

	// Initialize Memory
	memset(&ac, 0, sizeof(ac));
	memset(&asopt, 0, sizeof(asopt));
	asopt.promisc = 1;

	// Parse Command Line Arguments
	parse_args(argc, argv);

	// Open the Multicast Socket
	colon = strchr(g_mcastaddr, ':');
	*colon = 0L;
	retval = as_udp4_connect(&g_msock, g_mcastaddr, atoi(colon+1));
	if(retval < 0) {
		fprintf(stderr, "as_udp4_connect(%s:d%d) failed!\n", g_mcastaddr, atoi(colon+1));
		return 1;
	}

	// Start the Packet Capture
	printf("Opening %s ...\n", (g_dev ? g_dev : "ANY"));
	retval = as_pcapture_launch(&ac, &asopt, g_dev, g_filter, &recv_packet, NULL);
	if(retval < 0) {
		fprintf(stderr, "as_pcapture_launch(%s) failed!!\n", g_dev);
		return 2;
	}

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGQUIT, sig_handler);
	signal(SIGHUP,  sig_handler);
	//signal(SIGALRM, alarm_handler);
	//(void) alarm(30);

	while(!g_shutdown && !ac.dispatch_error) { usleep(100); }

	// Shutdown the Packet Capture
	as_pcapture_stop(&ac);
	if(g_verbosity == 1) { printf("\n"); }

	if(g_dev)		{ free(g_dev); }
	if(g_mcastaddr)	{ free(g_mcastaddr); }
	if(g_filter)	{ free(g_filter); }

	if(g_verbosity > 0) {
		printf("\nPackets Sent: %lu\n", g_pkt_id);
	}

	return 0;
}

struct options opts[] = 
{
	{ 1, "dev",			"Network device to sniff",			"i",  1 },
	{ 2, "MCAST",		"Set the MCAST address (IP:PORT)",	"M",  1 },
	{ 3, "filter",		"Apply this filter",				"f",  1 },
	{ 4, "verbosity",	"Set verbosity (-v 1 / -v 2)",		"v",  1 },
	{ 0, NULL,			NULL,								NULL, 0 }
};

static void parse_args(int argc, char **argv)
{
	char *args, *colon;
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
				g_mcastaddr = strdup(args);
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

	if(!g_dev && !g_filter) {
		fprintf(stderr, "If you wish to capture on ALL interfaces, you MUST implement a proper filter! (Fix with -f)\n");
		exit(EXIT_FAILURE);
	}

	if(!g_mcastaddr) {
		fprintf(stderr, "I need a Multicast Address to drop packets onto! (Fix with -M)\n");
		exit(EXIT_FAILURE);
	}

	colon = strchr(g_mcastaddr, ':');
	if(!colon) {
		fprintf(stderr, "Multicast Address must be in the form of \"<MCASTIP>:<1-65535> (Fix with -M)\"\n");
		exit(1);
	}

	if(atoi(colon+1) == 0) {
		fprintf(stderr, "Multicast Address must be in the form of \"<MCASTIP>:<1-65535> (Fix with -M)\"\n");
		exit(1);
	}

	if(atoi(colon+1) > 65535) {
		fprintf(stderr, "Multicast Address must be in the form of \"<MCASTIP>:<1-65535> (Fix with -M)\"\n");
		exit(1);
	}
}

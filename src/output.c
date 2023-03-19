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
//#include <unistd.h>
#include <errno.h>

#include "async_zmq_sub.h"

// Prototypes
void count_packet(unsigned int pkts, unsigned int bytes);

// Globals
FILE *g_outstream = NULL;
unsigned int g_file_header_written = 0;
unsigned int g_magic = 0;

// Externals found in pkt_recv.c
extern unsigned int g_shutdown;
extern unsigned int g_us_ts;
extern unsigned int g_ns_ts;
extern unsigned long g_zmqerr_count;
extern unsigned long g_zmqpkt_count;

static void print_file_header(zmq_mf_t *fh_msg)
{
	char *token, *line_saveptr;
	unsigned short vers_major;
	unsigned short vers_minor;
	unsigned int thiszone;
	unsigned int sigfigs;
	unsigned int snaplen;
	unsigned int linktype;
	size_t err;

	token = strtok_r(fh_msg->buf, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	g_magic = strtoul(token, NULL, 10);

	// Override the default and convert timestamps
	if(g_us_ts) { g_magic = 0xA1B2C3D4; }
	if(g_ns_ts) { g_magic = 0xA1B23C4D; }

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	linktype = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	thiszone = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	sigfigs = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	snaplen = strtoul(token, NULL, 10);

	err = 0;
	vers_major = 2;
	vers_minor = 4;

	err += fwrite(&g_magic,		4, 1, g_outstream);
	err += fwrite(&vers_major,	2, 1, g_outstream);
	err += fwrite(&vers_minor,	2, 1, g_outstream);
	err += fwrite(&thiszone,	4, 1, g_outstream);
	err += fwrite(&sigfigs,		4, 1, g_outstream);
	err += fwrite(&snaplen,		4, 1, g_outstream);
	err += fwrite(&linktype,	4, 1, g_outstream);
	if(err != 7) {
		fprintf(stderr, "Error writing file header!\n");
		g_shutdown = 1;
	}
}

static void print_packet(zmq_mf_t *ts_msg, zmq_mf_t *pkt_msg)
{
	unsigned int sec;
	unsigned int frac;
	unsigned int caplen;
	unsigned int pktlen;
	char *period;
	size_t err;

	err = 0;
	sec = 0;
	frac = 0;

	caplen = pktlen = pkt_msg->size;
	period = strchr(ts_msg->buf, '.');
	if(period) {
		sec  = atol(ts_msg->buf);
		frac = atol(period+1);
		if(g_magic == 0xA1B2C3D4) { frac /= 1000; }
	}

	err += fwrite(&sec,		4, 1, g_outstream);
	err += fwrite(&frac,	4, 1, g_outstream);
	err += fwrite(&caplen,	4, 1, g_outstream);
	err += fwrite(&pktlen,	4, 1, g_outstream);
	if(err != 4) {
		fprintf(stderr, "Error writing packet header!\n");
		exit(1);
	}

	err = fwrite(pkt_msg->buf, pkt_msg->size, 1, g_outstream);
	if(err != 1) {
		fprintf(stderr, "Error writing packet data!\n");
		exit(1);
	}

	count_packet(1, pkt_msg->size);
}

/*
	as_zmq_pub_send(g_pktpub, ac->dev, strlen(ac->dev)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%d/%d/%u/%u", ac->linktype, 0, 0, 262144);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	snprintf(zbuf, sizeof(zbuf), "%ld.%09ld", ts->tv_sec, ts->tv_usec);
	as_zmq_pub_send(g_pktpub, zbuf, strlen(zbuf)+1, 1);

	as_zmq_pub_send(g_pktpub, buf, len, 0);
*/
void pkt_cb(zmq_sub_t *s, zmq_mf_t **mpa, int msgcnt, void *user_data)
{
	zmq_mf_t *dev_msg;
	zmq_mf_t *fh_msg;
	zmq_mf_t *ts_msg;
	zmq_mf_t *pkt_msg;

	if(!mpa) { g_zmqerr_count++; return; }
	if(msgcnt != 4) { g_zmqerr_count++; return; }

	dev_msg = mpa[0];
	fh_msg = mpa[1];
	ts_msg = mpa[2];
	pkt_msg = mpa[3];

	if(!dev_msg) { g_zmqerr_count++; return; }
	if(!fh_msg) { g_zmqerr_count++; return; }
	if(!ts_msg) { g_zmqerr_count++; return; }
	if(!pkt_msg) { g_zmqerr_count++; return; }

	if(g_file_header_written == 0) {
		// Only do this once
		// Just in case init_output() never got called
		if(!g_outstream) { g_outstream = stdout; }
		print_file_header(fh_msg);
		g_file_header_written = 1;
	}

	print_packet(ts_msg, pkt_msg);
	fflush(g_outstream);
	g_zmqpkt_count++;
}

// If we have a filename, open the file for writing PCAP data
// else print packets to stdout
int init_output(char *filename)
{
	if(filename) {
		g_outstream = fopen(filename, "w");
		if(!g_outstream) {
			fprintf(stderr, "fopen(%s, w) fail: %s", filename, strerror(errno));
			return 1;
		}
	} else {
		g_outstream = stdout;
	}

	return 0;
}

void fini_output(void)
{
	fclose(g_outstream);
}

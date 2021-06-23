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
//#include <unistd.h>
//#include <errno.h>
#include <pcap/dlt.h>		//DLT_EN10MB,DLT_RAW,DLT_LINUX_SLL
#include <arpa/inet.h>		//inet_ntop()

#include "async_zmq_sub.h"

// Globals
int g_linktype = -1;
unsigned long ipp_hist[256];
unsigned long g_zmqerr_count;
unsigned long g_zmqpkt_count;
unsigned long g_proto_count;

// Externals found in hist_main.c
extern int g_verbose;

void print_stats(void)
{
	fprintf(stderr, "%lu/%lu/%lu\n", g_zmqerr_count, g_zmqpkt_count, g_proto_count);
	g_zmqpkt_count = g_zmqerr_count = g_proto_count = 0;
	fflush(stderr);
}

#include <netinet/ip.h>
#define SIZE_IPV4 (sizeof(struct ip))
static void process_ipv4(unsigned char *buf, int len)
{
#ifdef USE_IPHDR
	struct iphdr *ip4 = (struct iphdr *)buf;
#else
	struct ip *ip4 = (struct ip *)buf;
#endif
	//unsigned char hl;
	unsigned short tl;
	unsigned char proto;
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];

	if(len < SIZE_IPV4) { return; }

#ifdef USE_IPHDR
	//hl = ip4->ihl << 2;
	tl = ntohs(ip4->tot_len);
	proto = ip4->protocol;
	inet_ntop(AF_INET, &ip4->saddr, &src_addr[0], INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip4->daddr, &dst_addr[0], INET_ADDRSTRLEN);
#else
	//hl = ip4->ip_hl << 2;
	tl = ntohs(ip4->ip_len);
	proto = ip4->ip_p;
	inet_ntop(AF_INET, &ip4->ip_src, &src_addr[0], INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip4->ip_dst, &dst_addr[0], INET_ADDRSTRLEN);
#endif

	ipp_hist[proto]++;
	g_proto_count++;
	if(g_verbose) { fprintf(stderr, "%15s -> %15s %4u %3u ", &src_addr[0], &dst_addr[0], tl, proto); }

	//buf += hl; len -= hl;
	//process_payload(buf, len);
	if(g_verbose) { fprintf(stderr, "\n"); fflush(stderr); }
}

#include <net/ethernet.h>
#define SIZE_ETHERNET (sizeof(struct ether_header))
static void process_eth(unsigned char *buf, int len)
{
	unsigned short *pp, proto;

	if(len < SIZE_ETHERNET) { return; }

	pp = (unsigned short *) (buf+12);
	proto = ntohs(*pp);

	buf += SIZE_ETHERNET;
	len -= SIZE_ETHERNET;

	if(proto == ETHERTYPE_IP) {
		process_ipv4(buf, len);
	}
}

#include <pcap/sll.h>
#define SIZE_SLL (sizeof(struct sll_header))
static void process_sll(unsigned char *buf, int len)
{
	struct sll_header *sll = (struct sll_header *)buf;
	unsigned short proto;

	if(len < SIZE_SLL) { return; }

	proto = ntohs(sll->sll_protocol);
	buf += SIZE_SLL;
	len -= SIZE_SLL;

	if(proto == ETHERTYPE_IP) {
		process_ipv4(buf, len);
	}
}

static void get_linktype(zmq_mf_t *fh_msg)
{
	char *token, *line_saveptr;

	token = strtok_r(fh_msg->buf, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	//g_magic = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return; }
	g_linktype = atoi(token);
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

	if(g_linktype == -1) {
		get_linktype(fh_msg);
	}

	switch(g_linktype) {
		case DLT_EN10MB:				//  1
			process_eth(pkt_msg->buf, pkt_msg->size);
			break;
		case DLT_RAW:					// 12
			process_ipv4(pkt_msg->buf, pkt_msg->size);
			break;
		case DLT_LINUX_SLL:				//113
			process_sll(pkt_msg->buf, pkt_msg->size);
			break;
		/*default:
			printf("Unknown Linktype %d\n", g_linktype);*/
	}

	g_zmqpkt_count++;
}

void init_hist(void)
{
	memset(&ipp_hist[0], 0, sizeof(ipp_hist));
}

void fini_hist(int print_all, int fmt_csv)
{
	int i;

	for(i=0; i<256; i++) {
		if(print_all || ipp_hist[i]) {
			if(fmt_csv) {
				printf("%d,%lu\n", i, ipp_hist[i]);
			} else {
				printf("%03d: %lu\n", i, ipp_hist[i]);
			}
		}
	}
}

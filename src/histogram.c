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

#ifdef HISTIPP
unsigned long g_hist[256];
unsigned long g_proto_count = 0;
#endif

#if defined(HISTTCP) || defined(HISTUDP)
unsigned long g_hist[65536];
unsigned long g_port_count = 0;
#endif

unsigned long g_zmqerr_count = 0;
unsigned long g_zmqpkt_count = 0;

// Externals found in hist_main.c
extern int g_verbose;

// Prototype
static void process_ipv4(unsigned char *buf, int len);

void print_stats(void)
{
#ifdef HISTIPP
	fprintf(stderr, "%lu/%lu/%lu\n", g_zmqerr_count, g_zmqpkt_count, g_proto_count);
	g_proto_count = 0;
#endif

#if defined(HISTTCP) || defined(HISTUDP)
	fprintf(stderr, "%lu/%lu/%lu\n", g_zmqerr_count, g_zmqpkt_count, g_port_count);
	g_port_count = 0;
#endif

	g_zmqpkt_count = g_zmqerr_count = 0;
	fflush(stderr);
}

#ifdef HISTTCP
#include <netinet/tcp.h>
#define SIZE_TCP (sizeof(struct tcphdr))
static void process_tcp(unsigned char *buf, int len)
{
	struct tcphdr *tcp = (struct tcphdr *)buf;
	unsigned short sport;
	unsigned short dport;

	if(len < SIZE_TCP) { return; }

	sport = ntohs(tcp->th_sport);
	dport = ntohs(tcp->th_dport);
	g_hist[sport]++;
	g_hist[dport]++;
	g_port_count += 2;

	if(g_verbose) { fprintf(stderr, " %5u %5u", sport, dport); }
}
#endif

#ifdef HISTUDP
#include <netinet/udp.h>
#define SIZE_UDP (sizeof(struct udphdr))
static void process_udp(unsigned char *buf, int len)
{
	struct udphdr *udp = (struct udphdr *)buf;
	unsigned short sport;
	unsigned short dport;

	if(len < SIZE_UDP) { return; }

	sport = ntohs(udp->uh_sport);
	dport = ntohs(udp->uh_dport);
	g_hist[sport]++;
	g_hist[dport]++;
	g_port_count += 2;

	if(g_verbose) { fprintf(stderr, " %5u %5u", sport, dport); }
}
#endif

#include <netinet/ip6.h>
#define SIZE_IPV6 (sizeof(struct ip6_hdr))
static void process_ipv6(unsigned char *buf, int len)
{
	struct ip6_hdr *ip6 = (struct ip6_hdr *)buf;
	unsigned char ip_vers;
	unsigned short psize;
	unsigned char next_hdr;
	char src_addr[INET6_ADDRSTRLEN];
	char dst_addr[INET6_ADDRSTRLEN];

	if(len < SIZE_IPV6) { return; }

	ip_vers = (ntohl(ip6->ip6_flow) & 0xF0000000) >> 28;
	if(ip_vers != 6) { return; }

	psize = ntohs(ip6->ip6_plen);
	next_hdr = ip6->ip6_nxt;
	inet_ntop(AF_INET6, &ip6->ip6_src, &src_addr[0], INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &ip6->ip6_dst, &dst_addr[0], INET6_ADDRSTRLEN);

#ifdef HISTIPP
	g_hist[next_hdr]++;
	g_proto_count++;
#endif

	buf += SIZE_IPV6; len -= SIZE_IPV6;
	if(g_verbose) { fprintf(stderr, " %s -> %s %4u %3u", &src_addr[0], &dst_addr[0], psize, next_hdr); }

	if(next_hdr == IPPROTO_IPIP) { process_ipv4(buf, len); }
	if(next_hdr == IPPROTO_IPV6) { process_ipv6(buf, len); }

#ifdef HISTTCP
	if(next_hdr == IPPROTO_TCP) { process_tcp(buf, len); }
#endif
#ifdef HISTUDP
	if(next_hdr == IPPROTO_UDP) { process_udp(buf, len); }
#endif

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
	unsigned char ip_vers;
	unsigned char hl;
	unsigned short tl;
	unsigned char proto;
	char src_addr[INET_ADDRSTRLEN];
	char dst_addr[INET_ADDRSTRLEN];

	if(len < SIZE_IPV4) { return; }

#ifdef USE_IPHDR
	ip_vers = ip4->ip_version;
#else
	ip_vers = ip4->ip_v;
#endif
	if(ip_vers != 4) { return; }

#ifdef USE_IPHDR
	hl = ip4->ihl << 2;
	tl = ntohs(ip4->tot_len);
	proto = ip4->protocol;
	inet_ntop(AF_INET, &ip4->saddr, &src_addr[0], INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip4->daddr, &dst_addr[0], INET_ADDRSTRLEN);
#else
	hl = ip4->ip_hl << 2;
	tl = ntohs(ip4->ip_len);
	proto = ip4->ip_p;
	inet_ntop(AF_INET, &ip4->ip_src, &src_addr[0], INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &ip4->ip_dst, &dst_addr[0], INET_ADDRSTRLEN);
#endif

#ifdef HISTIPP
	g_hist[proto]++;
	g_proto_count++;
#endif

	buf += hl; len -= hl;
	if(g_verbose) { fprintf(stderr, " %15s -> %15s %4u %3u", &src_addr[0], &dst_addr[0], tl, proto); }

	if(proto == IPPROTO_IPIP) { process_ipv4(buf, len); }
	if(proto == IPPROTO_IPV6) { process_ipv6(buf, len); }

#ifdef HISTTCP
	if(proto == IPPROTO_TCP) { process_tcp(buf, len); }
#endif
#ifdef HISTUDP
	if(proto == IPPROTO_UDP) { process_udp(buf, len); }
#endif

}

#include <net/ethernet.h>
#define SIZE_ETHERNET (sizeof(struct ether_header))
static void process_eth(unsigned char *buf, int len)
{
	unsigned short *pp, proto;

	if(len < SIZE_ETHERNET) { return; }

	pp = (unsigned short *) (buf+12);
	proto = ntohs(*pp);
	buf += SIZE_ETHERNET; len -= SIZE_ETHERNET;

	if(proto == ETHERTYPE_IP) { process_ipv4(buf, len); }
	if(proto == ETHERTYPE_IPV6) { process_ipv6(buf, len); }
}

#include <pcap/sll.h>
#define SIZE_SLL (sizeof(struct sll_header))
static void process_sll(unsigned char *buf, int len)
{
	struct sll_header *sll = (struct sll_header *)buf;
	unsigned short proto;

	if(len < SIZE_SLL) { return; }

	proto = ntohs(sll->sll_protocol);
	buf += SIZE_SLL; len -= SIZE_SLL;

	if(proto == ETHERTYPE_IP) { process_ipv4(buf, len); }
	if(proto == ETHERTYPE_IPV6) { process_ipv6(buf, len); }
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

	if(g_verbose) { fprintf(stderr, "%s:", (char *)dev_msg->buf); }

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
		/*case DLT_IEEE802_11:			//105
			process_wlan(pkt_msg->buf, pkt_msg->size);
			break;
		case DLT_IEEE802_11_RADIO:		//127
			process_radiotap(pkt_msg->buf, pkt_msg->size);
			break;
		case DLT_IEEE802_11_RADIO_AVS:	//163
			process_radiotap_avs(pkt_msg->buf, pkt_msg->size);
			break;
		default:
			printf("Unknown Linktype %d\n", g_linktype);*/
	}

	if(g_verbose) { fprintf(stderr, "\n"); fflush(stderr); }
	g_zmqpkt_count++;
}

void init_hist(void)
{
	memset(&g_hist[0], 0, sizeof(g_hist));
}

void fini_hist(int print_all, int fmt_csv)
{
	int i, nmembers;

	// nmembers = 256   for IPP
	// nmembers = 65536 for TCP/UDP
	nmembers = sizeof(g_hist)/sizeof(g_hist[0]);

	for(i=0; i<nmembers; i++) {
		if(print_all || g_hist[i]) {
			if(fmt_csv) {
				printf("%d,%lu\n", i, g_hist[i]);
			} else {
				printf("%d: %lu\n", i, g_hist[i]);
			}
		}
	}
}

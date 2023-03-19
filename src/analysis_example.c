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
#include "packet_dissection.h"

// Prototypes
void count_packet(unsigned int pkts, unsigned int bytes);

// Externals found in pkt_recv.c
extern unsigned int g_shutdown;
extern unsigned int g_us_ts;
extern unsigned int g_ns_ts;
extern unsigned long g_zmqerr_count;
extern unsigned long g_zmqpkt_count;

static void handle_new_tcp_connection(char *ts, ipv4_t *ip4, ipv6_t *ip6, tcp_t *tcp)
{
	char src_str[64], dst_str[64];
	char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];

	if(ip6) {
		inet_ntop(AF_INET6, &ip6->src, &ip_src[0], INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6->dst, &ip_dst[0], INET6_ADDRSTRLEN);
	}
	if(ip4) {
		inet_ntop(AF_INET, &ip4->src, &ip_src[0], INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip4->dst, &ip_dst[0], INET_ADDRSTRLEN);
	}

	snprintf(src_str, sizeof(src_str), "%s:%u", ip_src, TCP_SRCP(tcp));
	snprintf(dst_str, sizeof(dst_str), "%s:%u", ip_dst, TCP_DSTP(tcp));
	printf("TCP: %s -> %s", src_str, dst_str);
	printf(" New Connection");
	printf("\n");
}

static void handle_icmp_echo(char *ts, ipv4_t *ip4, ipv6_t *ip6, icmp_t *icmp)
{
	char *icmp_type_str;
	char src_str[64], dst_str[64];
	char ip_src[INET6_ADDRSTRLEN], ip_dst[INET6_ADDRSTRLEN];

	if(ip6) {
		inet_ntop(AF_INET6, &ip6->src, &ip_src[0], INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &ip6->dst, &ip_dst[0], INET6_ADDRSTRLEN);
	}
	if(ip4) {
		inet_ntop(AF_INET, &ip4->src, &ip_src[0], INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip4->dst, &ip_dst[0], INET_ADDRSTRLEN);
	}

	snprintf(src_str, sizeof(src_str), "%s", ip_src);
	snprintf(dst_str, sizeof(dst_str), "%s", ip_dst);

	switch(ICMP_TYPE(icmp)) {
		case ICMP_ECHOREPLY: icmp_type_str = "REPLY"; break;
		case ICMP_ECHO: icmp_type_str = "ECHO"; break;
		default: icmp_type_str = "???";
	}

	printf("ICMP %5s: ", icmp_type_str);
	printf("%s -> %s", src_str, dst_str);
	printf("\n");
}

static inline void process_tcp(char *ts, unsigned char *buf, int len, ipv4_t *ip4, ipv6_t *ip6)
{
	if(len < SIZE_TCP) { return; }
	tcp_t *tcp = (tcp_t *)buf;
	if(TCP_SYNBIT(tcp) && !TCP_ACKBIT(tcp)) {
		handle_new_tcp_connection(ts, ip4, ip6, tcp);
	}
}

static inline void process_icmp(char *ts, unsigned char *buf, int len, ipv4_t *ip4, ipv6_t *ip6)
{
	if(len < SIZE_ICMP) { return; }
	icmp_t *icmp = (icmp_t *)buf;
	switch(ICMP_TYPE(icmp)) {
		case ICMP_ECHOREPLY:
		case ICMP_ECHO:
			handle_icmp_echo(ts, ip4, ip6, icmp);
			break;
	}
}

static inline void process_ipv6(char *ts, unsigned char *buf, int len)
{
	if(len < SIZE_IPV6) { return; }
	ipv6_t *ip = (ipv6_t *)buf;
	buf += SIZE_IPV6; len -= SIZE_IPV6;
	switch(IPV6_NXTH(ip)) {
		case IPPROTO_ICMP: process_icmp(ts, buf, len, NULL, ip); break;
		case IPPROTO_TCP: process_tcp(ts, buf, len, NULL, ip); break;
	}
}

static inline void process_ipv4(char *ts, unsigned char *buf, int len)
{
	if(len < SIZE_IPV4) { return; }
	ipv4_t *ip = (ipv4_t *)buf;
	unsigned char iphlen = IPV4_HSIZE(ip);
	buf += iphlen; len -= iphlen;
	switch(IPV4_PROTO(ip)) {
		case IPPROTO_ICMP: process_icmp(ts, buf, len, ip, NULL); break;
		case IPPROTO_TCP: process_tcp(ts, buf, len, ip, NULL); break;
	}
}

static inline void process_raw(char *ts, unsigned char *buf, int len)
{
	if(len < 1) { return; }
	unsigned char ip_v = buf[0] >> 4;
	if(ip_v == 4) { process_ipv4(ts, buf, len); }
	if(ip_v == 6) { process_ipv6(ts, buf, len); }
}

static inline void process_sll(char *ts, unsigned char *buf, int len)
{
	if(len < SIZE_SLL) { return; }
	sll_t *sll = (sll_t *)buf;
	buf += SIZE_SLL; len -= SIZE_SLL;
	switch(SLL_PROTO(sll)) {
		case ETHERTYPE_IP:   process_ipv4(ts, buf, len); break;
		case ETHERTYPE_IPV6: process_ipv6(ts, buf, len); break;
	}
}

static inline void process_ethernet(char *ts, unsigned char *buf, int len)
{
	if(len < SIZE_ETHERNET) { return; }
	eth_t *eth = (eth_t *)buf;
	buf += SIZE_ETHERNET; len -= SIZE_ETHERNET;
	switch(ETH_TYPELEN(eth)) {
		case ETHERTYPE_IP:   process_ipv4(ts, buf, len); break;
		case ETHERTYPE_IPV6: process_ipv6(ts, buf, len); break;
	}
}

static unsigned int get_linktype(zmq_mf_t *fh_msg)
{
	char *token, *line_saveptr;
	unsigned int linktype;

	token = strtok_r(fh_msg->buf, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return 0; }
	//g_magic = strtoul(token, NULL, 10);

	token = strtok_r(NULL, "/", &line_saveptr);
	if(!token) { g_zmqerr_count++; return 0; }
	linktype = strtoul(token, NULL, 10);
	return linktype;
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

	unsigned int linktype = get_linktype(fh_msg);
	char *ts_buf = (char *)ts_msg->buf;
	unsigned char *pkt_buf = (unsigned char *)pkt_msg->buf;
	int pkt_len = (int)pkt_msg->size;

	switch(linktype) {
		case DLT_EN10MB:
			process_ethernet(ts_buf, pkt_buf, pkt_len);
			break;
		case DLT_LINUX_SLL:
			process_sll(ts_buf, pkt_buf, pkt_len);
			break;
		case DLT_RAW:
		case DLT_IPV4:
		case DLT_IPV6:
			process_raw(ts_buf, pkt_buf, pkt_len);
			break;
		default:
			fprintf(stderr, "Unknown Linktype: %u\n", linktype);
	}

	g_zmqpkt_count++;
}

int init_output(char *filename)
{
	return 0;
}

void fini_output(void)
{

}

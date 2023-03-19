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

#ifndef __PACKET_DISSECTION_H__
#define __PACKET_DISSECTION_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif

#ifndef DLT_RAW
#define DLT_RAW 12
#endif

/* Linux cooked sockets */
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

#ifndef DLT_IPV4
#define DLT_IPV4 228
#endif

#ifndef DLT_IPV6
#define DLT_IPV6 229
#endif

/* Linux cooked sockets v2 */
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

#include <arpa/inet.h>

////////////////////////////////////////////////////////////////////////////////

#define	ETHERTYPE_IP		(0x0800)
#define	ETHERTYPE_VLAN		(0x8100)
#define	ETHERTYPE_IPV6		(0x86dd)

#define ETH_ALEN	(6)

typedef struct {
	uint8_t  ether_dhost[ETH_ALEN];
	uint8_t  ether_shost[ETH_ALEN];
	uint16_t ether_typelen;
} __attribute__ ((packed)) eth_t;
#define SIZE_ETHERNET (sizeof(eth_t))

#define ETH_TYPELEN(s) (ntohs(s->ether_typelen))

////////////////////////////////////////////////////////////////////////////////
// SSL Headers shamelessly ripped from libpcap

#ifndef SLL_ADDRLEN
#define SLL_ADDRLEN	8		/* length of address field */
#endif

typedef struct sll_header {
	uint16_t sll_pkttype;			/* packet type */
	uint16_t sll_hatype;			/* link-layer address type */
	uint16_t sll_halen;				/* link-layer address length */
	uint8_t  sll_addr[SLL_ADDRLEN];	/* link-layer address */
	uint16_t sll_protocol;			/* protocol */
}  __attribute__ ((packed)) sll_t;
#define SIZE_SLL (sizeof(sll_t))

#define SLL_PROTO(s) (ntohs(s->sll_protocol))

typedef struct sll2_header {
	uint16_t sll2_protocol;				/* protocol */
	uint16_t sll2_reserved_mbz;			/* reserved - must be zero */
	uint32_t sll2_if_index;				/* 1-based interface index */
	uint16_t sll2_hatype;				/* link-layer address type */
	uint8_t  sll2_pkttype;				/* packet type */
	uint8_t  sll2_halen;				/* link-layer address length */
	uint8_t  sll2_addr[SLL_ADDRLEN];	/* link-layer address */
}  __attribute__ ((packed)) sll2_t;
#define SIZE_SLL2 (sizeof(sll2_t))

#define SLL2_PROTO(s) (ntohs(s->sll2_protocol))

/*
 * The LINUX_SLL_ values for "sll_pkttype" and LINUX_SLL2_ values for
 * "sll2_pkttype"; these correspond to the PACKET_ values on Linux,
 * which are defined by a header under include/uapi in the current
 * kernel source, and are thus not going to change on Linux.  We
 * define them here so that they're available even on systems other
 * than Linux.
 */

#ifndef LINUX_SLL_HOST
#define LINUX_SLL_HOST		0
#endif

#ifndef LINUX_SLL_BROADCAST
#define LINUX_SLL_BROADCAST	1
#endif

#ifndef LINUX_SLL_MULTICAST
#define LINUX_SLL_MULTICAST	2
#endif

#ifndef LINUX_SLL_OTHERHOST
#define LINUX_SLL_OTHERHOST	3
#endif

#ifndef LINUX_SLL_OUTGOING
#define LINUX_SLL_OUTGOING	4
#endif

/*
 * The LINUX_SLL_ values for "sll_protocol" and LINUX_SLL2_ values for
 * "sll2_protocol"; these correspond to the ETH_P_ values on Linux, but
 * are defined here so that they're available even on systems other than
 * Linux.  We assume, for now, that the ETH_P_ values won't change in
 * Linux; if they do, then:
 *
 *	if we don't translate them in "pcap-linux.c", capture files
 *	won't necessarily be readable if captured on a system that
 *	defines ETH_P_ values that don't match these values;
 *
 *	if we do translate them in "pcap-linux.c", that makes life
 *	unpleasant for the BPF code generator, as the values you test
 *	for in the kernel aren't the values that you test for when
 *	reading a capture file, so the fixup code run on BPF programs
 *	handed to the kernel ends up having to do more work.
 *
 * Add other values here as necessary, for handling packet types that
 * might show up on non-Ethernet, non-802.x networks.  (Not all the ones
 * in the Linux "if_ether.h" will, I suspect, actually show up in
 * captures.)
 */

#ifndef LINUX_SLL_P_802_3
#define LINUX_SLL_P_802_3	0x0001	/* Novell 802.3 frames without 802.2 LLC header */
#endif

#ifndef LINUX_SLL_P_802_2
#define LINUX_SLL_P_802_2	0x0004	/* 802.2 frames (not D/I/X Ethernet) */
#endif

#ifndef LINUX_SLL_P_CAN
#define LINUX_SLL_P_CAN		0x000C	/* CAN frames, with SocketCAN pseudo-headers */
#endif

#ifndef LINUX_SLL_P_CANFD
#define LINUX_SLL_P_CANFD	0x000D	/* CAN FD frames, with SocketCAN pseudo-headers */
#endif

////////////////////////////////////////////////////////////////////////////////

typedef struct {
	uint8_t  info;		/* 4 bits version, 4 bits header size */
	uint8_t  tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t csum;
	uint32_t src;
	uint32_t dst;
} __attribute__ ((packed)) ipv4_t;
#define SIZE_IPV4 (sizeof(ipv4_t))

#define IPV4_VERS(s)   (     (s->info & 0xF0) >> 4)
#define IPV4_HSIZE(s)  (     (s->info & 0x0F) << 2) /* convert words to bytes */
#define IPV4_TOS(s)    (      s->tos)
#define IPV4_TOTLEN(s) (ntohs(s->tot_len))
#define IPV4_ID(s)     (ntohs(s->id))
#define IPV4_TTL(s)    (      s->ttl)
#define IPV4_PROTO(s)  (      s->proto)
#define IPV4_CSUM(s)   (ntohs(s->csum))
#define IPV4_SRC(s)    (ntohl(s->src))
#define IPV4_DST(s)    (ntohl(s->dst))

typedef struct {
	uint32_t info;			/* 4 bits version, 8 bits TC, 20 bits flow-ID */
	uint16_t size;			/* payload length */
	uint8_t  nxth;			/* next header */
	uint8_t  hlim;			/* hop limit */
	uint8_t  src[16];		/* source address */
	uint8_t  dst[16];		/* dest address */
} __attribute__ ((packed)) ipv6_t;
#define SIZE_IPV6 (sizeof(ipv6_t))

#define IPV6_VERS(s)  ((ntohl(s->info) & 0xF0000000) >> 28)
#define IPV6_TC(s)    ((ntohl(s->info) & 0x0FF00000) >> 20)
#define IPV6_FID(s)   ((ntohl(s->info) & 0x000FFFFF) >>  0)
#define IPV6_PSIZE(s) ( ntohs(s->size))
#define IPV6_NXTH(s)  (       s->nxth)
#define IPV6_HLIM(s)  (       s->hlim)

////////////////////////////////////////////////////////////////////////////////

//https://tools.ietf.org/html/rfc792
typedef struct {
	uint8_t  type;
	uint8_t  code;
	uint16_t sum;
	uint32_t content;
} __attribute__ ((packed)) icmp_t;
#define SIZE_ICMP (sizeof(icmp_t))

#define ICMP_TYPE(s) (      s->type)
#define ICMP_CODE(s) (      s->code)
#define ICMP_CSUM(s) (ntohs(s->sum))

#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY (0)
#endif

#ifndef ICMP_ECHO
#define ICMP_ECHO (8)
#endif

typedef struct {
	uint16_t src;
	uint16_t dst;
	uint32_t seq;
	uint32_t ack;
	uint8_t  hlres;
	uint8_t  flags;
	uint16_t win;
	uint16_t sum;
	uint16_t urp;
} __attribute__ ((packed)) tcp_t;
#define SIZE_TCP (sizeof(tcp_t))

#define TCP_SRCP(s)   (ntohs(s->src))
#define TCP_DSTP(s)   (ntohs(s->dst))
#define TCP_SEQ(s)    (ntohl(s->seq))
#define TCP_ACK(s)    (ntohl(s->ack))
#define TCP_HSIZE(s)  (     (s->hlres & 0xF0) >> 2) /* convert words to bytes */
#define TCP_FLAGS(s)  (      s->flags)
#define TCP_URGBIT(s) (TCP_FLAGS(s) & 0x20)
#define TCP_ACKBIT(s) (TCP_FLAGS(s) & 0x10)
#define TCP_PSHBIT(s) (TCP_FLAGS(s) & 0x08)
#define TCP_RSTBIT(s) (TCP_FLAGS(s) & 0x04)
#define TCP_SYNBIT(s) (TCP_FLAGS(s) & 0x02)
#define TCP_FINBIT(s) (TCP_FLAGS(s) & 0x01)
#define TCP_WIN(s)    (ntohs(s->win))
#define TCP_CSUM(s)   (ntohs(s->sum))
#define TCP_URGP(s)   (ntohs(s->urp))

////////////////////////////////////////////////////////////////////////////////

#ifdef __cplusplus
}
#endif

#endif /* __PACKET_DISSECTION_H__ */

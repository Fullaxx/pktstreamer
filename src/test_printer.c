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
//#include <signal.h>
#include <time.h>
#include <pcap.h>

static void print_file_header(void)
{
	size_t err = 0;
	unsigned int magic;
	unsigned short vers_major;
	unsigned short vers_minor;
	unsigned int thiszone;
	unsigned int sigfigs;
	unsigned int snaplen;
	unsigned int linktype;

	magic = 0xA1B2C3D4;
	vers_major = 2;
	vers_minor = 4;
	thiszone = 0;
	sigfigs = 0;
	snaplen = 262144;
	linktype = DLT_EN10MB;

	err += fwrite(&magic,		4, 1, stdout);
	err += fwrite(&vers_major,	2, 1, stdout);
	err += fwrite(&vers_minor,	2, 1, stdout);
	err += fwrite(&thiszone,	4, 1, stdout);
	err += fwrite(&sigfigs,		4, 1, stdout);
	err += fwrite(&snaplen,		4, 1, stdout);
	err += fwrite(&linktype,	4, 1, stdout);
	if(err != 7) {
		fprintf(stderr, "Error writing file header!\n");
		exit(1);
	}
}

static void print_packet(void)
{
	size_t err = 0;
	unsigned int sec;
	unsigned int usec;
	unsigned int caplen;
	unsigned int pktlen;
	unsigned char eth[14] = { 0xf8, 0x32, 0xe4, 0x9d, 0x54, 0x5c, 0x14, 0x18, 0x77, 0xff, 0xe1, 0x70, 0x08, 0x00 };
	unsigned char ip[20]  = { 0x45, 0x00, 0x00, 0x4c, 0x5e, 0xb8, 0x40, 0x00, 0x40, 0x11, 0xc5, 0xd5, 0x0a, 0x01, 0x01, 0x0d, 0x0a, 0x01, 0x01, 0x05 };
	unsigned char udp[8]  = { 0xe6, 0x32, 0x00, 0x35, 0x00, 0x38, 0x16, 0x5d };
	unsigned char dns[48] = { 0x4d, 0xa4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x69, 0x6e, 0x63, 0x6f, 0x6d, 0x69, 0x6e, 0x67, 0x09, 0x74, 0x65, 0x6c, 0x65, 0x6d, 0x65, 0x74, 0x72, 0x79, 0x07, 0x6d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x1c, 0x00, 0x01 };

	sec = 0;
	usec = 0;
	caplen = 90;
	pktlen = 90;

	err += fwrite(&sec,		4, 1, stdout);
	err += fwrite(&usec,	4, 1, stdout);
	err += fwrite(&caplen,	4, 1, stdout);
	err += fwrite(&pktlen,	4, 1, stdout);
	if(err != 4) {
		fprintf(stderr, "Error writing packet header!\n");
		exit(1);
	}

	err = fwrite(&eth[0], sizeof(eth), 1, stdout);
	if(err != 1) {
		fprintf(stderr, "Error writing packet data!\n");
		exit(1);
	}

	err = fwrite(&ip[0], sizeof(ip), 1, stdout);
	if(err != 1) {
		fprintf(stderr, "Error writing packet data!\n");
		exit(1);
	}

	err = fwrite(&udp[0], sizeof(udp), 1, stdout);
	if(err != 1) {
		fprintf(stderr, "Error writing packet data!\n");
		exit(1);
	}

	err = fwrite(&dns[0], sizeof(dns), 1, stdout);
	if(err != 1) {
		fprintf(stderr, "Error writing packet data!\n");
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	print_file_header();
	print_packet();
	print_packet();
	print_packet();
}

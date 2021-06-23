#!/bin/bash

set -e

OPT="-O2"
DBG="-ggdb3 -DDEBUG"
BAKAPIDIR="../bak_api"
CFLAGS="-Wall"
CFLAGS+=" -I${BAKAPIDIR}"
OPTCFLAGS="${CFLAGS} ${OPT}"
DBGCFLAGS="${CFLAGS} ${DBG}"

rm -f *.exe *.dbg

gcc ${OPTCFLAGS} test_printer.c -o test_printer.exe
gcc ${DBGCFLAGS} test_printer.c -o test_printer.dbg

gcc ${OPTCFLAGS} live2zmq.c ${BAKAPIDIR}/{getopts,async_pcapture,async_zmq_pub}.c -lpthread -lpcap -lzmq -o live2zmq.exe
gcc ${DBGCFLAGS} live2zmq.c ${BAKAPIDIR}/{getopts,async_pcapture,async_zmq_pub}.c -lpthread -lpcap -lzmq -o live2zmq.dbg

gcc ${OPTCFLAGS} pcap2zmq.c ${BAKAPIDIR}/{getopts,async_zmq_pub}.c -lpthread -lpcap -lzmq -o pcap2zmq.exe
gcc ${DBGCFLAGS} pcap2zmq.c ${BAKAPIDIR}/{getopts,async_zmq_pub}.c -lpthread -lpcap -lzmq -o pcap2zmq.dbg

gcc ${OPTCFLAGS} pkt_recv.c output.c ${BAKAPIDIR}/{getopts,async_zmq_sub}.c -lpthread -lzmq -o pkt_writer.exe
gcc ${DBGCFLAGS} pkt_recv.c output.c ${BAKAPIDIR}/{getopts,async_zmq_sub}.c -lpthread -lzmq -o pkt_writer.dbg

gcc ${OPTCFLAGS} hist_main.c histogram.c ${BAKAPIDIR}/{getopts,async_zmq_sub}.c -lpthread -lzmq -o ipp_hist.exe
gcc ${DBGCFLAGS} hist_main.c histogram.c ${BAKAPIDIR}/{getopts,async_zmq_sub}.c -lpthread -lzmq -o ipp_hist.dbg

strip *.exe

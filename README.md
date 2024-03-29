# Packet Streamer [![Actions Status](https://github.com/Fullaxx/pktstreamer/workflows/CI/badge.svg)](https://github.com/Fullaxx/pktstreamer/actions)
Stream filtered network packets using ZeroMQ

## Requirements for building
First we need to make sure we have all the appropriate libraries. \
Please consult this chart for help with installing the required packages. \
If your OS is not listed, please help us fill out the table, or submit a request via github.

| OS     | Commands (as root)                                                   |
| ------ | -------------------------------------------------------------------- |
| CentOS | `yum install -y gcc libpcap-devel zeromq-devel`                      |
| Debian | `apt update; apt install -y build-essential libpcap-dev libzmq3-dev` |
| Fedora | `yum install -y gcc libpcap-devel zeromq-devel`                      |
| Ubuntu | `apt update; apt install -y build-essential libpcap-dev libzmq3-dev` |

## Compile the Code
Install the required development packages and compile the code
```
cd src
./compile.sh
```

## Directly print test packets into wireshark/tshark/tcpdump
```
./test_printer.exe | wireshark -k -i -
./test_printer.exe | tshark -r -
./test_printer.exe | tcpdump -r -
```

## Setup a ZMQ PUB bus to put packets on
Use live2zmq.exe to capture packets from a network interface. \
Use pcap2zmq.exe to replay packets from a pcap file. \
Any packets received will be published to ZMQ.
```
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999
./pcap2zmq.exe -v 1 -P mypackets.pcap -Z tcp://*:9999
```

## Wireless example
This will configure a wireless adapter in monitor mode \
and allow live2zmq to sniff 802.11 packets.
```
iw dev wlan0 set monitor fcsfail control otherbss
ifconfig wlan0 promisc up
iw dev wlan0 set channel 11
./live2zmq.exe -v 2 -i wlan0 -Z tcp://*:9999
```

## Use a BPF to exclude unwanted packets
HTML Resources: [tcpdump.org](https://www.tcpdump.org/manpages/pcap-filter.7.html) / [wireshark.org](https://wiki.wireshark.org/CaptureFilters) / [hackertarget.com](https://hackertarget.com/tcpdump-examples/) / [biot.com](https://biot.com/capstats/bpf.html) / [ntop.org](https://www.ntop.org/guides/nprobe/bpf_expressions.html) \
PDF Cheat Sheets: [alumni.cs.ucr.edu](http://alumni.cs.ucr.edu/~marios/ethereal-tcpdump.pdf) / [gigamon.com](https://www.gigamon.com/content/dam/resource-library/english/guide---cookbook/gu-bpf-reference-guide-gigamon-insight.pdf) / [infosecwriters.com](https://www.infosecwriters.com/text_resources/pdf/JStebelton_BPF.pdf)
```
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "greater 1480"
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "less 40"
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "ether[0] & 1 == 1"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "not broadcast and not multicast"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "dst host ff02::1"
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "ether dst ff:ff:ff:ff:ff:ff"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f arp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f llc
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f ip
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f ip6
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "host 75.75.75.75"
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f "ip[8] < 128"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f icmp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f icmp6
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f igmp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f tcp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f udp
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999 -f sctp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp port 443"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "port 53"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp[tcpflags] == tcp-syn"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp[tcpflags] == tcp-syn|tcp-ack"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)"
```

## Capturing packets on the ANY interface
You can use live2zmq to capture on the ANY interface by omitting the dev argument.
In this case you must implement a filter that excludes the ZMQ stream itself.
If you don't, every ZMQ message will generate at least one packet, which will get captured by libpcap and then passed to ZMQ.
This in turn will create a rift in the space-time continuum that will destroy all life on Earth.
You have been warned.
```
./live2zmq.exe -v 2 -Z tcp://*:9999 -f "not tcp port 9999"
./pkt_writer.exe --stats -Z tcp://localhost:9999 | wireshark -k -i -
```

## Subscribe to a packet stream
Use pkt_writer.exe to save packets to a pcap file \
or to print packets into wireshark/tshark/tcpdump.
```
./pkt_writer.exe -Z tcp://localhost:9999         | wireshark -k -i -
./pkt_writer.exe -Z tcp://localhost:9999         | tshark -r -
./pkt_writer.exe -Z tcp://localhost:9999         | tcpdump -r -
./pkt_writer.exe -Z tcp://localhost:9999 --stats >shiny_new.pcap
./pkt_writer.exe -Z tcp://localhost:9999 --stats -P shiny_new.pcap
```

## Define a stop condition
Stop after 60 seconds \
Stop after 10000 packets \
Stop after 100 MB
```
./pkt_writer.exe -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxtime 60
./pkt_writer.exe -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxpkts 10000
./pkt_writer.exe -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxsize 100
```

## Analysis example
Use analysis_example to dissect ICMP and TCP packets. \
It will display pings and new TCP connections.
```
./analysis_example.exe -Z tcp://localhost:9999
```

## Histogram example
Use hist_ipp to collect a histogram of IP Protocols. \
Use hist_tcp to collect a histogram of TCP port numbers. \
Use hist_udp to collect a histogram of UDP port numbers. \
These binaries will display their histogram when they exit.
```
./hist_ipp.exe -Z tcp://localhost:9999
./hist_ipp.exe -Z tcp://localhost:9999 --csv
./hist_ipp.exe -Z tcp://localhost:9999 --all
./hist_ipp.exe -Z tcp://localhost:9999 --all --csv

./hist_tcp.exe -Z tcp://localhost:9999
./hist_tcp.exe -Z tcp://localhost:9999 --csv
./hist_tcp.exe -Z tcp://localhost:9999 --all
./hist_tcp.exe -Z tcp://localhost:9999 --all --csv

./hist_udp.exe -Z tcp://localhost:9999
./hist_udp.exe -Z tcp://localhost:9999 --csv
./hist_udp.exe -Z tcp://localhost:9999 --all
./hist_udp.exe -Z tcp://localhost:9999 --all --csv
```

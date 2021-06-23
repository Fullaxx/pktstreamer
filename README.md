[![Build Status](https://travis-ci.com/Fullaxx/pktstreamer.svg?branch=master)](https://travis-ci.com/Fullaxx/pktstreamer)

# pktstreamer
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
Use live2zmq.exe to capture packets from a network interface \
Use pcap2zmq.exe to replay packets from a pcap file \
Any packets received will be published to ZMQ
```
./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999
./pcap2zmq.exe -v 1 -P mypackets.pcap -Z tcp://*:9999
```

## Use a BPF to exclude unwanted packets
```
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f icmp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f igmp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f udp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f tcp
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp port 443"
./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f dns
```

## Capturing packets on the ANY interface
You can use live2zmq to capture on the ANY interface by omitting the dev argument.
In this case you must implement a filter that excludes the ZMQ stream itself.
If you don't every ZMQ message will generate at least one packet, which will get captured by libpcap and then passed to ZMQ.
This in turn will create a rift in the space-time continuum that will destroy all life on Earth.
You have been warned.
```
./live2zmq.exe -v 2 -Z tcp://*:9999 -f "not tcp port 9999"
./pkt_writer.exe --stats -Z tcp://localhost:9999 | wireshark -k -i -
```

## Subscribe to a packet stream
Use pkt_writer.exe to save packets to a pcap file \
or to print packets into wireshark/tshark/tcpdump
```
./pkt_writer.exe -Z tcp://localhost:9999         | wireshark -k -i -
./pkt_writer.exe -Z tcp://localhost:9999         | tshark -r -
./pkt_writer.exe -Z tcp://localhost:9999         | tcpdump -r -
./pkt_writer.exe -Z tcp://localhost:9999 --stats >shiny_new.pcap
./pkt_writer.exe -Z tcp://localhost:9999 --stats -P shiny_new.pcap
```

## Histogram Example
Use ipp_hist to collect a histogram of IP Protocols seen
```
./ipp_hist.exe -Z tcp://localhost:9999
./ipp_hist.exe -Z tcp://localhost:9999 --csv
./ipp_hist.exe -Z tcp://localhost:9999 --all
./ipp_hist.exe -Z tcp://localhost:9999 --all --csv
./ipp_hist.exe -Z tcp://localhost:9999 --stats
```

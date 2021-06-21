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
Use pcap2zmq.exe to replay packets from a pcap file
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

## Subscribe to a packet stream
Use zmq2stdout.exe to print packets into wireshark/tshark/tcpdump
Use pkt_writer.exe to save packets to a pcap file
```
./zmq2stdout.exe -Z tcp://localhost:9999 | wireshark -k -i -
./zmq2stdout.exe -Z tcp://localhost:9999 | tshark -r -
./zmq2stdout.exe -Z tcp://localhost:9999 | tcpdump -r -
./pkt_writer.exe --stats -Z tcp://localhost:9999 >shiny_new.pcap
./pkt_writer.exe --stats -Z tcp://localhost:9999 -P shiny_new.pcap
```

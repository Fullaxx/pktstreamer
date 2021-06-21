[![Build Status](https://travis-ci.com/Fullaxx/pktstreamer.svg?branch=master)](https://travis-ci.com/Fullaxx/pktstreamer)

# pktstreamer
Stream filtered network packets using ZMQ

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

## Directly print some test packets into wireshark/tshark/tcpdump
```
./test_printer.exe | wireshark -k -i -
./test_printer.exe | tshark -r -
./test_printer.exe | tcpdump -r -
```

## Capture packets from eth0 and drop them on a ZMQ PUB bus
```
sudo ./live2zmq.exe -v 1 -i eth0 -Z tcp://*:9999
```

## Use a BPF to exclude unwanted packets
```
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f icmp
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f igmp
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f udp
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f tcp
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f "tcp port 443"
sudo ./live2zmq.exe -v 2 -i eth0 -Z tcp://*:9999 -f dns
```

## Receive packets from ZMQ and print them into wireshark/tshark/tcpdump
```
./zmq2stdout.exe -Z tcp://localhost:9999 | wireshark -k -i -
./zmq2stdout.exe -Z tcp://localhost:9999 | tshark -r -
./zmq2stdout.exe -Z tcp://localhost:9999 | tcpdump -r -
```

## Receive packets from ZMQ and save to pcap file
```
./pkt_writer.exe -Z tcp://localhost:9999 >shiny_new.pcap
./pkt_writer.exe -Z tcp://localhost:9999 -P shiny_new.pcap
```

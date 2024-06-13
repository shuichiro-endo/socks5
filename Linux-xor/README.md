# socks5 xor

socks5 server and client (Linux)

## Installation
### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```

2. build
```
cd socks5/Linux-xor
make
```

## Usage
- server
```
Normal mode  : client -> server
usage        : ./server -h listen_ip -p listen_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./server -h 0.0.0.0 -p 9050
             : ./server -h localhost -p 9050 -x -k deadbeef
             : ./server -h ::1 -p 9050 -x -A 3 -B 0 -C 3 -D 0
             : ./server -h fe80::xxxx:xxxx:xxxx:xxxx%eth0 -p 9050 -x -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : ./server -r -H socks5client_ip -P socks5client_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./server -r -H 192.168.0.5 -P 1234
             : ./server -r -H localhost -P 1234 -x -k deadbeef
             : ./server -r -H ::1 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : ./server -r -H fe80::xxxx:xxxx:xxxx:xxxx%eth0 -P 1234 -x -A 3 -B 0 -C 3 -D 0
```

- client
```
Normal mode  : client -> server
usage        : ./client -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050
             : ./client -h localhost -p 9050 -H 192.168.0.10 -P 9050 -x -k deadbeef
             : ./client -h ::1 -p 9050 -H 192.168.0.10 -P 9050 -x -A 3 -B 0 -C 3 -D 0
             : ./client -h fe80::xxxx:xxxx:xxxx:xxxx%eth0 -p 9050 -H fe80::yyyy:yyyy:yyyy:yyyy%eth0 -P 9050 -x -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : ./client -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234
             : ./client -r -h localhost -p 9050 -H 0.0.0.0 -P 1234 -x -k deadbeef
             : ./client -r -h ::1 -p 9050 -H 0.0.0.0 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : ./client -r -h fe80::xxxx:xxxx:xxxx:xxxx%eth0 -p 9050 -H fe80::xxxx:xxxx:xxxx:xxxx%eth0 -P 1234 -x -A 3 -B 0 -C 3 -D 0

```
Note: In the reverse mode, the number of concurrent connections allowed is one. If the number of concurrent connections is multiple, this tool doesn't work.

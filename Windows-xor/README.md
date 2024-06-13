# socks5 xor

socks5 server and client (Windows)

## Installation
### Install dependencies
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```
2. run x64 Native Tools Command Prompt for VS 2022
3. build
    - server
    ```
    cd socks5\Windows-xor\server
    compile.bat
    ```
    - client
    ```
    cd socks5\Windows-xor\client
    compile.bat
    ```

## Usage
- server
```
Normal mode  : client -> server
usage        : server.exe -h listen_ip -p listen_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : server.exe -h 192.168.0.10 -p 9050
             : server.exe -h localhost -p 9050 -x -k deadbeef
             : server.exe -h ::1 -p 9050 -x -A 3 -B 0 -C 3 -D 0
             : server.exe -h 192.168.0.10 -p 9050 -x -A 3 -B 0 -C 3 -D 0
             : server.exe -h fe80::xxxx:xxxx:xxxx:xxxx%14 -p 9050 -x -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : server.exe -r -H socks5client_ip -P socks5client_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : server.exe -r -H 192.168.0.5 -P 1234
             : server.exe -r -H localhost -P 1234 -x -k deadbeef
             : server.exe -r -H ::1 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : server.exe -r -H 192.168.0.5 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : server.exe -r -H fe80::xxxx:xxxx:xxxx:xxxx%14 -P 1234 -x -A 3 -B 0 -C 3 -D 0
```
- client
```
Normal mode  : client -> server
usage        : client.exe -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050
             : client.exe -h localhost -p 9050 -H 192.168.0.10 -P 9050 -x -k deadbeef
             : client.exe -h ::1 -p 9050 -H 192.168.0.10 -P 9050 -x -A 3 -B 0 -C 3 -D 0
             : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -x -A 3 -B 0 -C 3 -D 0
             : client.exe -h fe80::xxxx:xxxx:xxxx:xxxx%14 -p 9050 -H fe80::yyyy:yyyy:yyyy:yyyy%14 -P 9050 -x -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : client.exe -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port
             : [-x (xor encryption] [-k key(hexstring)]
             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234
             : client.exe -r -h localhost -p 9050 -H 192.168.0.5 -P 1234 -x -k deadbeef
             : client.exe -r -h ::1 -p 9050 -H 192.168.0.5 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -x -A 3 -B 0 -C 3 -D 0
             : client.exe -r -h fe80::xxxx:xxxx:xxxx:xxxx%14 -p 9050 -H fe80::xxxx:xxxx:xxxx:xxxx%14 -P 1234 -x -A 3 -B 0 -C 3 -D 0
```

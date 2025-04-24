# socks5 xor static

socks5 server and client (Linux static)

## Installation
### Install dependencies
- gcc
- make
- cmake
- [c-ares](https://github.com/c-ares/c-ares) (ares_getaddrinfo function: The alternative to the glibc's getaddrinfo function.)

### Install
#### c-ares
1. download c-ares
```
wget https://github.com/c-ares/c-ares/releases/download/v1.34.5/c-ares-1.34.5.tar.gz
tar xvzf c-ares-1.34.5.tar.gz
```

2. modify ares_getaddrinfo.c and ares_getnameinfo.c ([static linking (glibc getservbyport_r getservbyname_r) #945](https://github.com/c-ares/c-ares/issues/945))
- c-ares-1.34.5/src/lib/ares_getaddrinfo.c (lookup_service function)
```
nano -l c-ares-1.34.5/src/lib/ares_getaddrinfo.c
```
```
static unsigned short lookup_service(const char *service, int flags)
{
    if (service) {
        return (unsigned short)atoi(service);
    }
    return 0;
}
```
- c-ares-1.34.5/src/lib/ares_getnameinfo.c (lookup_service function)
```
nano -l c-ares-1.34.5/src/lib/ares_getnameinfo.c
```
```
static char *lookup_service(unsigned short port, unsigned int flags, char *buf,
                            size_t buflen)
{
    return NULL;
}
```

3. build c-ares
```
cd c-ares-1.34.5
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local/cares -DCARES_STATIC=On -DCARES_STATIC_PIC=On ..
make
```

#### socks5 xor static
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```

2. copy c-ares directories to socks5 directory
- c-ares-1.34.5/include
```
cp -rp c-ares-1.34.5/include socks5/Linux-xor-static/
```
- c-ares-1.34.5/build/lib
```
cp -rp c-ares-1.34.5/build/lib socks5/Linux-xor-static/
```

3. check Linux_static directory
```
> tree socks5/Linux-xor-static
socks5/Linux-xor-static
├── client.c
├── client.h
├── include
│   ├── ares_build.h
│   ├── ares_build.h.cmake
│   ├── ares_build.h.in
│   ├── ares_dns.h
│   ├── ares_dns_record.h
│   ├── ares.h
│   ├── ares_nameser.h
│   ├── ares_version.h
│   ├── CMakeLists.txt
│   ├── Makefile.am
│   └── Makefile.in
├── lib
│   ├── libcares.a
│   ├── libcares.so -> libcares.so.2
│   ├── libcares.so.2 -> libcares.so.2.19.4
│   └── libcares.so.2.19.4
├── Makefile
├── README.md
├── server.c
├── server.h
└── socks5.h

3 directories, 22 files
```

4. build
```
cd socks5/Linux-xor-static
make
```

5. check if they are statically linked binaries
```
> file client
file client
client: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=32c9877844ac51bed4081a90f45a8625be6c2d84, for GNU/Linux 3.2.0, not stripped

> ldd client
not a dynamic executable

> file server
server: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=71a621a7e55d370794a7f464b055720fdbb1a4ab, for GNU/Linux 3.2.0, not stripped

> ldd server
not a dynamic executable
```

6. run strip command (optional)
```
> strip client

> file client
client: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=32c9877844ac51bed4081a90f45a8625be6c2d84, for GNU/Linux 3.2.0, stripped

> nm client
nm: client: no symbols

> strip server

> file server
server: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=71a621a7e55d370794a7f464b055720fdbb1a4ab, for GNU/Linux 3.2.0, stripped

> nm server
nm: server: no symbols
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

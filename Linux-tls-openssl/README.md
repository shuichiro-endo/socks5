# socks5

socks5 server and client (Linux)

## Installation
### Install dependencies
- openssl and libssl-dev
```
sudo apt install openssl libssl-dev
```

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```

2. build
```
cd socks5/Linux
make
```

## Usage
- server
```
Normal mode  : client -> server
usage        : ./server -h listen_ip -p listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./server -h 0.0.0.0 -p 9050
             : ./server -h 0.0.0.0 -p 9050 -s
             : ./server -h 0.0.0.0 -p 9050 -s -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : ./server -r -H socks5client_ip -P socks5client_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./server -r -H 192.168.0.5 -P 1234
             : ./server -r -H 192.168.0.5 -P 1234 -s
             : ./server -r -H 192.168.0.5 -P 1234 -s -A 3 -B 0 -C 3 -D 0
```

- client
```
Normal mode  : client -> server
usage        : ./client -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050
             : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s
             : ./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s -A 3 -B 0 -C 3 -D 0
or
Reverse mode : client <- server
usage        : ./client -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]
example      : ./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234
             : ./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s
             : ./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s -A 3 -B 0 -C 3 -D 0
```

### Normal mode (client -> server)
1. run my server
```
# Socks5
./server -h 0.0.0.0 -p 9050

# Socks5 over TLS
./server -h 0.0.0.0 -p 9050 -s
```
2. run my client
```
# Socks5
./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050

# Socks5 over TLS
./client -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s
```
3. connect to my client from other clients(browser, proxychains, etc.)
```
proxychains4 curl -v https://www.google.com
curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
```

### Reverse mode (client <- server)
1. run my client
```
# Socks5
./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234

# Socks5 over TLS
./client -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s
```
2. run my server
```
# Socks5
./server -r -H 192.168.0.5 -P 1234

# Socks5 over TLS
./server -r -H 192.168.0.5 -P 1234 -s
```
3. connect to my client from other clients(browser, proxychains, etc.)
```
proxychains4 curl -v https://www.google.com
curl -v -x socks5h://127.0.0.1:9050 https://www.google.com
```

## Notes
### How to change socks5 server Authentication Method
- server
    1. modify server.c file
    ```
    static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
    char username[256] = "socks5user";
    char password[256] = "supersecretpassword";
    ```
    2. build
    ```
    cd socks5/Linux
    make
    ```

### How to change socks5 server privatekey and certificate
- server
    1. generate server privatekey, publickey and certificate
    ```
    openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
    
    openssl req -new -sha256 -key server-key-pair.pem -out server.csr
    openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
    openssl x509 -text -noout -in server.crt
    ```
    2. copy the server privatekey and certificate
    ```
    cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'
    cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into serverkey.h file
    ```
    char serverPrivateKey[] = "-----BEGIN EC PRIVATE KEY-----\n"\
    "MHcCAQEEIPAB7VXkdlfWvOL1YKr+cxGLhx69g/eqUjncU1D9hkUdoAoGCCqGSM49\n"\
    "AwEHoUQDQgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9\n"\
    "O7kldBsGkxFXSbXcUfjk6wyrgarKndpK0A==\n"\
    "-----END EC PRIVATE KEY-----\n";

    char serverCertificate[] = "-----BEGIN CERTIFICATE-----\n"\
    "MIIBhTCCASsCFB47Pqx2Ko4ZXD5bCsGaaTP1Zjh8MAoGCCqGSM49BAMCMEUxCzAJ\n"\
    "BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l\n"\
    "dCBXaWRnaXRzIFB0eSBMdGQwHhcNMjMwMTE1MTIwODA3WhcNMzMwMTEyMTIwODA3\n"\
    "WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwY\n"\
    "SW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n"\
    "QgAErAWMtToIcsL5fGF+DKZhMRy9m1WR3ViC7nrLokou9A/TMPr2DMz9O7kldBsG\n"\
    "kxFXSbXcUfjk6wyrgarKndpK0DAKBggqhkjOPQQDAgNIADBFAiEAqknImSukXNY+\n"\
    "fkuuFbDFkte9mZM3Xy/ArE7kDIMt4nwCIHdlJRn0Cf18VQbpLessgklsk/gX59uo\n"\
    "jrsksbPHQ50h\n"\
    "-----END CERTIFICATE-----\n";
    ```
    4. build
    ```
    cd socks5/Linux
    make
    ```

- client
    1. copy server.crt file to socks5/Linux directory
    ```
    cp server.crt socks5/Linux/server.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char serverCertificateFilename[256] = "server.crt";
    char serverCertificateFileDirectoryPath[256] = ".";
    ```
    3. build (if you change the certificate filename or directory path)
    ```
    cd socks5/Linux
    make
    ```

### How to change socks5 server cipher suite (TLS1.2, TLS1.3)
- server
    1. select cipher suite(TLS1.2) and check
    ```
    openssl ciphers -v "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256"
    ```
    2. select cipher suite(TLS1.3) [https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_ciphersuites.html)
    ```
    TLS_AES_128_GCM_SHA256
    TLS_AES_256_GCM_SHA384
    TLS_CHACHA20_POLY1305_SHA256
    TLS_AES_128_CCM_SHA256
    TLS_AES_128_CCM_8_SHA256
    ```
    3. modify server.c file
    ```
    char cipherSuiteTLS1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
    char cipherSuiteTLS1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3
    ```
    4. build
    ```
    cd socks5/Linux
    make
    ```


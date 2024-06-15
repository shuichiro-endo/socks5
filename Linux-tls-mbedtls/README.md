# socks5 mbedtls

socks5 server and client (Linux)

## Installation
### Install dependencies
- mbedtls (e.g. debian: libmbedtls14t64 and libmbedtls-dev)
```
sudo apt install libmbedtls14t64 libmbedtls-dev
```

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```

2. build
```
cd socks5/Linux-tls-mbedtls
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
Note: In the reverse mode, the number of concurrent connections allowed is one. If the number of concurrent connections is multiple, this tool doesn't work.

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
    cd socks5/Linux-tls-mbedtls
    make
    ```

### How to change socks5 server privatekey and certificate
- server
    1. generate server privatekey and certificate ([https://mbed-tls.readthedocs.io/en/latest/kb/how-to/generate-a-self-signed-certificate/](https://mbed-tls.readthedocs.io/en/latest/kb/how-to/generate-a-self-signed-certificate/))
    ```
    git clone --recurse-submodules https://github.com/Mbed-TLS/mbedtls.git
    cd mbedtls/programs
    make

    cd ../../
    # rsa
    mbedtls/programs/pkey/gen_key type=rsa rsa_keysize=4096 format=pem filename=server-private.pem
    # ec
    mbedtls/programs/pkey/gen_key type=ec ec_curve=secp256r1 format=pem filename=server-private.pem

    mbedtls/programs/x509/cert_write selfsign=1 issuer_key=server-private.pem issuer_name=CN=socks5 not_before=20240101000000 not_after=21231231235959 is_ca=1 max_pathlen=0 format=pem output_file=server.crt
    ```
    2. copy the server privatekey and certificate
    ```
    # rsa
    cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END RSA PRIVATE KEY-----\\n"\\/"-----END RSA PRIVATE KEY-----\\n";/g'
    # ec
    cat server-private.pem | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END EC PRIVATE KEY-----\\n"\\/"-----END EC PRIVATE KEY-----\\n";/g'

    cat server.crt | sed -e 's/^/"/g' -e 's/$/\\n"\\/g' -e 's/"-----END CERTIFICATE-----\\n"\\/"-----END CERTIFICATE-----\\n";/g'
    ```
    3. paste the privatekey and certificate into serverkey.h file (e.g. ec)
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
    cd socks5/Linux-tls-mbedtls
    make
    ```

- client
    1. copy server.crt file to socks5/Linux-tls-mbedtls directory
    ```
    cp server.crt socks5/Linux-tls-mbedtls/server.crt
    ```
    2. modify client.c file (if you change the certificate filename)
    ```
    char serverCertificateFilename[256] = "./server.crt";	// server certificate filepath
    ```
    3. build (if you change the certificate filename)
    ```
    cd socks5/Linux-tls-mbedtls
    make
    ```

### How to change socks5 server cipher suite
- server
    1. select cipher suite
    ```
    cat /usr/include/mbedtls/ssl_ciphersuites.h
    ```
    Note: mbedtls development version ([https://github.com/Mbed-TLS/mbedtls/blob/development/include/mbedtls/ssl_ciphersuites.h](https://github.com/Mbed-TLS/mbedtls/blob/development/include/mbedtls/ssl_ciphersuites.h))

    2. modify server.c file
    ```
    int ciphersuites[] = {
    //MBEDTLS_TLS1_3_AES_256_GCM_SHA384,
    //MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,
    //MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    0};
    ```
    3. build
    ```
    cd socks5/Linux-tls-mbedtls
    make
    ```


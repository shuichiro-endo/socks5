# socks5

socks5 server and client (Windows)

## Installation
### Install dependencies
- openssl
    1. download [openssl 3.0 version](https://www.openssl.org/source/)
    2. extract openssl-3.0.x.tar.gz
    3. install openssl. see openssl-3.0.x\NOTES-WINDOWS.md(Quick start)
- visual studio community (Desktop development with C++)
    1. install Desktop development with C++

Note: It takes a lot of time to install these.

### Install
1. download files
```
git clone https://github.com/shuichiro-endo/socks5.git
```
2. run x64 Native Tools Command Prompt for VS 2022
3. set environment variable
```
set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
set LIB=%LIB%;C:\Program Files\OpenSSL\lib
set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
```
4. build
    - server
    ```
    cd socks5\Windows\server
    compile.bat
    ```
    - client
    ```
    cd socks5\Windows\client
    compile.bat
    ```
5. copy openssl dll files (libcrypto-3-x64.dll, libssl-3-x64.dll) to the client and server directory
    - server
    ```
    cd socks5\Windows\server
    copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
    copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
    ```
    - client
    ```
    cd socks5\Windows\client
    copy "C:\Program Files\OpenSSL\bin\libcrypto-3-x64.dll" .
    copy "C:\Program Files\OpenSSL\bin\libssl-3-x64.dll" .
    ```

## Usage
- server
```
Normal mode  : client -> server
usage        : server.exe -h listen_ip -p listen_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec)] [-u tv_usec(forwarder timeout microsec)]
example      : server.exe -h 192.168.0.10 -p 9050
             : server.exe -h 192.168.0.10 -p 9050 -s
             : server.exe -h 192.168.0.10 -p 9050 -s -t 1
             : server.exe -h 192.168.0.10 -p 9050 -s -t 0 -u 500000
or
Reverse mode : client <- server
usage        : server.exe -r -H socks5client_ip -P socks5client_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec)] [-u tv_usec(forwarder timeout microsec)]
example      : server.exe -r -H 192.168.0.5 -P 1234
             : server.exe -r -H 192.168.0.5 -P 1234 -s
             : server.exe -r -H 192.168.0.5 -P 1234 -s -t 1
             : server.exe -r -H 192.168.0.5 -P 1234 -s -t 0 -u 500000
```
- client
```
Normal mode  : client -> server
usage        : client.exe -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]
example      : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050
             : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s
             : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s -t 1
             : client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s -t 0 -u 500000
or
Reverse mode : client <- server
usage        : client.exe -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]
example      : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234
             : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s
             : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s -t 1
             : client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s -t 0 -u 500000
```

### Normal mode (client -> server)
1. run my server
```
# Socks5
server.exe -h 192.168.0.10 -p 9050

# Socks5 over TLS
server.exe -h 192.168.0.10 -p 9050 -s
```
2. run my client
```
# Socks5
client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050

# Socks5 over TLS
client.exe -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s
```
3. connect to my client from other clients(browser, proxychains, etc.)
```
proxychains4 curl -v https://www.google.com
curl -v -x socks5h://192.168.0.5:9050 https://www.google.com
```

### Reverse mode (client <- server)
1. run my client
```
# Socks5
client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234

# Socks5 over TLS
client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s
```
2. run my server
```
# Socks5
server.exe -r -H 192.168.0.5 -P 1234

# Socks5 over TLS
server.exe -r -H 192.168.0.5 -P 1234 -s
```
3. connect to my client from other clients(browser, proxychains, etc.)
```
proxychains4 curl -v https://www.google.com
curl -v -x socks5h://192.168.0.5:9050 https://www.google.com
```

Note: adjust forwarder timeout sec (default:3 sec)
- forwarder timeout: 2 sec
```
client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -t 2
server.exe -r -H 192.168.0.5 -P 1234 -t 2
```
- forwarder timeout: 0.5 sec
```
client.exe -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -t 0 -u 500000
server.exe -r -H 192.168.0.5 -P 1234 -t 0 -u 500000
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
    2. run x64 Native Tools Command Prompt for VS 2022
    3. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    4. build
    ```
    cd socks5\Windows\server
    compile.bat
    ```

### How to change socks5 server privatekey and certificate
- server
    1. run x64 Native Tools Command Prompt for VS 2022
    2. set environment variable
    ```
    set OPENSSL_CONF=C:\Program Files\Common Files\SSL\openssl.cnf
    ```
    3. generate server privatekey, publickey and certificate
    ```
    openssl ecparam -genkey -name prime256v1 -out server-key-pair.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -out server-private.pem
    
    openssl ec -in server-key-pair.pem -outform PEM -pubout -out server-public.pem
    
    openssl req -new -sha256 -key server-key-pair.pem -out server.csr
    openssl x509 -days 3650 -req -signkey server-private.pem < server.csr > server.crt
    openssl x509 -text -noout -in server.crt
    ```
    4. copy the server privatekey and certificate
    ```
    type server-private.pem
    type server.crt
    ```
    5. paste the privatekey and certificate into serverkey.h file
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
    6. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    7. build
    ```
    cd socks5\Windows\server
    compile.bat
    ```

- client
    1. copy server.crt file to socks5\Windows\client directory
    ```
    copy server.crt socks5\Windows\client\server.crt
    ```
    2. modify client.c file (if you change the certificate filename or directory path)
    ```
    char serverCertificateFilename[256] = "server.crt";
    char serverCertificateFileDirectoryPath[256] = ".";
    ```
    3. run x64 Native Tools Command Prompt for VS 2022
    4. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    5. build (if you change the certificate filename or directory path)
    ```
    cd socks5\Windows\client
    compile.bat
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
    4. run x64 Native Tools Command Prompt for VS 2022
    5. set environment variable
    ```
    set INCLUDE=%INCLUDE%;C:\Program Files\OpenSSL\include
    set LIB=%LIB%;C:\Program Files\OpenSSL\lib
    set LIBPATH=%LIBPATH%;C:\Program Files\OpenSSL\lib
    ```
    6. build
    ```
    cd socks5\Windows\server
    compile.bat
    ```


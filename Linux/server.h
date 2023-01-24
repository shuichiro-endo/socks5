/*
 * Title:  socks5 server header (Linux)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(int sock, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(int clientSock, int targetSock);
int forwarderTls(int clientSock, int targetSock, SSL *clientSsl);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv4Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
	SSL *clientSsl;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *clientCtx;
	SSL *clientSsl;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


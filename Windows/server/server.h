/*
 * Title:  socks5 server header (Windows)
 * Author: Shuichiro Endo
 */

int recvData(SOCKET sock, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(SOCKET sock, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(SOCKET clientSock, SOCKET targetSock);
int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *clientSsl);
int sendSocksResponseIpv4(SOCKET clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv4Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6(SOCKET clientSock, char ver, char req, char rsv, char atyp);
int sendSocksResponseIpv6Tls(SSL *clientSsl, char ver, char req, char rsv, char atyp);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

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


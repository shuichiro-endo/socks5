/*
 * Title:  socks5 server header (Windows)
 * Author: Shuichiro Endo
 */

int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(SOCKET socket, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(SOCKET socket, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec);
int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *clientSsl, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(SOCKET clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(SOCKET clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	int clientSock;
	SSL *clientSsl;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
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


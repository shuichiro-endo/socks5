/*
 * Title:  socks5 server header (Linux)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, SSL *clientSsl, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(int sock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(int sock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

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


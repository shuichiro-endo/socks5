/*
 * Title:  socks5 client header (Windows)
 * Author: Shuichiro Endo
 */

int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(SOCKET socket, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(SOCKET socket, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec);
int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *targetSsl, long tv_sec, long tv_usec);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	SOCKET targetSock;
	SOCKET clientSock;
	SSL *targetSsl;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *targetCtx;
	SSL *targetSsl;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);


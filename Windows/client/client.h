/*
 * Title:  socks5 client header (Windows)
 * Author: Shuichiro Endo
 */

int recvData(SOCKET socket, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(SOCKET socket, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(SOCKET clientSock, SOCKET targetSock);
int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *targetSsl);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	SOCKET targetSock;
	SOCKET clientSock;
	SSL *targetSsl;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *targetCtx;
	SSL *targetSsl;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);


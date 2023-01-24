/*
 * Title:  socks5 client header (Linux)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length);
int recvDataTls(SSL *ssl ,void *buffer, int length);
int sendData(int sock, void *buffer, int length);
int sendDataTls(SSL *ssl, void *buffer, int length);
int forwarder(int clientSock, int targetSock);
int forwarderTls(int clientSock, int targetSock, SSL *targetSsl);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int targetSock;
	int clientSock;
	SSL *targetSsl;
} PARAM, *pPARAM;

typedef struct {
	SSL_CTX *targetCtx;
	SSL *targetSsl;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);


/*
 * Title:  socks5 client header (Linux)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(int sock, mbedtls_ssl_context *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(int sock, mbedtls_ssl_context *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, mbedtls_ssl_context *targetSsl, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int targetSock;
	int clientSock;
	mbedtls_ssl_context *pTargetSslCtx;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	mbedtls_net_context *pTargetNetCtx;
	mbedtls_entropy_context *pEntropyCtx;
	mbedtls_ctr_drbg_context *pCtrDrbgCtx;
	mbedtls_ssl_context *pTargetSslCtx;
	mbedtls_ssl_config *pTargetSslCfg;
	mbedtls_x509_crt *pCacrt;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam, int sslConnected);


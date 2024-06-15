/*
 * Title:  socks5 server header (Linux)
 * Author: Shuichiro Endo
 */

int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(int sock, mbedtls_ssl_context *ssl ,void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(int sock, mbedtls_ssl_context *ssl, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderTls(int clientSock, int targetSock, mbedtls_ssl_context *clientSsl, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(int sock, mbedtls_ssl_context *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(int sock, mbedtls_ssl_context *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
	mbedtls_ssl_context *pClientSslCtx;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	mbedtls_net_context *pClientNetCtx;
	mbedtls_entropy_context *pEntropyCtx;
	mbedtls_ctr_drbg_context *pCtrDrbgCtx;
	mbedtls_ssl_context *pClientSslCtx;
	mbedtls_ssl_config *pClientSslCfg;
	mbedtls_x509_crt *pServerCrt;
	mbedtls_pk_context *pServerKey;
	mbedtls_ssl_cache_context *pCache;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam, int sslConnected);

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


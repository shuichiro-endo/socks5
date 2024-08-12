/*
 * Title:  socks5 server header (Windows)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
int encryptMessage(CtxtHandle *pClientContextHandle, SecPkgContext_StreamSizes streamSizes, char *input, int inputLength, char *output, int outputLength);
int decryptMessage(CtxtHandle *pClientContextHandle, SecPkgContext_StreamSizes streamSizes, char *input, int *inputLength, char *output, int outputLength, int *decryptMessageLength);
int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataTls(SOCKET socket, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataTls(SOCKET socket, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec);
int forwarderTls(SOCKET clientSock, SOCKET targetSock, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Tls(SOCKET clientSock, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Tls(SOCKET clientSock, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
PCCERT_CONTEXT findCertificate(const HCERTSTORE hCertStore, const char* certSearchString);
void freeAllBuffers(SecBufferDesc *pSecBufferDesc);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	int clientSock;
	CtxtHandle *pClientContextHandle;
	SecPkgContext_StreamSizes streamSizes;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pServerCert;
	HCRYPTPROV hCryptProv;
	CredHandle *pClientCredHandle;
	CtxtHandle *pClientContextHandle;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


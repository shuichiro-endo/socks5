/*
 * Title:  socks5 client header (Windows)
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
int forwarderTls(SOCKET clientSock, SOCKET targetSock, CtxtHandle *pTargetContextHandle, SecPkgContext_StreamSizes streamSizes, long tv_sec, long tv_usec);
void freeAllBuffers(SecBufferDesc *pSecBufferDesc);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	SOCKET targetSock;
	SOCKET clientSock;
	CtxtHandle *pTargetContextHandle;
	SecPkgContext_StreamSizes streamSizes;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	CredHandle *pTargetCredHandle;
	CtxtHandle *pTargetContextHandle;
} SSLPARAM, *pSSLPARAM;

void finiSsl(pSSLPARAM pSslParam);


/*
 * Title:  socks5 client header (Linux)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
char hexcharToInt(char c);
int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize);
void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength);
int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderXor(int clientSock, int targetSock, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int targetSock;
	int clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;


/*
 * Title:  socks5 server header (Windows)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
char hexcharToInt(char c);
int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize);
void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength);
int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataXor(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataXor(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec);
int forwarderXor(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Xor(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Xor(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
	int clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


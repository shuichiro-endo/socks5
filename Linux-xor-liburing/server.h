/*
 * Title:  socks5 server header (Linux liburing)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
char hexcharToInt(char c);
int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize);
void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength);
int loadLengthFromBuffer(const char *buffer);
void storeLengthToBuffer(int length, char *buffer);
int recvData(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataXor(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataXor(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec);
int forwarderWorker1(void *ptr);
int forwarderWorker2(void *ptr);
int forwarder(struct io_uring *ring1, struct io_uring *ring2, int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderXorWorker1(void *ptr);
int forwarderXorWorker2(void *ptr);
int forwarderXor(struct io_uring *ring1, struct io_uring *ring2, int clientSock, int targetSock, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Xor(struct io_uring *ring, int sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Xor(struct io_uring *ring, int sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	struct io_uring *ring;
	int clientSock;
	int targetSock;
	long tv_sec;
	long tv_usec;
} PARAM2, *pPARAM2;

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


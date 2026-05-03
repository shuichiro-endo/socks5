/*
 * Title:  socks5 client header (Linux liburing)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
char hexcharToInt(char c);
int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize);
void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength);
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

typedef struct {
	struct io_uring *ring;
	int clientSock;
	int targetSock;
	long tv_sec;
	long tv_usec;
} PARAM2, *pPARAM2;


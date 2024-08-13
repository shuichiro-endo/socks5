/*
 * Title:  client.h (Windows DCOM)
 * Author: Shuichiro Endo
 */

#include "socks5server.h"

void printBytes(unsigned char *input, int input_length);
int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int forwarderRecvData(void *ptr);
int forwarderSendData(void *ptr);
void forwarderRecvDataThread(void *ptr);
void forwarderSendDataThread(void *ptr);
int forwarder(SOCKET clientSock, ISocks5Server *pSocks5Server, long tv_sec, long tv_usec);
int worker(void *ptr);
void workerThread(void *ptr);
void usage(char *filename);
int getopt(int argc, char **argv, char *optstring);

typedef struct {
    int tz_minuteswest;
    int tz_dsttime;
} timezone;

int gettimeofday(timeval *tv, timezone *tz);

typedef struct {
	SOCKET clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	SOCKET clientSock;
	ISocks5Server *pSocks5Server;
	long tv_sec;
	long tv_usec;
} FPARAM, *pFPARAM;



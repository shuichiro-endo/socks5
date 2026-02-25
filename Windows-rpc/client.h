/*
 * Title:  client.h (Windows RPC)
 * Author: Shuichiro Endo
 */

#include "socks5server.h"

void PrintBytes(unsigned char *input, int input_length);
int RecvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int SendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec);
int ForwarderRecvData(void *ptr);
int ForwarderSendData(void *ptr);
void ForwarderRecvDataThread(void *ptr);
void ForwarderSendDataThread(void *ptr);
int Forwarder(RPC_BINDING_HANDLE bindingHandle, unsigned int id, SOCKET clientSock, long tv_sec, long tv_usec);
int Worker(void *ptr);
void WorkerThread(void *ptr);
void Usage(char *filename);
int GetOpt(int argc, char **argv, char *optstring);

typedef struct
{
    int tz_minuteswest;
    int tz_dsttime;
} timezone;

int GetTimeOfDay(timeval *tv, timezone *tz);

typedef struct
{
	RPC_BINDING_HANDLE bindingHandle;
	SOCKET clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct
{
	RPC_BINDING_HANDLE bindingHandle;
	unsigned int id;
	SOCKET clientSock;
	long tv_sec;
	long tv_usec;
} FPARAM, *pFPARAM;



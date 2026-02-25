/*
 * Title:  client.cpp (Windows RPC)
 * Author: Shuichiro Endo
 */

#define __DEBUG

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <stdlib.h>
#include <process.h>
#include <rpc.h>
#include <rpcndr.h>
#include <iostream>
#include <random>

#include "client.h"
#include "socks5server.h"
#include "socks5.h"

#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"rpcrt4.lib")
#pragma comment(lib,"ws2_32.lib")

#define BUFFERSIZE 8192

int optstringIndex = 0;
char *optarg = NULL;

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetNetBiosName = NULL;


void* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return malloc(cBytes);
}


void __RPC_USER midl_user_free(void *p)
{
	free(p);
}


void PrintBytes(unsigned char *input, int input_length)
{
	for(int i=0; i<input_length; i++)
	{
		if(i != 0 && i%16 == 0)
		{
			printf("\n");
		}else if(i%16 == 8)
		{
			printf(" ");
		}
		printf("%02x ", input[i]);
	}
	printf("\n");

	return;
}


unsigned int GenerateRandomId()
{
	std::random_device rd;
	std::mt19937 mt(rd());
	std::uniform_int_distribution<unsigned int> distrib(1, UINT32_MAX);

	return distrib(mt);
}


/*
 * Reference:
 * https://stackoverflow.com/questions/10905892/equivalent-of-GetTimeOfDay-for-windows
 */
static int GetTimeOfDay(timeval *tv, timezone *tz)
{
	if(tv)
	{
		FILETIME filetime;
		ULARGE_INTEGER x;
		ULONGLONG usec;
		static const ULONGLONG epoch_offset_us = 11644473600000000ULL;

#if _WIN32_WINNT >= WIN32_WINNT_WIN8
		GetSystemTimePreciseAsFileTime(&filetime);
#else
		GetSystemTimeAsFileTime(&filetime);
#endif

		x.LowPart = filetime.dwLowDateTime;
		x.HighPart = filetime.dwHighDateTime;
		usec = x.QuadPart / 10 - epoch_offset_us;
		tv->tv_sec = (long)(usec / 1000000ULL);
		tv->tv_usec = (long)(usec % 1000000ULL);
	}else
	{
		return -1;
	}

	if(tz)
	{
		TIME_ZONE_INFORMATION timezone;
		GetTimeZoneInformation(&timezone);
		tz->tz_minuteswest = timezone.Bias;
		tz->tz_dsttime = 0;
	}

	return 0;
}


int RecvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	tv.tv_sec = tv_sec;
	tv.tv_usec = tv_usec;
	ZeroMemory(buffer, length+1);

	while(1)
	{
		FD_ZERO(&readfds);
		FD_SET(socket, &readfds);

		if(select(NULL, &readfds, NULL, NULL, &tv) == 0)
		{
#ifdef __DEBUG
			printf("[I] RecvData timeout\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &readfds))
		{
			rec = recv(socket, (char *)buffer, length, 0);
			if(rec == SOCKET_ERROR)
			{
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK)
				{
					Sleep(5);
					continue;
				}
#ifdef __DEBUG
				printf("[E] recv error: %d\n", err);
#endif
				return -1;
			}else
			{
				break;
			}
		}
	}
	
	return rec;
}


int SendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	int err = 0;
	fd_set writefds;
	timeval tv;
	tv.tv_sec = tv_sec;
	tv.tv_usec = tv_usec;


	while(len > 0)
	{
		FD_ZERO(&writefds);
		FD_SET(socket, &writefds);

		if(select(NULL, NULL, &writefds, NULL, &tv) == 0)
		{
#ifdef __DEBUG
			printf("[I] SendData timeout\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &writefds))
		{
			sen = send(socket, (char *)buffer+sendLength, len, 0);
			if(sen == SOCKET_ERROR)
			{
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK)
				{
					Sleep(5);
					continue;
				}
#ifdef __DEBUG
				printf("[E] send error: %d\n", err);
#endif
				return -1;
			}
			sendLength += sen;
			len -= sen;
		}
	}
	
	return sendLength;
}


int ForwarderRecvData(void *ptr)
{
	pFPARAM pFParam = (pFPARAM)ptr;
	RPC_BINDING_HANDLE bindingHandle = pFParam->bindingHandle;
	unsigned int id = pFParam->id;
	SOCKET clientSock = pFParam->clientSock;
	long tv_sec = pFParam->tv_sec;
	long tv_usec = pFParam->tv_usec;

	int rec;
	int err = 0;
	int ret = 0;
	fd_set readfds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;

	int inputBufferLength = 0;
	unsigned char *inputBuffer = (unsigned char *)calloc(BUFFERSIZE, sizeof(unsigned char));
	RPC_STATUS status;



	if(GetTimeOfDay(&start, NULL) == -1)
	{
#ifdef __DEBUG
		printf("[E] GetTimeOfDay error\n");
#endif
		goto error;
	}

	while(1)
	{
		if(GetTimeOfDay(&end, NULL) == -1)
		{
#ifdef __DEBUG
			printf("[E] GetTimeOfDay error\n");
#endif
			goto error;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec))
		{
#ifdef __DEBUG
			printf("[I] ForwarderRecvData timeout\n");
#endif
			goto error;
		}

		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		ret = select(NULL, &readfds, NULL, NULL, &tv);
		if(ret == 0)
		{
#ifdef __DEBUG
			printf("[I] ForwarderRecvData select timeout\n");
#endif
			goto error;
		}else if(ret == SOCKET_ERROR)
		{
			err = WSAGetLastError();
#ifdef __DEBUG
			printf("[I] ForwarderRecvData select error: 0x%x\n", err);
#endif
			goto error;
		}

		if(FD_ISSET(clientSock, &readfds))
		{
			rec = recv(clientSock, (char *)inputBuffer, BUFFERSIZE, 0);
			if(rec == SOCKET_ERROR)
			{
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK)
				{
					Sleep(5);
					continue;
				}
#ifdef __DEBUG
				printf("[E] [client -> client] recv error: %d\n", err);
#endif
				goto error;
			}else if(rec <= 0)
			{
#ifdef __DEBUG
				printf("[E] [client -> client] recv error: %d\n", rec);
#endif
				goto error;
			}else
			{
				inputBufferLength = rec;

				RpcTryExcept
				{
					ret = SendForwarderData(bindingHandle, id, inputBufferLength, inputBuffer, tv_sec, tv_usec);
					if(ret < 0)
					{
#ifdef __DEBUG
						printf("[E] [client -> server] SendForwarderData error\n");
#endif
						goto error;
					}
				}
				RpcExcept(1)
				{
#ifdef __DEBUG
					printf("[E] [client -> server] SendForwarderData error: 0x%lx\n", RpcExceptionCode());
#endif
					goto error;
				}
				RpcEndExcept

				ZeroMemory(inputBuffer, BUFFERSIZE);
				tv.tv_sec = tv_sec;
				tv.tv_usec = tv_usec;
				if(GetTimeOfDay(&start, NULL) == -1)
				{
#ifdef __DEBUG
					printf("[E] GetTimeOfDay error\n");
#endif
					goto error;
				}
			}
		}
	}

	free(inputBuffer);

	return 0;

error:

	free(inputBuffer);

	return -1;
}


int ForwarderSendData(void *ptr)
{
	pFPARAM pFParam = (pFPARAM)ptr;
	RPC_BINDING_HANDLE bindingHandle = pFParam->bindingHandle;
	unsigned int id = pFParam->id;
	SOCKET clientSock = pFParam->clientSock;
	long tv_sec = pFParam->tv_sec;
	long tv_usec = pFParam->tv_usec;

	int sen;
	int sendLength = 0;
	int len = 0;
	int err = 0;
	int ret = 0;
	fd_set writefds;
	timeval tv;
	timeval start;
	timeval end;
	long t = 0;

	int outputBufferLength = 0;
	unsigned char *outputBuffer = NULL;


	if(GetTimeOfDay(&start, NULL) == -1)
	{
#ifdef __DEBUG
		printf("[E] GetTimeOfDay error\n");
#endif
		goto error;
	}

	while(1)
	{
		if(GetTimeOfDay(&end, NULL) == -1)
		{
#ifdef __DEBUG
			printf("[E] GetTimeOfDay error\n");
#endif
			goto error;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec))
		{
#ifdef __DEBUG
			printf("[I] ForwarderSendData timeout\n");
#endif
			goto error;
		}

		outputBufferLength = 0;
		outputBuffer = NULL;

		RpcTryExcept
		{
			ret = RecvForwarderData(bindingHandle, id, tv_sec, tv_usec, &outputBufferLength, &outputBuffer);
			if(ret < 0 || outputBufferLength == 0 || outputBuffer == NULL)
			{
#ifdef __DEBUG
				printf("[E] [client <- server] RecvForwarderData error\n");
#endif
				goto error;
			}
		}
		RpcExcept(1)
		{
#ifdef __DEBUG
			printf("[E] [client <- server] RecvForwarderData error: 0x%lx\n", RpcExceptionCode());
#endif
			goto error;
		}
		RpcEndExcept

		len = outputBufferLength;
		sen = 0;
		sendLength = 0;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		while(len > 0)
		{
			FD_ZERO(&writefds);
			FD_SET(clientSock, &writefds);

			ret = select(NULL, NULL, &writefds, NULL, &tv);
			if(ret == 0)
			{
#ifdef __DEBUG
				printf("[I] ForwarderSendData select timeout\n");
#endif
				goto error;
			}else if(ret == SOCKET_ERROR)
			{
				err = WSAGetLastError();
#ifdef __DEBUG
				printf("[I] ForwarderSendData select error: 0x%x\n", err);
#endif
				goto error;
			}

			if(FD_ISSET(clientSock, &writefds))
			{
				sen = send(clientSock, (char *)outputBuffer+sendLength, len, 0);
				if(sen == SOCKET_ERROR)
				{
					err = WSAGetLastError();
					if(err == WSAEWOULDBLOCK)
					{
						Sleep(5);
						continue;
					}
#ifdef __DEBUG
					printf("[E] [client <- client] send error: %d\n", err);
#endif
					goto error;
				}else if(sen < 0)
				{
#ifdef __DEBUG
					printf("[E] [client <- client] send error: %d\n", err);
#endif
					goto error;
				}else
				{
					sendLength += sen;
					len -= sen;
				}
			}
		}

		midl_user_free(outputBuffer);
		outputBuffer = NULL;

		if(GetTimeOfDay(&start, NULL) == -1){
#ifdef __DEBUG
			printf("[E] GetTimeOfDay error\n");
#endif
			goto error;
		}
	}

	if(outputBuffer != NULL)
	{
		midl_user_free(outputBuffer);
	}

	return 0;

error:

	if(outputBuffer != NULL)
	{
		midl_user_free(outputBuffer);
	}

	return -1;
}


void ForwarderRecvDataThread(void *ptr)
{
	int err = 0;

	err = ForwarderRecvData(ptr);

	_endthread();
}


void ForwarderSendDataThread(void *ptr)
{
	int err = 0;

	err = ForwarderSendData(ptr);

	_endthread();
}


int Forwarder(RPC_BINDING_HANDLE bindingHandle, unsigned int id, SOCKET clientSock, long tv_sec, long tv_usec)
{
	FPARAM fParam;
	fParam.bindingHandle = bindingHandle;
	fParam.id = id;
	fParam.clientSock = clientSock;
	fParam.tv_sec = tv_sec;
	fParam.tv_usec = tv_usec;
	HANDLE handle[2];


	handle[0] = (HANDLE)_beginthread(ForwarderRecvDataThread, 0, &fParam);
	handle[1] = (HANDLE)_beginthread(ForwarderSendDataThread, 0, &fParam);

	WaitForMultipleObjects(2, (const HANDLE *)handle, TRUE, INFINITE);

	return 0;
}


int Worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	RPC_BINDING_HANDLE bindingHandle = pParam->bindingHandle;
	SOCKET clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;
	free(ptr);

	u_long ulMode = 1;	// non-blocking mode
	int ret = 0;
	int err = 0;
	int rec, sen;
	unsigned char method = 0;

	unsigned int id = GenerateRandomId();
	int inputBufferLength = 0;
	int outputBufferLength = 0;
	unsigned char *inputBuffer = (unsigned char *)calloc(BUFFERSIZE, sizeof(unsigned char));
	unsigned char *outputBuffer = NULL;
	RPC_STATUS status;


#ifdef __DEBUG
	printf("[I] id: %u\n", id);
#endif

	// socks SELECTION_REQUEST	client -> client
	if((rec = RecvData(clientSock, (char *)inputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0)
	{
#ifdef __DEBUG
		printf("[E] [client -> client] Recv selection request error\n");
#endif
		goto error;
	}
#ifdef __DEBUG
	printf("[I] [client -> client] Recv selection request: %d bytes\n", rec);
#endif


	// socks SELECTION_REQUEST	client -> server
	inputBufferLength = rec;
	outputBufferLength = 0;
	outputBuffer = NULL;
#ifdef __DEBUG
	printf("[I] [client -> server] Send selection request: %d bytes\n", inputBufferLength);
#endif
	RpcTryExcept
	{
		ret = SelectionRequestResponse(bindingHandle, id, inputBufferLength, inputBuffer, &outputBufferLength, &outputBuffer);
		if(ret < 0 || outputBufferLength == 0 || outputBuffer == NULL)
		{
#ifdef __DEBUG
			printf("[E] [client -> server] SelectionRequestResponse error\n");
#endif
			goto error;
		}
	}
	RpcExcept(1)
	{
#ifdef __DEBUG
		printf("[E] [client -> server] SelectionRequestResponse error: 0x%lx\n", RpcExceptionCode());
#endif
		goto error;
	}
	RpcEndExcept


	// socks SELECTION_RESPONSE	client <- server
#ifdef __DEBUG
	printf("[I] [client <- server] Recv selection response: %d bytes\n", outputBufferLength);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)outputBuffer;
	method = (unsigned char)pSelectionResponse->method;


	// socks SELECTION_RESPONSE	client <- client
	sen = SendData(clientSock, outputBuffer, outputBufferLength, tv_sec, tv_usec);
#ifdef __DEBUG
	printf("[I] [client <- client] Send selection response: %d bytes\n", sen);
#endif
	midl_user_free(outputBuffer);
	outputBuffer = NULL;

	if(method == 0xFF)
	{
#ifdef __DEBUG
		printf("[E] Target socks5server Authentication Method error\n");
#endif
		goto error;
	}

	if(method == 0x2)	// USERNAME_PASSWORD_AUTHENTICATION
	{
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST	client -> client
		if((rec = RecvData(clientSock, (char *)inputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0)
		{
#ifdef __DEBUG
			printf("[E] [client -> client] Recv username password authentication request error\n");
#endif
			goto error;
		}
#ifdef __DEBUG
		printf("[I] [client -> client] Recv username password authentication request: %d bytes\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST	client -> server
		inputBufferLength = rec;
		outputBufferLength = 0;
		outputBuffer = NULL;
#ifdef __DEBUG
		printf("[I] [client -> server] Send username password authentication request: %d bytes\n", inputBufferLength);
#endif
		RpcTryExcept
		{
			ret = UsernamePasswordAuthenticationRequestResponse(bindingHandle, id, inputBufferLength, inputBuffer, &outputBufferLength, &outputBuffer);
			if(ret < 0 || outputBufferLength == 0 || outputBuffer == NULL)
			{
#ifdef __DEBUG
				printf("[E] [client -> server] UsernamePasswordAuthenticationRequestResponse error\n");
#endif
				goto error;
			}
		}
		RpcExcept(1)
		{
#ifdef __DEBUG
			printf("[E] [client -> server] UsernamePasswordAuthenticationRequestResponse error: 0x%lx\n", RpcExceptionCode());
#endif
			goto error;
		}
		RpcEndExcept


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
#ifdef __DEBUG
		printf("[I] [client <- server] Recv username password authentication response: %d bytes\n", outputBufferLength);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- client
		sen = SendData(clientSock, (char *)outputBuffer, outputBufferLength, tv_sec, tv_usec);
#ifdef __DEBUG
		printf("[I] [client <- client] Send username password authentication response: %d bytes\n", sen);
#endif
		midl_user_free(outputBuffer);
		outputBuffer = NULL;
	}


	// socks SOCKS_REQUEST	client -> client
	if((rec = RecvData(clientSock, (char *)inputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0)
	{
#ifdef __DEBUG
		printf("[E] [client -> client] Recv socks request error\n");
#endif
		goto error;
	}
#ifdef __DEBUG
	printf("[I] [client -> client] Recv socks request: %d bytes\n", rec);
#endif


	// socks SOCKS_REQUEST	client -> server
	inputBufferLength = rec;
	outputBufferLength = 0;
	outputBuffer = NULL;
#ifdef __DEBUG
	printf("[I] [client -> server] Send socks request: %d bytes\n", inputBufferLength);
#endif
	RpcTryExcept
	{
		ret = Socks5RequestResponse(bindingHandle, id, inputBufferLength, inputBuffer, &outputBufferLength, &outputBuffer);
		if(ret < 0 || outputBufferLength == 0 || outputBuffer == NULL)
		{
#ifdef __DEBUG
			printf("[E] [client -> server] Socks5RequestResponse error\n");
#endif
			goto error;
		}
	}
	RpcExcept(1)
	{
#ifdef __DEBUG
		printf("[E] [client -> server] Socks5RequestResponse error: 0x%lx\n", RpcExceptionCode());
#endif
		goto error;
	}
	RpcEndExcept


	// socks SOCKS_RESPONSE	client <- server
#ifdef __DEBUG
	printf("[I] [client <- server] Recv socks response: %d bytes\n", outputBufferLength);
#endif


	// socks SOCKS_RESPONSE	client <- client
	sen = SendData(clientSock, outputBuffer, outputBufferLength, tv_sec, tv_usec);
#ifdef __DEBUG
	printf("[I] [client <- client] Send socks response: %d bytes\n", sen);
#endif
	midl_user_free(outputBuffer);
	outputBuffer = NULL;


	err = ioctlsocket(clientSock, FIONBIO, &ulMode);
	if(err != NO_ERROR)
	{
#ifdef __DEBUG
		printf("[E] ioctlsocket error: %d\n", err);
#endif
		goto error;
	}


	// Forwarder
#ifdef __DEBUG
	printf("[I] Forwarder\n");
#endif
	err = Forwarder(bindingHandle, id, clientSock, forwarder_tv_sec, forwarder_tv_usec);


#ifdef __DEBUG
	printf("[I] Worker exit\n");
#endif
	RpcTryExcept
	{
		Close(bindingHandle, id);
	}
	RpcExcept(1)
	{
#ifdef __DEBUG
		printf("[E] Close error: 0x%lx\n", RpcExceptionCode());
#endif
	}
	RpcEndExcept

	free(inputBuffer);
	closesocket(clientSock);

	return 0;

error:

	RpcTryExcept
	{
		Close(bindingHandle, id);
	}
	RpcExcept(1)
	{
#ifdef __DEBUG
		printf("[E] Close error: 0x%lx\n", RpcExceptionCode());
#endif
	}
	RpcEndExcept

	free(inputBuffer);
	closesocket(clientSock);

	return -1;
}


void WorkerThread(void *ptr)
{
	int err = 0;
	
	err = Worker(ptr);
	
	_endthread();
}


void Usage(char *filename)
{
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_netbios_name\n", filename);
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -h 127.0.0.1 -p 9050 -H TESTPC01\n", filename);
	printf("             : %s -h localhost -p 9050 -H TESTPC01\n", filename);
	printf("             : %s -h ::1 -p 9050 -H TESTPC01 -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H TESTPC01 -A 30 -C 30\n", filename);
}


int GetOpt(int argc, char **argv, char *optstring)
{
	unsigned char opt = '\0';
	unsigned char next = '\0';
	char *argtmp = NULL;

	while(1){
		opt = *(optstring + optstringIndex);
		optstringIndex++;
		if(opt == '\0')
		{
			break;
		}
	
		next = *(optstring + optstringIndex);
		if(next == ':')
		{
			optstringIndex++;
		}
	
		for(int i=1; i<argc; i++)
		{
			argtmp = argv[i];
			if(argtmp[0] == '-')
			{
				if(argtmp[1] == opt)
				{
					if(next == ':')
					{
						optarg = argv[i+1];
						return (int)opt;
					}else
					{
						return (int)opt;
					}
				}
			}
		}
	}

	return 0;
}


int main(int argc, char** argv)
{
	int opt;
	char optstring[] = "h:p:H:A:B:C:D:";
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;

	while((opt=GetOpt(argc, argv, optstring)) > 0)
	{
		switch(opt)
		{
		case 'h':
			socks5ServerIp = optarg;
			break;
			
		case 'p':
			socks5ServerPort = optarg;
			break;
		
		case 'H':
			socks5TargetNetBiosName = optarg;
			break;

		case 'A':
			tv_sec = atol(optarg);
			break;

		case 'B':
			tv_usec = atol(optarg);
			break;

		case 'C':
			forwarder_tv_sec = atol(optarg);
			break;

		case 'D':
			forwarder_tv_usec = atol(optarg);
			break;

		default:
			Usage(argv[0]);
			exit(-1);
		}
	}

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetNetBiosName == NULL)
	{
		Usage(argv[0]);
		exit(-1);
	}

	if(tv_sec < 0 || tv_sec > 10 || tv_usec < 0 || tv_usec > 1000000)
	{
		tv_sec = 3;
		tv_usec = 0;
	}else if(tv_sec == 0 && tv_usec == 0)
	{
		tv_sec = 3;
		tv_usec = 0;
	}

	if(forwarder_tv_sec < 0 || forwarder_tv_sec > 3600 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000)
	{
		forwarder_tv_sec = 3;
		forwarder_tv_usec = 0;
	}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0)
	{
		forwarder_tv_sec = 3;
		forwarder_tv_usec = 0;
	}

	WSADATA wsaData;
	SOCKET serverSock = INVALID_SOCKET;
	SOCKET clientSock = INVALID_SOCKET;
	sockaddr_in serverAddr, clientAddr;
	sockaddr_in *tmpIpv4;
	sockaddr_in6 serverAddr6, clientAddr6;
	sockaddr_in6 *tmpIpv6;
	addrinfo hints;
	addrinfo *serverHost;

	ZeroMemory(&serverAddr, sizeof(struct sockaddr_in));
	ZeroMemory(&clientAddr, sizeof(struct sockaddr_in));

	ZeroMemory(&serverAddr6, sizeof(struct sockaddr_in6));
	ZeroMemory(&clientAddr6, sizeof(struct sockaddr_in6));

	ZeroMemory(&hints, sizeof(struct addrinfo));

	char *serverDomainname = socks5ServerIp;
	u_short serverDomainnameLength = 0;
	if(serverDomainname != NULL)
	{
		serverDomainnameLength = strlen(serverDomainname);
	}

	char *serverPortNumber = socks5ServerPort;

	char serverAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *serverAddr6StringPointer = serverAddr6String;
	char clientAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *clientAddr6StringPointer = clientAddr6String;

	char *colon = NULL;
	int family = 0;
	int flags;
	int clientAddrLen = sizeof(clientAddr);
	int clientAddr6Len = sizeof(clientAddr6);
	u_long iMode = 1;	// non-blocking mode

	RPC_STATUS status;

	RPC_CSTR stringBinding = NULL;
	RPC_BINDING_HANDLE bindingHandle = NULL;

	pPARAM pParam;

	int ret = 0;
	int err = 0;

#ifdef __DEBUG
	printf("[I] Timeout recv/send tv_sec(0-10 sec): %ld sec recv/send tv_usec(0-1000000 microsec): %ld microsec\n", tv_sec, tv_usec);
	printf("[I] Timeout forwarder tv_sec(0-3600 sec): %ld sec forwarder tv_usec(0-1000000 microsec): %ld microsec\n", forwarder_tv_sec, forwarder_tv_usec);
#endif

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(err != 0)
	{
#ifdef __DEBUG
		printf("[E] WSAStartup error: %d\n", err);
#endif
		goto error;
	}

	status = RpcStringBindingComposeA(NULL, (RPC_CSTR)"ncacn_ip_tcp", (RPC_CSTR)socks5TargetNetBiosName, NULL, NULL, &stringBinding);
	if(status != RPC_S_OK)
	{
#ifdef __DEBUG
		printf("[E] RpcStringBindingComposeW error: 0x%x\n", status);
#endif
		goto error;
	}

	status = RpcBindingFromStringBindingA(stringBinding, &bindingHandle);
	if(status != RPC_S_OK)
	{
#ifdef __DEBUG
		printf("[E] RpcBindingFromStringBinding error: 0x%x\n", status);
#endif
		goto error;
	}

	RpcStringFreeA(&stringBinding);

	colon = strstr(serverDomainname, ":");	// check ipv6 address
	if(colon == NULL)	// ipv4 address or domainname
	{
		hints.ai_family = AF_INET;	// ipv4
		if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0)
		{
			hints.ai_family = AF_INET6;	// ipv6
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0)
			{
#ifdef __DEBUG
				printf("[E] Cannot resolv the domain name: %s\n", serverDomainname);
#endif
				goto error;
			}
		}
	}else	// ipv6 address
	{
		hints.ai_family = AF_INET6;	// ipv6
		if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef __DEBUG
			printf("[E] Cannot resolv the domain name: %s\n", serverDomainname);
#endif
			goto error;
		}
	}

	if(serverHost->ai_family == AF_INET)
	{
		family = AF_INET;
		serverAddr.sin_family = AF_INET;
		tmpIpv4 = (struct sockaddr_in *)serverHost->ai_addr;
		memcpy(&serverAddr.sin_addr, &tmpIpv4->sin_addr, sizeof(unsigned long));
		memcpy(&serverAddr.sin_port, &tmpIpv4->sin_port, 2);
		freeaddrinfo(serverHost);
	}else if(serverHost->ai_family == AF_INET6)
	{
		family = AF_INET6;
		serverAddr6.sin6_family = AF_INET6;
		tmpIpv6 = (struct sockaddr_in6 *)serverHost->ai_addr;
		memcpy(&serverAddr6.sin6_addr, &tmpIpv6->sin6_addr, sizeof(struct in6_addr));
		memcpy(&serverAddr6.sin6_port, &tmpIpv6->sin6_port, 2);
		serverAddr6.sin6_scope_id = tmpIpv6->sin6_scope_id;
		freeaddrinfo(serverHost);
	}else
	{
#ifdef __DEBUG
		printf("[E] Not implemented\n");
#endif
		freeaddrinfo(serverHost);
		goto error;
	}

	if(family == AF_INET)	// ipv4
	{
		serverSock = socket(AF_INET, SOCK_STREAM, 0);
		if(serverSock == INVALID_SOCKET)
		{
#ifdef __DEBUG
			printf("[E] Socket error: %d\n", WSAGetLastError());
#endif
			goto error;
		}

		// bind
		err = bind(serverSock, (sockaddr *)&serverAddr, sizeof(serverAddr));
		if(err == SOCKET_ERROR)
		{
#ifdef __DEBUG
			printf("[E] bind error: %d\n", WSAGetLastError());
#endif
			goto error;
		}

		// listen
		err = listen(serverSock, 5);
		if(err == SOCKET_ERROR)
		{
#ifdef __DEBUG
			printf("[E] listen error: %d\n", WSAGetLastError());
#endif
			goto error;
		}
#ifdef __DEBUG
		printf("[I] Listenning port %d on %s\n",  ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr, &clientAddrLen)))
		{
#ifdef __DEBUG
			printf("[I] Connected from ip: %s port: %d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->bindingHandle = bindingHandle;
			pParam->clientSock = clientSock;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;

			_beginthread(WorkerThread, 0, pParam);
		}
	}else if(family == AF_INET6)	// ipv6
	{
		serverSock = socket(AF_INET6, SOCK_STREAM, 0);
		if(serverSock == INVALID_SOCKET)
		{
#ifdef __DEBUG
			printf("[E] Socket error: %d\n", WSAGetLastError());
#endif
			goto error;
		}

		// bind
		err = bind(serverSock, (sockaddr *)&serverAddr6, sizeof(serverAddr6));
		if(err == SOCKET_ERROR)
		{
#ifdef __DEBUG
			printf("[E] bind error: %d\n", WSAGetLastError());
#endif
			goto error;
		}

		// listen
		err = listen(serverSock, 5);
		if(err == SOCKET_ERROR)
		{
#ifdef __DEBUG
			printf("[E] listen error: %d\n", WSAGetLastError());
#endif
			goto error;
		}
#ifdef __DEBUG
		inet_ntop(AF_INET6, &serverAddr6.sin6_addr, serverAddr6StringPointer, INET6_ADDRSTRLEN);
		if(serverAddr6.sin6_scope_id > 0)
		{
			printf("[I] Listening port %d on %s%%%d\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer, serverAddr6.sin6_scope_id);
		}else
		{
			printf("[I] Listening port %d on %s\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer);
		}
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr6, &clientAddr6Len)))
		{
#ifdef __DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0)
			{
				printf("[I] Connected from ip: %s%%%d port: %d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else
			{
				printf("[I] Connected from ip: %s port: %d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif

			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->bindingHandle = bindingHandle;
			pParam->clientSock = clientSock;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;

			_beginthread(WorkerThread, 0, pParam);
		}
	}

	closesocket(serverSock);
	RpcBindingFree(&bindingHandle);
	WSACleanup();
	
	return 0;

error:

	closesocket(serverSock);
	RpcBindingFree(&bindingHandle);
	WSACleanup();

	return -1;
}


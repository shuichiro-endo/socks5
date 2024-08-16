/*
 * Title:  client.cpp (Windows DCOM)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <process.h>

#include "client.h"
#include "socks5server.h"
#include "socks5.h"

#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"rpcrt4.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
#pragma comment(lib,"ws2_32.lib")

#define BUFFERSIZE 8192

int optstringIndex = 0;
char *optarg = NULL;

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;

// CLSID:70d2c8cf-f464-414a-84be-95fecc01c132
static const GUID CLSID_Socks5Server =
{0x70d2c8cf, 0xf464, 0x414a, {0x84, 0xbe, 0x95, 0xfe, 0xcc, 0x01, 0xc1, 0x32}};


void printBytes(unsigned char *input, int input_length)
{
	for(int i=0; i<input_length; i++){
		if(i != 0 && i%16 == 0){
			printf("\n");
		}else if(i%16 == 8){
			printf(" ");
		}
		printf("%02x ", input[i]);
	}
	printf("\n");

	return;
}


/*
 * Reference:
 * https://stackoverflow.com/questions/10905892/equivalent-of-gettimeofday-for-windows
 */
static int gettimeofday(timeval *tv, timezone *tz)
{
	if(tv){
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
	}else{
		return -1;
	}

	if(tz){
		TIME_ZONE_INFORMATION timezone;
		GetTimeZoneInformation(&timezone);
		tz->tz_minuteswest = timezone.Bias;
		tz->tz_dsttime = 0;
	}

	return 0;
}


int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	tv.tv_sec = tv_sec;
	tv.tv_usec = tv_usec;
	ZeroMemory(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(socket, &readfds);

		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvData timeout.\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &readfds)){
			rec = recv(socket, (char *)buffer, length, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] recv error:%d.\n", err);
#endif
				return -1;
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int sendData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	int err = 0;
	fd_set writefds;
	timeval tv;
	tv.tv_sec = tv_sec;
	tv.tv_usec = tv_usec;


	while(len > 0){
		FD_ZERO(&writefds);
		FD_SET(socket, &writefds);

		if(select(NULL, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendData timeout.\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &writefds)){
			sen = send(socket, (char *)buffer+sendLength, len, 0);
			if(sen == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[E] send error:%d.\n", err);
#endif
				return -1;
			}
			sendLength += sen;
			len -= sen;
		}
	}
	
	return sendLength;
}


int forwarderRecvData(void *ptr)
{
	pFPARAM pFParam = (pFPARAM)ptr;
	SOCKET clientSock = pFParam->clientSock;
	ISocks5Server *pSocks5Server = pFParam->pSocks5Server;
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

	HRESULT hr;
	ULONG ulInputLength = 0;
	BYTE *pbInputBuffer = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));


	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error\n");
#endif
		return -1;
	}

	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error\n");
#endif
			return -1;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] forwarderRecvData timeout\n");
#endif
			return -1;
		}

		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);

		ret = select(NULL, &readfds, NULL, NULL, &tv);
		if(ret == 0){
#ifdef _DEBUG
			printf("[I] forwarderRecvData select timeout\n");
#endif
			return -1;
		}else if(ret == SOCKET_ERROR){
			err = WSAGetLastError();
#ifdef _DEBUG
			printf("[I] forwarderRecvData select error:0x%x\n", err);
#endif
			return -1;
		}

		if(FD_ISSET(clientSock, &readfds)){
			rec = recv(clientSock, (char *)pbInputBuffer, BUFFERSIZE, 0);
			if(rec == SOCKET_ERROR){
				err = WSAGetLastError();
				if(err == WSAEWOULDBLOCK){
					Sleep(5);
					continue;
				}
#ifdef _DEBUG
				printf("[I] recv error:%d\n", err);
#endif
				return -1;
			}else if(rec <= 0){
#ifdef _DEBUG
				printf("[I] recv error:%d\n", err);
#endif
				return -1;
			}else{
				ulInputLength = (ULONG)rec;
				hr = pSocks5Server->SendForwarderData(ulInputLength, pbInputBuffer, tv_sec, tv_usec);
				if(FAILED(hr)){
#ifdef _DEBUG
					printf("[I] SendForwarderData error:0x%x\n", hr);
#endif
					return -1;
				}
				ZeroMemory(pbInputBuffer, BUFFERSIZE);
				tv.tv_sec = tv_sec;
				tv.tv_usec = tv_usec;
				if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
					printf("[E] gettimeofday error\n");
#endif
					return -1;
				}
			}
		}
	}

	free(pbInputBuffer);
	return 0;
}


int forwarderSendData(void *ptr)
{
	pFPARAM pFParam = (pFPARAM)ptr;
	SOCKET clientSock = pFParam->clientSock;
	ISocks5Server *pSocks5Server = pFParam->pSocks5Server;
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

	HRESULT hr;
	ULONG ulOutputLength = 0;
	BYTE *pbOutputBuffer = NULL;


	if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
		printf("[E] gettimeofday error\n");
#endif
		return -1;
	}

	while(1){
		if(gettimeofday(&end, NULL) == -1){
#ifdef _DEBUG
			printf("[E] gettimeofday error\n");
#endif
			return -1;
		}

		t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
		if(t >= (tv_sec * 1000000 + tv_usec)){
#ifdef _DEBUG
			printf("[I] forwarderSendData timeout\n");
#endif
			return -1;
		}

		hr = pSocks5Server->RecvForwarderData(&ulOutputLength, &pbOutputBuffer, tv_sec, tv_usec);
		if(SUCCEEDED(hr) && ulOutputLength > 0){
			len = (int)ulOutputLength;
			sen = 0;
			sendLength = 0;
			tv.tv_sec = tv_sec;
			tv.tv_usec = tv_usec;

			while(len > 0){
				FD_ZERO(&writefds);
				FD_SET(clientSock, &writefds);

				ret = select(NULL, NULL, &writefds, NULL, &tv);
				if(ret == 0){
#ifdef _DEBUG
					printf("[I] forwarderSendData select timeout\n");
#endif
					CoTaskMemFree(pbOutputBuffer);
					pbOutputBuffer = NULL;
					return -1;
				}else if(ret == SOCKET_ERROR){
					err = WSAGetLastError();
#ifdef _DEBUG
					printf("[I] forwarderSendData select error:0x%x\n", err);
#endif
					CoTaskMemFree(pbOutputBuffer);
					pbOutputBuffer = NULL;
					return -1;
				}

				if(FD_ISSET(clientSock, &writefds)){
					sen = send(clientSock, (char *)pbOutputBuffer+sendLength, len, 0);
					if(sen == SOCKET_ERROR){
						err = WSAGetLastError();
						if(err == WSAEWOULDBLOCK){
							Sleep(5);
							continue;
						}
#ifdef _DEBUG
						printf("[E] send error:%d\n", err);
#endif
						CoTaskMemFree(pbOutputBuffer);
						pbOutputBuffer = NULL;
						return -1;
					}else if(sen < 0){
#ifdef _DEBUG
						printf("[E] send error:%d\n", err);
#endif
						CoTaskMemFree(pbOutputBuffer);
						pbOutputBuffer = NULL;
						return -1;
					}else{
						sendLength += sen;
						len -= sen;
					}
				}
			}
			CoTaskMemFree(pbOutputBuffer);
			pbOutputBuffer = NULL;

			if(gettimeofday(&start, NULL) == -1){
#ifdef _DEBUG
				printf("[E] gettimeofday error\n");
#endif
				return -1;
			}
		}else if(FAILED(hr)){
#ifdef _DEBUG
			printf("[I] RecvForwarderData error:0x%x\n", hr);
#endif
			CoTaskMemFree(pbOutputBuffer);
			pbOutputBuffer = NULL;
			return -1;
		}
	}

	return 0;
}


void forwarderRecvDataThread(void *ptr)
{
	int err = 0;

	err = forwarderRecvData(ptr);

	_endthread();
}


void forwarderSendDataThread(void *ptr)
{
	int err = 0;

	err = forwarderSendData(ptr);

	_endthread();
}


int forwarder(SOCKET clientSock, ISocks5Server *pSocks5Server, long tv_sec, long tv_usec)
{
	FPARAM fParam;
	fParam.clientSock = clientSock;
	fParam.pSocks5Server = pSocks5Server;
	fParam.tv_sec = tv_sec;
	fParam.tv_usec = tv_usec;
	HANDLE handle[2];


	handle[0] = (HANDLE)_beginthread(forwarderRecvDataThread, 0, &fParam);
	handle[1] = (HANDLE)_beginthread(forwarderSendDataThread, 0, &fParam);

	WaitForMultipleObjects(2, (const HANDLE *)handle, TRUE, INFINITE);

	return 0;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	SOCKET clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;
	free(ptr);

	char *targetDomainname = socks5TargetIp;
	u_short targetDomainnameLength = 0;
	if(targetDomainname != NULL){
		targetDomainnameLength = strlen(targetDomainname);
	}

	u_long ulMode = 1;	// non-blocking mode
	int ret = 0;
	int err = 0;
	int rec, sen;
	unsigned char method = 0;

	wchar_t targetDomainname_w[1024];
	HRESULT hr;
	COSERVERINFO csi;
//	COAUTHINFO cai;
	MULTI_QI mqi[] = { {&IID_ISocks5Server, NULL, S_OK} };
	ISocks5Server *pSocks5Server = NULL;
	ULONG ulInputLength = 0;
	ULONG ulOutputLength = 0;
	BYTE *pbInputBuffer = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));
	BYTE *pbOutputBuffer = NULL;


#ifdef _DEBUG
	printf("[I] Target domainname:%s, Length:%d\n", targetDomainname, targetDomainnameLength);
#endif
	mbstowcs(targetDomainname_w, targetDomainname, strlen(targetDomainname)+1);
	csi.dwReserved1 = 0;
	csi.pwszName = targetDomainname_w;	// target server
	csi.pAuthInfo = NULL;	//
	csi.dwReserved2 = 0;


#ifdef _DEBUG
	printf("[I] CoCreateInstanceEx\n");
#endif
	hr = CoCreateInstanceEx(CLSID_Socks5Server, NULL, CLSCTX_REMOTE_SERVER, &csi, 1, mqi);
	if(FAILED(hr) || FAILED(mqi[0].hr)){
#ifdef _DEBUG
		printf("[E] CoCreateInstanceEx error:0x%x\n", hr);
#endif
		free(pbInputBuffer);
		closesocket(clientSock);
		return 1;
	}

	pSocks5Server = static_cast<ISocks5Server *>(mqi[0].pItf);

#ifdef _DEBUG
	printf("[I] Connected\n");
#endif


	// socks SELECTION_REQUEST	client -> server
	if((rec = recvData(clientSock, (char *)pbInputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieve selection request error. client -> server\n");
#endif
		hr = pSocks5Server->Close();
		pSocks5Server->Release();
		free(pbInputBuffer);
		closesocket(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection request:%d bytes. client -> server\n", rec);
#endif


	// socks SELECTION_REQUEST	server -> target
	ulInputLength = (ULONG)rec;
	ulOutputLength = 0;
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", (int)ulInputLength);
#endif
	hr = pSocks5Server->SelectionRequestResponse(ulInputLength, pbInputBuffer, &ulOutputLength, &pbOutputBuffer);
	if(FAILED(hr)){
#ifdef _DEBUG
		printf("[E] SelectionRequestResponse error:0x%x\n", hr);
#endif
		hr = pSocks5Server->Close();
		pSocks5Server->Release();
		free(pbInputBuffer);
		closesocket(clientSock);
		return 1;
	}


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieve selection response:%d bytes. server <- target\n", (int)ulOutputLength);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)pbOutputBuffer;
	method = (unsigned char)pSelectionResponse->method;


	// socks SELECTION_RESPONSE	client <- server
	sen = sendData(clientSock, pbOutputBuffer, (int)ulOutputLength, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	CoTaskMemFree(pbOutputBuffer);
	pbOutputBuffer = NULL;
	if(method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(method == 0x2){	// USERNAME_PASSWORD_AUTHENTICATION
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		client -> server
		if((rec = recvData(clientSock, (char *)pbInputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
			printf("[E] Recieve username password authentication request error. client -> server\n");
#endif
			hr = pSocks5Server->Close();
			pSocks5Server->Release();
			free(pbInputBuffer);
			closesocket(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		server -> target
		ulInputLength = (ULONG)rec;
		ulOutputLength = 0;
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", (int)ulInputLength);
#endif
		hr = pSocks5Server->UsernamePasswordAuthenticationRequestResponse(ulInputLength, pbInputBuffer, &ulOutputLength, &pbOutputBuffer);
		if(FAILED(hr)){
#ifdef _DEBUG
			printf("[E] UsernamePasswordAuthenticationRequestResponse error:0x%x\n", hr);
#endif
			hr = pSocks5Server->Close();
			pSocks5Server->Release();
			free(pbInputBuffer);
			closesocket(clientSock);
			return 1;
		}


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieve username password authentication response:%d bytes. server <- target\n", (int)ulOutputLength);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
		sen = sendData(clientSock, (char *)pbOutputBuffer, (int)ulOutputLength, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
		CoTaskMemFree(pbOutputBuffer);
		pbOutputBuffer = NULL;
	}


	// socks SOCKS_REQUEST	client -> server
	if((rec = recvData(clientSock, (char *)pbInputBuffer, BUFFERSIZE, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieve socks request error. client -> server\n");
#endif
		hr = pSocks5Server->Close();
		pSocks5Server->Release();
		free(pbInputBuffer);
		closesocket(clientSock);
		return 1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks request:%d bytes. client -> server\n", rec);
#endif


	// socks SOCKS_REQUEST	server -> target
	ulInputLength = (ULONG)rec;
	ulOutputLength = 0;
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", (int)ulInputLength);
#endif
	hr = pSocks5Server->Socks5RequestResponse(ulInputLength, pbInputBuffer, &ulOutputLength, &pbOutputBuffer);
	if(FAILED(hr)){
#ifdef _DEBUG
		printf("[E] Socks5RequestResponse error:0x%x\n", hr);
#endif
		hr = pSocks5Server->Close();
		pSocks5Server->Release();
		free(pbInputBuffer);
		closesocket(clientSock);
		return 1;
	}


	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieve socks response:%d bytes. server <- target\n", (int)ulOutputLength);
#endif


	// socks SOCKS_RESPONSE	client <- server
	sen = sendData(clientSock, pbOutputBuffer, (int)ulOutputLength, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif
	CoTaskMemFree(pbOutputBuffer);
	pbOutputBuffer = NULL;


	err = ioctlsocket(clientSock, FIONBIO, &ulMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n", err);
#endif
		hr = pSocks5Server->Close();
		pSocks5Server->Release();
		free(pbInputBuffer);
		closesocket(clientSock);
		return 1;
	}


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder\n");
#endif
	err = forwarder(clientSock, pSocks5Server, forwarder_tv_sec, forwarder_tv_usec);


#ifdef _DEBUG
	printf("[I] Worker exit\n");
#endif
	hr = pSocks5Server->Close();
	pSocks5Server->Release();
	free(pbInputBuffer);
	closesocket(clientSock);
	return 0;
}


void workerThread(void *ptr)
{
	int err = 0;
	
	err = worker(ptr);
	
	_endthread();
}


void usage(char *filename)
{
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip\n", filename);
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10\n", filename);
	printf("             : %s -h localhost -p 9050 -H 192.168.0.10\n", filename);
	printf("             : %s -h ::1 -p 9050 -H 192.168.0.10 -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -A 30 -C 30\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%14 -p 9050 -H 192.168.0.10 -A 30 -C 30\n", filename);
}


int getopt(int argc, char **argv, char *optstring)
{

	unsigned char opt = '\0';
	unsigned char next = '\0';
	char *argtmp = NULL;

	while(1){
		opt = *(optstring + optstringIndex);
		optstringIndex++;
		if(opt == '\0'){
			break;
		}
	
		next = *(optstring + optstringIndex);
		if(next == ':'){
			optstringIndex++;
		}
	
		for(int i=1; i<argc; i++){
			argtmp = argv[i];
			if(argtmp[0] == '-'){
				if(argtmp[1] == opt){
					if(next == ':'){
						optarg = argv[i+1];
						return (int)opt;
					}else{
						return (int)opt;
					}
				}
			}
		}
	}

	return 0;
}


//int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
//int wmain(int argc, wchar_t * argv[])
int main(int argc, char** argv)
{

	int opt;
	char optstring[] = "h:p:H:A:B:C:D:";
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;

	while((opt=getopt(argc, argv, optstring)) > 0){
		switch(opt){
		case 'h':
			socks5ServerIp = optarg;
			break;
			
		case 'p':
			socks5ServerPort = optarg;
			break;
		
		case 'H':
			socks5TargetIp = optarg;
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
			usage(argv[0]);
			exit(1);
		}
	}

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetIp == NULL){
		usage(argv[0]);
		exit(1);
	}

	if(tv_sec < 0 || tv_sec > 10 || tv_usec < 0 || tv_usec > 1000000){
		tv_sec = 3;
		tv_usec = 0;
	}else if(tv_sec == 0 && tv_usec == 0){
		tv_sec = 3;
		tv_usec = 0;
	}

	if(forwarder_tv_sec < 0 || forwarder_tv_sec > 3600 || forwarder_tv_usec < 0 || forwarder_tv_usec > 1000000){
		forwarder_tv_sec = 3;
		forwarder_tv_usec = 0;
	}else if(forwarder_tv_sec == 0 && forwarder_tv_usec == 0){
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
	if(serverDomainname != NULL){
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

	pPARAM pParam;

	int ret = 0;
	int err = 0;

	HRESULT hr;


	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(err != 0){
#ifdef _DEBUG
		printf("[E] WSAStartup error:%d.\n", err);
#endif
		return -1;
	}

#ifdef _DEBUG
	printf("[I] CoInitializeEx\n");
#endif
	CoInitializeEx(NULL, COINIT_MULTITHREADED);

#ifdef _DEBUG
	printf("[I] CoInitializeSecurity\n");
#endif
	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_ANONYMOUS, NULL, EOAC_NONE, NULL);
	if(FAILED(hr)){
#ifdef _DEBUG
		printf("[E] CoInitializeSecurity error:0x%x\n", hr);
#endif
		CoUninitialize();
		WSACleanup();
		return 1;
	}

#ifdef _DEBUG
	printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
	printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif

	colon = strstr(serverDomainname, ":");	// check ipv6 address
	if(colon == NULL){	// ipv4 address or domainname
		hints.ai_family = AF_INET;	// IPv4
		if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
				CoUninitialize();
				WSACleanup();
				return -1;
			}
		}
	}else{	// ipv6 address
		hints.ai_family = AF_INET6;	// IPv6
		if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
			printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
			CoUninitialize();
			WSACleanup();
			return -1;
		}
	}

	if(serverHost->ai_family == AF_INET){
		family = AF_INET;
		serverAddr.sin_family = AF_INET;
		tmpIpv4 = (struct sockaddr_in *)serverHost->ai_addr;
		memcpy(&serverAddr.sin_addr, &tmpIpv4->sin_addr, sizeof(unsigned long));
		memcpy(&serverAddr.sin_port, &tmpIpv4->sin_port, 2);
		freeaddrinfo(serverHost);
	}else if(serverHost->ai_family == AF_INET6){
		family = AF_INET6;
		serverAddr6.sin6_family = AF_INET6;
		tmpIpv6 = (struct sockaddr_in6 *)serverHost->ai_addr;
		memcpy(&serverAddr6.sin6_addr, &tmpIpv6->sin6_addr, sizeof(struct in6_addr));
		memcpy(&serverAddr6.sin6_port, &tmpIpv6->sin6_port, 2);
		serverAddr6.sin6_scope_id = tmpIpv6->sin6_scope_id;
		freeaddrinfo(serverHost);
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented\n");
#endif
		freeaddrinfo(serverHost);
		CoUninitialize();
		WSACleanup();
		return -1;
	}

	if(family == AF_INET){	// IPv4
		serverSock = socket(AF_INET, SOCK_STREAM, 0);
		if(serverSock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			CoUninitialize();
			WSACleanup();
			return -1;
		}

		// bind
		err = bind(serverSock, (sockaddr *)&serverAddr, sizeof(serverAddr));
		if(err == SOCKET_ERROR) {
#ifdef _DEBUG
			printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
			CoUninitialize();
			WSACleanup();
			return -1;
		}

		// listen
		err = listen(serverSock, 5);
		if(err == SOCKET_ERROR){
#ifdef _DEBUG
			printf("[E] listen error:%d.\n", WSAGetLastError());
#endif
			closesocket(serverSock);
			CoUninitialize();
			WSACleanup();
			return -1;
			}
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n",  ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr, &clientAddrLen))){
#ifdef _DEBUG
			printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->clientSock = clientSock;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;

			_beginthread(workerThread, 0, pParam);
		}
	}else if(family == AF_INET6){	// IPv6
		serverSock = socket(AF_INET6, SOCK_STREAM, 0);
		if(serverSock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			CoUninitialize();
			WSACleanup();
			return -1;
		}

		// bind
		err = bind(serverSock, (sockaddr *)&serverAddr6, sizeof(serverAddr6));
		if(err == SOCKET_ERROR) {
#ifdef _DEBUG
			printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
			CoUninitialize();
			WSACleanup();
			return -1;
		}

		// listen
		err = listen(serverSock, 5);
		if(err == SOCKET_ERROR){
#ifdef _DEBUG
			printf("[E] listen error:%d.\n", WSAGetLastError());
#endif
			closesocket(serverSock);
			CoUninitialize();
			WSACleanup();
			return -1;
		}
#ifdef _DEBUG
		inet_ntop(AF_INET6, &serverAddr6.sin6_addr, serverAddr6StringPointer, INET6_ADDRSTRLEN);
		if(serverAddr6.sin6_scope_id > 0){
			printf("[I] Listening port %d on %s%%%d.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer, serverAddr6.sin6_scope_id);
		}else{
			printf("[I] Listening port %d on %s.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer);
		}
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr6, &clientAddr6Len))){
#ifdef _DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0){
				printf("[I] Connected from ip:%s%%%d port:%d.\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else{
				printf("[I] Connected from ip:%s port:%d.\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif

			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->clientSock = clientSock;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;

			_beginthread(workerThread, 0, pParam);
		}
	}

	closesocket(serverSock);
	CoUninitialize();
	WSACleanup();
	
	return 0;
}


/*
 * Title:  socks5 client (Windows)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <process.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "client.h"
#include "socks5.h"

#pragma comment(lib,"ws2_32.lib")	// Winsock Library
#pragma comment(lib,"libssl.lib")	// OpenSSL Library
#pragma comment(lib,"libcrypto.lib")	// OpenSSL Library

int optstringIndex = 0;
char *optarg = NULL;

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
char *socks5Server2Ip = NULL;
char *socks5Server2Port = NULL;
int reverseFlag = 0;
int tlsFlag = 0;
long tv_sec = 3;
long tv_usec = 0;

char serverCertificateFilename[256] = "server.crt";	// server certificate file name
char serverCertificateFileDirectoryPath[256] = ".";	// server certificate file directory path


int recvData(SOCKET socket, void *buffer, int length)
{
	int rec = 0;
	int err = 0;

	while(1){
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
	
	return rec;
}


int recvDataTls(SSL *ssl ,void *buffer, int length)
{
	int rec = 0;
	int err = 0;

	while(1){
		rec = SSL_read(ssl, buffer, length);
		err = SSL_get_error(ssl, rec);
		
		if(err == SSL_ERROR_NONE){
			break;
		}else if(err == SSL_ERROR_ZERO_RETURN){
			break;
		}else if(err == SSL_ERROR_WANT_READ){
			Sleep(5);
		}else if(err == SSL_ERROR_WANT_WRITE){
			Sleep(5);
		}else{
#ifdef _DEBUG
			printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			return -2;
		}
	}
	
	return rec;
}


int sendData(SOCKET socket, void *buffer, int length)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	int err = 0;
	
	while(len > 0){
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
	
	return sendLength;
}


int sendDataTls(SSL *ssl, void *buffer, int length)
{
	int sen = 0;
	int err = 0;

	while(1){
		sen = SSL_write(ssl, buffer, length);
		err = SSL_get_error(ssl, sen);
		
		if(err == SSL_ERROR_NONE){
			break;
		}else if(err == SSL_ERROR_WANT_WRITE){
			Sleep(5);
		}else if(err == SSL_ERROR_WANT_READ){
			Sleep(5);
		}else{
#ifdef _DEBUG
			printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			return -2;
		}
	}
		
	return sen;
}


int forwarder(SOCKET clientSock, SOCKET targetSock)
{
	int rec, sen;
	fd_set readfds;
	timeval tv;
	char buffer[BUFSIZ+1];
	ZeroMemory(buffer, BUFSIZ+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = recvData(clientSock, buffer, BUFSIZ)) > 0){
				sen = sendData(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = recvData(targetSock, buffer, BUFSIZ)) > 0){
				sen = sendData(clientSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
	}

	return 0;
}


int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *targetSsl)
{
	int rec, sen;
	fd_set readfds;
	timeval tv;
	char buffer[BUFSIZ+1];
	ZeroMemory(buffer, BUFSIZ+1);
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			if((rec = recvData(clientSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = SSL_write(targetSsl, buffer, rec);
					err = SSL_get_error(targetSsl, sen);
					
					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						Sleep(5);
					}else if(err == SSL_ERROR_WANT_READ){
						Sleep(5);
					}else{
#ifdef _DEBUG
						printf("[E] SSL_write error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
						return -2;
					}
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			rec = SSL_read(targetSsl, buffer, BUFSIZ);
			err = SSL_get_error(targetSsl, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = sendData(clientSock, buffer, rec);
				
				if(sen <= 0){
					break;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				Sleep(5);
			}else if(err == SSL_ERROR_WANT_WRITE){
				Sleep(5);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
	}

	return 0;
}


void finiSsl(pSSLPARAM pSslParam)
{
	// Socks5 over TLS
	if(pSslParam->targetSsl != NULL){
		SSL_shutdown(pSslParam->targetSsl);
		SSL_free(pSslParam->targetSsl);
	}
	if(pSslParam->targetCtx != NULL){
		SSL_CTX_free(pSslParam->targetCtx);
	}
	
	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	SOCKET targetSock = pParam->targetSock;
	SOCKET clientSock = pParam->clientSock;

	sockaddr_in targetAddr;
	u_long iMode = 1;	// non-blocking mode
	int ret = 0;
	int err = 0;
	
	SSL_CTX *targetCtx = NULL;
	SSL *targetSsl = pParam->targetSsl;
	
	SSLPARAM sslParam;
	sslParam.targetCtx = NULL;
	sslParam.targetSsl = NULL;
	
	int rec, sen;
	char buffer[BUFSIZ+1];
	ZeroMemory(buffer, BUFSIZ+1);
	
	if(reverseFlag == 0){	// Nomal mode

		targetAddr.sin_family = AF_INET;
		targetAddr.sin_addr.s_addr = inet_addr(socks5TargetIp);
		targetAddr.sin_port = htons(atoi(socks5TargetPort));

		targetSock = socket(AF_INET, SOCK_STREAM, 0);
		if(targetSock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			return -1;
		}
		
		err = connect(targetSock, (sockaddr *)&targetAddr, sizeof(targetAddr));
		if(err != 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d\n", WSAGetLastError());
#endif
			return -1;
		}

		if(tlsFlag == 1){
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

			// SSL TLS connection
			targetCtx = SSL_CTX_new(TLS_client_method());
			if(targetCtx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
#endif
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
			sslParam.targetCtx = targetCtx;

			SSL_CTX_set_mode(targetCtx, SSL_MODE_AUTO_RETRY);
			
			ret = SSL_CTX_set_min_proto_version(targetCtx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_set_default_verify_paths(targetCtx);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_default_verify_paths error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, serverCertificateFileDirectoryPath);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_load_verify_locations error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
			SSL_CTX_set_verify(targetCtx, SSL_VERIFY_PEER, NULL);
			
			targetSsl = SSL_new(targetCtx);
			if(targetSsl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
			sslParam.targetSsl = targetSsl;

			ret = SSL_set_fd(targetSsl, targetSock);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
			ret = SSL_connect(targetSsl);
			if(ret <= 0){
				err = SSL_get_error(targetSsl, ret);
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(clientSock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
		}
	}


	// socks SELECTION_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving selection request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving selection request error. client -> server\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection request:%d bytes. client -> server\n", rec);
#endif


	// socks SELECTION_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending selection request. server -> target\n");
#endif
	if(tlsFlag == 0){
		sen = sendData(targetSock, buffer, rec);
	}else{	// tls
		sen = sendDataTls(targetSsl, buffer, rec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(tlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ);
	}else{	// tls
		rec = recvDataTls(targetSsl, buffer, BUFSIZ);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection response:%d bytes. server <- target\n", rec);
#endif


	// socks SELECTION_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending selection response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)buffer;
	if((unsigned char)pSelectionResponse->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error.\n");
#endif
	}

	if(pSelectionResponse->method == 0x2){	// USERNAME_PASSWORD_AUTHENTICATION
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		client -> server
#ifdef _DEBUG
		printf("[I] Recieving username password authentication request. client -> server\n");
#endif
		if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication request error. client -> server\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(targetSock);
			}
			closesocket(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		server -> target
#ifdef _DEBUG
		printf("[I] Sending username password authentication request. server -> target\n");
#endif
		if(tlsFlag == 0){
			sen = sendData(targetSock, buffer, rec);
		}else{	// tls
			sen = sendDataTls(targetSsl, buffer, rec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(tlsFlag == 0){
			rec = recvData(targetSock, buffer, BUFSIZ);
		}else{	// tls
			rec = recvDataTls(targetSsl, buffer, BUFSIZ);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(targetSock);
			}
			closesocket(clientSock);
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
#ifdef _DEBUG
		printf("[I] Sending username password authentication response. client <- server\n");
#endif
		sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks SOCKS_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving socks request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFSIZ)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks request error. client -> server\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks request:%d bytes. client -> server\n", rec);
#endif


	// socks SOCKS_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending socks request. server -> target\n");
#endif
	if(tlsFlag == 0){
		sen = sendData(targetSock, buffer, rec);
	}else{	// tls
		sen = sendDataTls(targetSsl, buffer, rec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);
#endif
	
	
	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(tlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ);
	}else{	// tls
		rec = recvDataTls(targetSsl, buffer, BUFSIZ);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks response:%d bytes. server <- target\n", rec);
#endif


	// socks SOCKS_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending socks response. client <- server\n");
#endif
	sen = sendData(clientSock, buffer, rec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	err = ioctlsocket(clientSock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}

	err = ioctlsocket(targetSock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
		}
		closesocket(clientSock);
		return -1;
	}
	
	
	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(tlsFlag == 0){
		err = forwarder(clientSock, targetSock);
	}else{	// tls
		err = forwarderTls(clientSock, targetSock, targetSsl);
	}


	if(reverseFlag == 1){	// Reverse mode
		iMode = 0;	// blocking mode
		err = ioctlsocket(targetSock, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n.", err);
#endif
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
			closesocket(clientSock);
			return -2;
		}
	}
	

#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	if(reverseFlag == 0){	// Nomal mode
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		closesocket(targetSock);
	}
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
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]\n", filename);
	printf("example      : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s -t 1\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s -t 0 -u 500000\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]\n", filename);
	printf("example      : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s -t 1\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s -t 0 -u 500000\n", filename);
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
	char optstring[] = "rh:p:H:P:st:u:";

	while((opt=getopt(argc, argv, optstring)) > 0){
		switch(opt){
		case 'r':
			reverseFlag = 1;
			break;
			
		case 'h':
			socks5ServerIp = optarg;
			break;
			
		case 'p':
			socks5ServerPort = optarg;
			break;
		
		case 'H':
			socks5TargetIp = optarg;
			socks5Server2Ip = optarg;
			break;
			
		case 'P':
			socks5TargetPort = optarg;
			socks5Server2Port = optarg;
			break;

		case 's':
			tlsFlag = 1;
			break;

		case 't':
			tv_sec = atol(optarg);
			break;

		case 'u':
			tv_usec = atol(optarg);
			break;

		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetIp == NULL || socks5TargetPort == NULL || socks5Server2Ip == NULL || socks5Server2Port == NULL){
		usage(argv[0]);
		exit(1);
	}

	WSADATA wsaData;
	SOCKET serverSock = INVALID_SOCKET;
	SOCKET clientSock = INVALID_SOCKET;
	SOCKET server2Sock = INVALID_SOCKET;
	SOCKET targetSock = INVALID_SOCKET;
	sockaddr_in serverAddr, clientAddr, server2Addr, targetAddr;
	int clientAddrLen = sizeof(sockaddr);
	int targetAddrLen = sizeof(targetAddr);
	u_long iMode = 1;	// non-blocking mode

	PARAM param;
	
	SSL_CTX *targetCtx = NULL;
	SSL *targetSsl = NULL;
	
	SSLPARAM sslParam;
	sslParam.targetCtx = NULL;
	sslParam.targetSsl = NULL;

	int ret = 0;
	int err = 0;

	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if(err != 0){
#ifdef _DEBUG
		printf("[E] WSAStartup error:%d.\n", err);
#endif
		return -1;
	}

	if(reverseFlag == 0){	// Nomal mode
#ifdef _DEBUG
		printf("[I] Nomal mode.\n");
#endif
		if(tlsFlag == 1){
#ifdef _DEBUG
			printf("[I] Socks5 over TLS:on.\n");
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Socks5 over TLS:off.\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Forwarder timeout:%ld sec %ld microsec.\n", tv_sec, tv_usec);
#endif
		
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = inet_addr(socks5ServerIp);
		serverAddr.sin_port = htons(atoi(socks5ServerPort));
				
		serverSock = socket(AF_INET, SOCK_STREAM, 0);
		if(serverSock == INVALID_SOCKET){
#ifdef _DEBUG
			printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
			WSACleanup();
			return -1;
		}
		
		// bind
		err = bind(serverSock, (sockaddr *)&serverAddr, sizeof(serverAddr));
		if(err == SOCKET_ERROR) {
#ifdef _DEBUG
			printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
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
			WSACleanup();
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n",  ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr, &clientAddrLen))){
#ifdef _DEBUG
			printf("[I] Connected from %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif
			
			param.targetSock = targetSock;
			param.clientSock = clientSock;
			param.targetSsl = NULL;
			
			_beginthread(workerThread, 0, &param);
		}
		
		closesocket(serverSock);

	}else{	// Reverse mode
#ifdef _DEBUG
		printf("[I] Reverse mode.\n");
#endif
		if(tlsFlag == 1){
#ifdef _DEBUG
			printf("[I] Socks5 over TLS:on.\n");
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Socks5 over TLS:off.\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Forwarder timeout:%ld sec %ld microsec.\n", tv_sec, tv_usec);
#endif
		
		server2Addr.sin_family = AF_INET;
		server2Addr.sin_addr.s_addr = inet_addr(socks5Server2Ip);
		server2Addr.sin_port = htons(atoi(socks5Server2Port));

		server2Sock = socket(AF_INET, SOCK_STREAM, 0);

		// bind
		err = bind(server2Sock, (sockaddr *)&server2Addr, sizeof(server2Addr));
		if(err == SOCKET_ERROR) {
#ifdef _DEBUG
			printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
			WSACleanup();
			return -1;
		}
	
		// listen
		err = listen(server2Sock, 0);
		if(err == SOCKET_ERROR){
#ifdef _DEBUG
			printf("[E] listen error:%d.\n", WSAGetLastError());
#endif
			closesocket(server2Sock);
			WSACleanup();
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n", ntohs(server2Addr.sin_port), inet_ntoa(server2Addr.sin_addr));
#endif

		// accept
		targetSock = accept(server2Sock, (sockaddr *)&targetAddr, &targetAddrLen);
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(targetAddr.sin_addr));
#endif
		
		if(tlsFlag == 1){	// tls
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

			// SSL TLS connection
			targetCtx = SSL_CTX_new(TLS_client_method());
			if(targetCtx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
#endif
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}
			sslParam.targetCtx = targetCtx;

			SSL_CTX_set_mode(targetCtx, SSL_MODE_AUTO_RETRY);
			
			ret = SSL_CTX_set_min_proto_version(targetCtx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}

			ret = SSL_CTX_set_default_verify_paths(targetCtx);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_default_verify_paths error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, serverCertificateFileDirectoryPath);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_load_verify_locations error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}
			
			SSL_CTX_set_verify(targetCtx, SSL_VERIFY_PEER, NULL);
			
			targetSsl = SSL_new(targetCtx);
			if(targetSsl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}
			sslParam.targetSsl = targetSsl;
			
			ret = SSL_set_fd(targetSsl, targetSock);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_connect)\n");
#endif
			ret = SSL_connect(targetSsl);
			if(ret <= 0){
				err = SSL_get_error(targetSsl, ret);
#ifdef _DEBUG
				printf("[E] SSL_connect error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				finiSsl(&sslParam);
				closesocket(targetSock);
				closesocket(server2Sock);
				WSACleanup();
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_connect)\n");
#endif
		}
		
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = inet_addr(socks5ServerIp);
		serverAddr.sin_port = htons(atoi(socks5ServerPort));

		serverSock = socket(AF_INET, SOCK_STREAM, 0);
		
		// bind
		err = bind(serverSock, (sockaddr *) &serverAddr, sizeof(serverAddr));
		if(err == SOCKET_ERROR) {
#ifdef _DEBUG
			printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
			closesocket(server2Sock);
			closesocket(serverSock);
			WSACleanup();
			return -1;
		}
		
		// listen
		err = listen(serverSock, 0);
		if(err == SOCKET_ERROR){
#ifdef _DEBUG
			printf("[E] listen error:%d.\n", WSAGetLastError());
#endif
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
			closesocket(server2Sock);
			closesocket(serverSock);
			WSACleanup();
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

		// accept
		while((clientSock = accept(serverSock, (sockaddr *)&clientAddr, &clientAddrLen))){
#ifdef _DEBUG
			printf("[I] Connected from %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif
			
			param.targetSock = targetSock;
			param.clientSock = clientSock;
			param.targetSsl = targetSsl;
			
			err = worker(&param);
			if(err == -2){
				break;
			}
			
		}

		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		closesocket(targetSock);
		closesocket(server2Sock);
		closesocket(serverSock);
	}

	WSACleanup();
	
	return 0;
}


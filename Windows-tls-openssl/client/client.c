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

char serverCertificateFilename[256] = ".\\server.crt";	// server certificate file name


int recvData(SOCKET socket, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	ZeroMemory(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

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


int recvDataTls(SOCKET socket, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	ZeroMemory(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(socket, &readfds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(NULL, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvDataTls timeout.\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &readfds)){
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

	while(len > 0){
		FD_ZERO(&writefds);
		FD_SET(socket, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

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


int sendDataTls(SOCKET socket, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	timeval tv;

	while(1){
		FD_ZERO(&writefds);
		FD_SET(socket, &writefds);
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;

		if(select(NULL, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendDataTls timeout.\n");
#endif
			break;
		}

		if(FD_ISSET(socket, &writefds)){
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
	}
		
	return sen;
}


int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec)
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
			if((rec = recv(clientSock, buffer, BUFSIZ, 0)) > 0){
				sen = send(targetSock, buffer, rec, 0);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = recv(targetSock, buffer, BUFSIZ, 0)) > 0){
				sen = send(clientSock, buffer, rec, 0);
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


int forwarderTls(SOCKET clientSock, SOCKET targetSock, SSL *targetSsl, long tv_sec, long tv_usec)
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
			if((rec = recv(clientSock, buffer, BUFSIZ, 0)) > 0){
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
				sen = send(clientSock, buffer, rec, 0);
				
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
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;

	sockaddr_in targetAddr;
	sockaddr_in *tmpIpv4;
	sockaddr_in6 targetAddr6;
	sockaddr_in6 *tmpIpv6;
	addrinfo hints;
	addrinfo *targetHost;

	ZeroMemory(&targetAddr, sizeof(struct sockaddr_in));
	ZeroMemory(&targetAddr6, sizeof(struct sockaddr_in6));
	ZeroMemory(&hints, sizeof(struct addrinfo));

	char *targetDomainname = socks5TargetIp;
	u_short targetDomainnameLength = 0;
	if(targetDomainname != NULL){
		targetDomainnameLength = strlen(targetDomainname);
	}
	char *targetPortNumber = socks5TargetPort;
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *targetAddr6StringPointer = targetAddr6String;

	char *colon = NULL;
	int family = 0;
	int flags;
	int targetAddrLen = sizeof(targetAddr);
	int targetAddr6Len = sizeof(targetAddr6);

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
	
	free(ptr);
	
	
	if(reverseFlag == 0){	// Nomal mode
#ifdef _DEBUG
		printf("[I] Target domainname:%s, Length:%d\n", targetDomainname, targetDomainnameLength);
#endif
		colon = strstr(targetDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(targetDomainname, targetPortNumber, &hints, &targetHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(targetDomainname, targetPortNumber, &hints, &targetHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(targetDomainname, targetPortNumber, &hints, &targetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
				return -1;
			}
		}

		if(targetHost->ai_family == AF_INET){
			family = AF_INET;
			targetAddr.sin_family = AF_INET;
			tmpIpv4 = (struct sockaddr_in *)targetHost->ai_addr;
			memcpy(&targetAddr.sin_addr, &tmpIpv4->sin_addr, sizeof(unsigned long));
			memcpy(&targetAddr.sin_port, &tmpIpv4->sin_port, 2);
			freeaddrinfo(targetHost);
		}else if(targetHost->ai_family == AF_INET6){
			family = AF_INET6;
			targetAddr6.sin6_family = AF_INET6;
			tmpIpv6 = (struct sockaddr_in6 *)targetHost->ai_addr;
			memcpy(&targetAddr6.sin6_addr, &tmpIpv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&targetAddr6.sin6_port, &tmpIpv6->sin6_port, 2);
			targetAddr6.sin6_scope_id = tmpIpv6->sin6_scope_id;
			freeaddrinfo(targetHost);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			freeaddrinfo(targetHost);
			return -1;
		}

		if(family == AF_INET){	// IPv4
			targetSock = socket(AF_INET, SOCK_STREAM, 0);
			if(targetSock == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

			err = connect(targetSock, (sockaddr *)&targetAddr, sizeof(targetAddr));
			if(err != 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", WSAGetLastError());
#endif
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);
			if(targetSock == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
				return -1;
			}

#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connecting to ip:%s%%%d port:%d\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connecting to ip:%s port:%d\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif

			err = connect(targetSock, (sockaddr *)&targetAddr6, sizeof(targetAddr6));
			if(err != 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", WSAGetLastError());
#endif
				return -1;
			}

#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connected to ip:%s%%%d port:%d\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connected to ip:%s port:%d\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
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
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, NULL);
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
	if((rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
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
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{	// tls
		sen = sendDataTls(targetSock, targetSsl, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(tlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{	// tls
		rec = recvDataTls(targetSock, targetSsl, buffer, BUFSIZ, tv_sec, tv_usec);
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
	sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
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
		if((rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
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
			sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
		}else{	// tls
			sen = sendDataTls(targetSock, targetSsl, buffer, rec, tv_sec, tv_usec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(tlsFlag == 0){
			rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{	// tls
			rec = recvDataTls(targetSock, targetSsl, buffer, BUFSIZ, tv_sec, tv_usec);
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
		sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks SOCKS_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving socks request. client -> server\n");
#endif
	if((rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
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
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{	// tls
		sen = sendDataTls(targetSock, targetSsl, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);
#endif
	
	
	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(tlsFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{	// tls
		rec = recvDataTls(targetSock, targetSsl, buffer, BUFSIZ, tv_sec, tv_usec);
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
	sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
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
		err = forwarder(clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}else{	// tls
		err = forwarderTls(clientSock, targetSock, targetSsl, forwarder_tv_sec, forwarder_tv_usec);
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
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050\n", filename);
	printf("             : %s -h localhost -p 9050 -H 192.168.0.10 -P 9050 -s\n", filename);
	printf("             : %s -h ::1 -p 9050 -H 192.168.0.10 -P 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h 192.168.0.5 -p 9050 -H 192.168.0.10 -P 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%14 -p 9050 -H fe80::yyyy:yyyy:yyyy:yyyy%%14 -P 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -h localhost -p 9050 -H 192.168.0.5 -P 1234 -s\n", filename);
	printf("             : %s -r -h ::1 -p 9050 -H 192.168.0.5 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -h 192.168.0.5 -p 9050 -H 192.168.0.5 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%14 -p 9050 -H fe80::xxxx:xxxx:xxxx:xxxx%%14 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
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
	char optstring[] = "rh:p:H:P:sA:B:C:D:";
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;

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

	if(socks5ServerIp == NULL || socks5ServerPort == NULL || socks5TargetIp == NULL || socks5TargetPort == NULL || socks5Server2Ip == NULL || socks5Server2Port == NULL){
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
	SOCKET server2Sock = INVALID_SOCKET;
	SOCKET targetSock = INVALID_SOCKET;
	sockaddr_in serverAddr, clientAddr, server2Addr, targetAddr;
	sockaddr_in *tmpIpv4;
	sockaddr_in6 serverAddr6, clientAddr6, server2Addr6, targetAddr6;
	sockaddr_in6 *tmpIpv6;
	addrinfo hints, hints2;
	addrinfo *serverHost;
	addrinfo *server2Host;

	ZeroMemory(&serverAddr, sizeof(struct sockaddr_in));
	ZeroMemory(&clientAddr, sizeof(struct sockaddr_in));
	ZeroMemory(&server2Addr, sizeof(struct sockaddr_in));
	ZeroMemory(&targetAddr, sizeof(struct sockaddr_in));

	ZeroMemory(&serverAddr6, sizeof(struct sockaddr_in6));
	ZeroMemory(&clientAddr6, sizeof(struct sockaddr_in6));
	ZeroMemory(&server2Addr6, sizeof(struct sockaddr_in6));
	ZeroMemory(&targetAddr6, sizeof(struct sockaddr_in6));

	ZeroMemory(&hints, sizeof(struct addrinfo));
	ZeroMemory(&hints2, sizeof(struct addrinfo));

	char *serverDomainname = socks5ServerIp;
	u_short serverDomainnameLength = 0;
	if(serverDomainname != NULL){
		serverDomainnameLength = strlen(serverDomainname);
	}

	char *server2Domainname = socks5Server2Ip;
	u_short server2DomainnameLength = 0;
	if(server2Domainname != NULL){
		server2DomainnameLength = strlen(server2Domainname);
	}

	char *serverPortNumber = socks5ServerPort;
	char *server2PortNumber = socks5Server2Port;

	char serverAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *serverAddr6StringPointer = serverAddr6String;
	char clientAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *clientAddr6StringPointer = clientAddr6String;
	char server2Addr6String[INET6_ADDRSTRLEN+1] = {0};
	char *server2Addr6StringPointer = server2Addr6String;
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *targetAddr6StringPointer = targetAddr6String;

	char *colon = NULL;
	int family = 0;
	int flags;
	int clientAddrLen = sizeof(clientAddr);
	int clientAddr6Len = sizeof(clientAddr6);
	int targetAddrLen = sizeof(targetAddr);
	int targetAddr6Len = sizeof(targetAddr6);
	u_long iMode = 1;	// non-blocking mode

	pPARAM pParam;
	
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
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
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
			return -1;
		}

		if(family == AF_INET){	// IPv4
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
				printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->targetSsl = NULL;
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
				WSACleanup();
				return -1;
			}

			// bind
			err = bind(serverSock, (sockaddr *)&serverAddr6, sizeof(serverAddr6));
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
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->targetSsl = NULL;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				_beginthread(workerThread, 0, pParam);
			}
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
		printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif

		colon = strstr(server2Domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints2.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
				hints2.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					return -1;
				}
			}
		}else{	// ipv6 address
			hints2.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
				return -1;
			}
		}

		if(server2Host->ai_family == AF_INET){
			family = AF_INET;
			server2Addr.sin_family = AF_INET;
			tmpIpv4 = (struct sockaddr_in *)server2Host->ai_addr;
			memcpy(&server2Addr.sin_addr, &tmpIpv4->sin_addr, sizeof(unsigned long));
			memcpy(&server2Addr.sin_port, &tmpIpv4->sin_port, 2);
			freeaddrinfo(server2Host);
		}else if(server2Host->ai_family == AF_INET6){
			family = AF_INET6;
			server2Addr6.sin6_family = AF_INET6;
			tmpIpv6 = (struct sockaddr_in6 *)server2Host->ai_addr;
			memcpy(&server2Addr6.sin6_addr, &tmpIpv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&server2Addr6.sin6_port, &tmpIpv6->sin6_port, 2);
			server2Addr6.sin6_scope_id = tmpIpv6->sin6_scope_id;
			freeaddrinfo(server2Host);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			freeaddrinfo(server2Host);
			return -1;
		}

		if(family == AF_INET){	// IPv4
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
			err = listen(server2Sock, 5);
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
			printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			server2Sock = socket(AF_INET6, SOCK_STREAM, 0);

			// bind
			err = bind(server2Sock, (sockaddr *)&server2Addr6, sizeof(server2Addr6));
			if(err == SOCKET_ERROR) {
#ifdef _DEBUG
				printf("[E] bind error:%d.\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}

			// listen
			err = listen(server2Sock, 5);
			if(err == SOCKET_ERROR){
#ifdef _DEBUG
				printf("[E] listen error:%d.\n", WSAGetLastError());
#endif
				closesocket(server2Sock);
				WSACleanup();
				return -1;
			}
#ifdef _DEBUG
			inet_ntop(AF_INET6, &server2Addr6.sin6_addr, server2Addr6StringPointer, INET6_ADDRSTRLEN);
			if(server2Addr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d.\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer, server2Addr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s.\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer);
			}
#endif

			// accept
			targetSock = accept(server2Sock, (sockaddr *)&targetAddr6, &targetAddr6Len);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connected from ip:%s%%%d port:%d.\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connected from ip:%s port:%d.\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif
		}

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
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, NULL);
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

		colon = strstr(serverDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(targetSock);
					closesocket(server2Sock);
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
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(targetSock);
				closesocket(server2Sock);
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
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(targetSock);
			closesocket(server2Sock);
			WSACleanup();
			return -1;
		}

		if(family == AF_INET){	// IPv4
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
			err = listen(serverSock, 5);
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
				printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->targetSsl = targetSsl;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				err = worker(pParam);
				if(err == -2){
					break;
				}
			}
		}else if(family == AF_INET6){	// IPv6
			serverSock = socket(AF_INET6, SOCK_STREAM, 0);

			// bind
			err = bind(serverSock, (sockaddr *) &serverAddr6, sizeof(serverAddr6));
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
			err = listen(serverSock, 5);
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
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->targetSsl = targetSsl;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				err = worker(pParam);
				if(err == -2){
					break;
				}
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


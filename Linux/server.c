/*
 * Title:  socks5 server (Linux)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "socks5.h"
#include "server.h"
#include "serverkey.h"


char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5ClientIp = NULL;
char *socks5ClientPort = NULL;
int reverseFlag = 0;
int tlsFlag = 0;

static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
char username[256] = "socks5user";
char password[256] = "supersecretpassword";

char cipherSuiteTLS1_2[1000] = "AESGCM+ECDSA:CHACHA20+ECDSA:+AES256";	// TLS1.2
char cipherSuiteTLS1_3[1000] = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";	// TLS1.3


int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	bzero(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvData timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = recv(sock, buffer, length, 0);
			if(rec <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}else{
				break;
			}
		}
	}
	
	return rec;
}


int recvDataTls(int sock, SSL *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int err = 0;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	bzero(buffer, length+1);

	while(1){
		FD_ZERO(&readfds);
		FD_SET(sock, &readfds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] recvDataTls timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = SSL_read(ssl, buffer, length);
			err = SSL_get_error(ssl, rec);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
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


int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;
	
	while(len > 0){
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendData timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = send(sock, buffer+sendLength, len, 0);
			if(sen <= 0){
				if(errno == EINTR){
					continue;
				}else if(errno == EAGAIN){
					usleep(5000);
					continue;
				}else{
					return -1;
				}
			}
			sendLength += sen;
			len -= sen;
		}
	}
	
	return sendLength;
}


int sendDataTls(int sock, SSL *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int err = 0;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;

	while(1){
		FD_ZERO(&writefds);
		FD_SET(sock, &writefds);
		nfds = sock + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, NULL, &writefds, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] sendDataTls timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &writefds)){
			sen = SSL_write(ssl, buffer, length);
			err = SSL_get_error(ssl, sen);
			
			if(err == SSL_ERROR_NONE){
				break;
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
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


int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
						
		if(FD_ISSET(clientSock, &readfds)){	
			if((rec = read(clientSock, buffer, BUFSIZ)) > 0){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				sen = write(clientSock, buffer, rec);
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


int forwarderTls(int clientSock, int targetSock, SSL *clientSsl, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	int nfds = -1;
	struct timeval tv;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	int err = 0;
	
	while(1){
		FD_ZERO(&readfds);
		FD_SET(clientSock, &readfds);
		FD_SET(targetSock, &readfds);
		nfds = (clientSock > targetSock ? clientSock : targetSock) + 1;
		tv.tv_sec = tv_sec;
		tv.tv_usec = tv_usec;
		
		if(select(nfds, &readfds, NULL, NULL, &tv) == 0){
#ifdef _DEBUG
			printf("[I] Forwarder timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(clientSock, &readfds)){
			rec = SSL_read(clientSsl, buffer, BUFSIZ);
			err = SSL_get_error(clientSsl, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = write(targetSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else if(err == SSL_ERROR_ZERO_RETURN){
				break;
			}else if(err == SSL_ERROR_WANT_READ){
				usleep(5000);
			}else if(err == SSL_ERROR_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] SSL_read error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				return -2;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = SSL_write(clientSsl, buffer, rec);
					err = SSL_get_error(clientSsl, sen);

					if(err == SSL_ERROR_NONE){
						break;
					}else if(err == SSL_ERROR_WANT_WRITE){
						usleep(5000);
					}else if(err == SSL_ERROR_WANT_READ){
						usleep(5000);
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
	}
	
	return 0;
}


int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
		
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendData(clientSock, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv4Tls(int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
	
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendDataTls(clientSock, clientSsl, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT
	
	sen = sendData(clientSock, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
	
	free(pSocksResponseIpv6);

	return sen;
}


int sendSocksResponseIpv6Tls(int clientSock, SSL *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT
	
	sen = sendDataTls(clientSock, clientSsl, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
						
	free(pSocksResponseIpv6);

	return sen;
}


void finiSsl(pSSLPARAM pSslParam)
{
	// Socks5 over TLS
	if(pSslParam->clientSsl != NULL){
		SSL_shutdown(pSslParam->clientSsl);
		SSL_free(pSslParam->clientSsl);
	}
	if(pSslParam->clientCtx != NULL){
		SSL_CTX_free(pSslParam->clientCtx);
	}
	
	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;

	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	int rec, sen;
	int ret = 0;
	int err = 0;
	int count = 0;

	SSL_CTX *clientCtx = NULL;
	SSL *clientSsl = pParam->clientSsl;
	BIO *bio = NULL;
	EVP_PKEY *sprivatekey = NULL;
	X509 *scert = NULL;

	SSLPARAM sslParam;
	sslParam.clientCtx = NULL;
	sslParam.clientSsl = NULL;

	if(reverseFlag == 0 && tlsFlag == 1){	// Normal mode and tls
		// Initialize
		OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
		
		// SSL TLS connection
		clientCtx = SSL_CTX_new(TLS_server_method());
		if(clientCtx == NULL){
#ifdef _DEBUG
			printf("[E] SSL_CTX_new error.\n");
#endif
			close(clientSock);
			return -2;
		}
		sslParam.clientCtx = clientCtx;

		// server private key
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, serverPrivateKey, strlen(serverPrivateKey));
		PEM_read_bio_PrivateKey(bio, &sprivatekey, NULL, NULL);
		BIO_free(bio);
		
		// server X509 certificate
		bio = BIO_new(BIO_s_mem());
		BIO_write(bio, serverCertificate, strlen(serverCertificate));
		PEM_read_bio_X509(bio, &scert, NULL, NULL);
		BIO_free(bio);

		ret = SSL_CTX_use_certificate(clientCtx, scert);
		if(ret != 1){
#ifdef _DEBUG
			printf("[E] SSL_CTX_use_certificate error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		
		ret = SSL_CTX_use_PrivateKey(clientCtx, sprivatekey);
		if(ret != 1){
#ifdef _DEBUG
			printf("[E] SSL_CTX_use_PrivateKey error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		
		ret = SSL_CTX_check_private_key(clientCtx);
		if(ret != 1){
#ifdef _DEBUG
			printf("[E] SSL_CTX_check_private_key error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		
		SSL_CTX_set_mode(clientCtx, SSL_MODE_AUTO_RETRY);
		
		ret = SSL_CTX_set_min_proto_version(clientCtx, TLS1_2_VERSION);
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		
		ret = SSL_CTX_set_cipher_list(clientCtx, cipherSuiteTLS1_2);
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_cipher_list error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}

		ret = SSL_CTX_set_ciphersuites(clientCtx, cipherSuiteTLS1_3);
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_CTX_set_ciphersuites error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		
		clientSsl = SSL_new(clientCtx);
		if(clientSsl == NULL){
#ifdef _DEBUG
			printf("[E] SSL_new error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
		sslParam.clientSsl = clientSsl;
		
		ret = SSL_set_fd(clientSsl, clientSock);
		if(ret == 0){
#ifdef _DEBUG
			printf("[E] SSL_set_fd error.\n");
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}

#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_accept)\n");
#endif
		// accept
		ret = SSL_accept(clientSsl);
		if(ret <= 0){
			err = SSL_get_error(clientSsl, ret);
#ifdef _DEBUG
			printf("[E] SSL_accept error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
			finiSsl(&sslParam);
			close(clientSock);
			return -2;
		}
#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (SSL_accept)\n");
#endif
	}

	
	// socks SELECTION_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving selection request.\n");
#endif
	do{
		if(tlsFlag == 0){
			if(reverseFlag == 0){
				rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
			}else{
				rec = recvData(clientSock, buffer, BUFSIZ, 3600, 0);
			}
		}else{
			if(reverseFlag == 0){
				rec = recvDataTls(clientSock, clientSsl, buffer, BUFSIZ, tv_sec, tv_usec);
			}else{
				rec = recvDataTls(clientSock, clientSsl, buffer, BUFSIZ, 3600, 0);
			}
		}
		
		if(rec == -1 || rec == -2){
			break;
		}
	}while((rec > 0 && rec < 3) || rec > 257);

	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Cannot receive selection request.\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		
		if(reverseFlag == 0){
			return -1;
		}else{
			return -2;
		}
	}

#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes.\n", rec);
#endif
	pSELECTION_REQUEST pSelectionRequest = (pSELECTION_REQUEST)buffer;
	unsigned char method = 0xFF;
	for(int i=0; i<pSelectionRequest->nmethods; i++){
		if(pSelectionRequest->methods[i] == 0x0 || pSelectionRequest->methods[i] == 0x2){	// NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
			method = pSelectionRequest->methods[i];
			break;
		}
	}
	if(method == 0xFF){
#ifdef _DEBUG
		printf("[E] Selection request method error.\n");
#endif
	}


	// socks SELECTION_RESPONSE
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)malloc(sizeof(SELECTION_RESPONSE));
	pSelectionResponse->ver = 0x5;		// socks version 5
	pSelectionResponse->method = method;	// no authentication required or username/password 
	if(pSelectionRequest->ver != 0x5 || authenticationMethod != method){
		pSelectionResponse->method = 0xFF;
	}
	if(tlsFlag == 0){
		sen = sendData(clientSock, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}else{
		sen = sendDataTls(clientSock, clientSsl, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}
	free(pSelectionResponse);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes.\n", sen);
#endif
	
	if(authenticationMethod != method){
#ifdef _DEBUG
		printf("[E] Authentication method error. server:0x%x client:0x%x\n", authenticationMethod, method);
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
	
	
	// socks USERNAME_PASSWORD_AUTHENTICATION
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST
#ifdef _DEBUG
		printf("[I] Receiving username password authentication request.\n");
#endif
		if(tlsFlag == 0){
			rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{
			rec = recvDataTls(clientSock, clientSsl, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receiving username password authentication request error.\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes.\n", rec);
#endif
		pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP pUsernamePasswordAuthenticationRequest = (pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP)buffer;

		ulen = pUsernamePasswordAuthenticationRequest->ulen;
		memcpy(uname, &pUsernamePasswordAuthenticationRequest->uname, ulen);
		memcpy(&plen, &pUsernamePasswordAuthenticationRequest->uname + ulen, 1);
		memcpy(passwd, &pUsernamePasswordAuthenticationRequest->uname + ulen + 1, plen);
#ifdef _DEBUG
		printf("[I] uname:%s, ulen:%d, passwd:%s, plen:%d\n", uname, ulen, passwd, plen);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE
		pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE pUsernamePasswordAuthenticationResponse = (pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE)malloc(sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE));
		pUsernamePasswordAuthenticationResponse->ver = 0x1;
		
		if(pUsernamePasswordAuthenticationRequest->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password))){
#ifdef _DEBUG
			printf("[I] Succeed username password authentication.\n");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0x0;
		
			if(tlsFlag == 0){
				sen = sendData(clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{
				sen = sendDataTls(clientSock, clientSsl, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
			
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
		}else{
#ifdef _DEBUG
			printf("[E] Fail username password authentication.\n");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0xFF;
			
			if(tlsFlag == 0){
				sen = sendData(clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{
				sen = sendDataTls(clientSock, clientSsl, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
			if(reverseFlag == 0){	// Nomal mode
				finiSsl(&sslParam);
				if(tlsFlag == 1){	// tls
					close(clientSock);
				}
			}
			return -1;
		}
	}	
	
	
	// socks SOCKS_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving socks request.\n");
#endif
	bzero(buffer, BUFSIZ+1);
	if(tlsFlag == 0){
		rec = recvData(clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataTls(clientSock, clientSsl, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receiving socks request error.\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes.\n", rec);
#endif
	
	pSOCKS_REQUEST pSocksRequest = (pSOCKS_REQUEST)buffer;
	pSOCKS_REQUEST_IPV4 pSocksRequestIpv4;
	pSOCKS_REQUEST_DOMAINNAME pSocksRequestDomainname;
	pSOCKS_REQUEST_IPV6 pSocksRequestIpv6;
	
	char atyp = pSocksRequest->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		printf("[E] Socks request atyp(%d) error.\n", atyp);
		printf("[E] Not implemented.\n");
#endif
		
		// socks SOCKS_RESPONSE send error
		if(tlsFlag == 0){
			sen = sendSocksResponseIpv4(clientSock, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
	
	char cmd = pSocksRequest->cmd;
	if(cmd != 0x1){	// CONNECT only
#ifdef _DEBUG
		printf("[E] Socks request cmd(%d) error.\n", cmd);
		printf("[E] Not implemented.\n");
#endif
		
		// socks SOCKS_RESPONSE send error
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
		
	struct sockaddr_in targetAddr, *pTmpIpv4;		// IPv4
	memset(&targetAddr, 0, sizeof(struct sockaddr_in));
	
	struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// IPv6
	memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));
	
	struct addrinfo hints, *pTargetHost;
	memset(&hints, 0, sizeof(struct addrinfo));
	
	int family = 0;
	char domainname[256] = {0};
	u_short domainnameLength = 0;
	char *colon;
	
	if(pSocksRequest->atyp == 0x1){	// IPv4
		family = AF_INET;
		targetAddr.sin_family = AF_INET;
		pSocksRequestIpv4 = (pSOCKS_REQUEST_IPV4)buffer;
		memcpy(&targetAddr.sin_addr.s_addr, &pSocksRequestIpv4->dstAddr, 4);
		memcpy(&targetAddr.sin_port, &pSocksRequestIpv4->dstPort, 2);
	}else if(pSocksRequest->atyp == 0x3){	// domain name		
		pSocksRequestDomainname = (pSOCKS_REQUEST_DOMAINNAME)buffer;
		domainnameLength = pSocksRequestDomainname->dstAddrLen;
		memcpy(&domainname, &pSocksRequestDomainname->dstAddr, domainnameLength);
#ifdef _DEBUG
		printf("[I] Domainname:%s, Length:%d.\n", domainname, domainnameLength);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
#endif
					
					// socks SOCKS_RESPONSE send error
					if(tlsFlag == 0){
						sen = sendSocksResponseIpv4(clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						close(clientSock);
					}
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s.\n", (char *)domainname);
#endif
				
				// socks SOCKS_RESPONSE send error
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}
		}
		
		if(pTargetHost->ai_family == AF_INET){
			family = AF_INET;
			targetAddr.sin_family = AF_INET;
			pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
			memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
			memcpy(&targetAddr.sin_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);
			freeaddrinfo(pTargetHost);
		}else if(pTargetHost->ai_family == AF_INET6){
			family = AF_INET6;
			targetAddr6.sin6_family = AF_INET6;
			pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
			memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&targetAddr6.sin6_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);			
			freeaddrinfo(pTargetHost);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			// socks SOCKS_RESPONSE send error
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			freeaddrinfo(pTargetHost);
			return -1;
		}
	}else if(pSocksRequest->atyp == 0x4){	// IPv6
		family = AF_INET6;
		targetAddr6.sin6_family = AF_INET6;
		pSocksRequestIpv6 = (pSOCKS_REQUEST_IPV6)buffer;
		memcpy(&targetAddr6.sin6_addr, &pSocksRequestIpv6->dstAddr, 16);
		memcpy(&targetAddr6.sin6_port, &pSocksRequestIpv6->dstPort, 2);
	}else {
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		
		// socks SOCKS_RESPONSE send error
		if(tlsFlag == 0){
			sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
	
	
	// socks SOCKS_RESPONSE	
	int targetSock;
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *pTargetAddr6String = targetAddr6String;
	int flags = 0;
	
	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
			targetSock = socket(AF_INET, SOCK_STREAM, 0);
			
			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				
				close(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
			
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
				targetSock = socket(AF_INET, SOCK_STREAM, 0);
				
				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);
				
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(tlsFlag == 0){
						sen = sendSocksResponseIpv4(clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					close(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						close(clientSock);
					}
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
				targetSock = socket(AF_INET6, SOCK_STREAM, 0);

				flags = fcntl(targetSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);
			
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(tlsFlag == 0){
						sen = sendSocksResponseIpv6(clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					close(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						close(clientSock);
					}
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif				
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}		
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);
			
			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

				close(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					close(clientSock);
				}
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE.\n");
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				close(clientSock);
			}
			return -1;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented.\n");
#endif
		
		if(tlsFlag == 0){
			sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Tls(clientSock, clientSsl, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			close(clientSock);
		}
		return -1;
	}
	
	
	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(tlsFlag == 0){
		err = forwarder(clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}else{
		err = forwarderTls(clientSock, targetSock, clientSsl, forwarder_tv_sec, forwarder_tv_usec);
		if(reverseFlag == 1 && err == -2){
			close(targetSock);
			return -2;
		}
	}

#ifdef _DEBUG	
	printf("[I] Worker exit.\n");
#endif
	close(targetSock);
	if(reverseFlag == 0){	// Nomal mode
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		close(clientSock);
	}

	return 0;
}

void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h listen_ip -p listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 9050\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9050 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -H socks5client_ip -P socks5client_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -H 192.168.0.5 -P 1234 -s\n", filename);
	printf("             : %s -r -H 192.168.0.5 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
}

int main(int argc, char **argv)
{

	int opt;
	const char* optstring = "rh:p:H:P:sA:B:C:D:";
	opterr = 0;
	long tv_sec = 3;	// recv send
	long tv_usec = 0;	// recv send
	long forwarder_tv_sec = 3;
	long forwarder_tv_usec = 0;

	while((opt=getopt(argc, argv, optstring)) != -1){
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
			socks5ClientIp = optarg;
			break;
			
		case 'P':
			socks5ClientPort = optarg;
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

	if(reverseFlag == 0 && socks5ServerIp == NULL || reverseFlag == 0 && socks5ServerPort == NULL || reverseFlag == 1 && socks5ClientIp == NULL || reverseFlag == 1 && socks5ClientPort == NULL){
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

	int serverSock, clientSock;
	struct sockaddr_in serverAddr, clientAddr;
	int reuse = 1;
	int clientAddrLen = sizeof(clientAddr);
	int flags;
	int ret = 0;
	int err = 0;
	
	SSL_CTX *clientCtx = NULL;
	SSL *clientSsl = NULL;
	BIO *bio = NULL;
	EVP_PKEY *sprivatekey = NULL;
	X509 *scert = NULL;

	PARAM param;

	SSLPARAM sslParam;
	sslParam.clientCtx = NULL;
	sslParam.clientSsl = NULL;

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
	
		serverAddr.sin_family = AF_INET;
		serverAddr.sin_addr.s_addr = inet_addr(socks5ServerIp);
		serverAddr.sin_port = htons(atoi(socks5ServerPort));
		
		serverSock = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
		
		// bind
		if(bind(serverSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
			printf("[E] bind error.\n");
#endif
			return -1;
		}
		
		// listen
		listen(serverSock, 5);
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

		// accept
		while((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen))){
#ifdef _DEBUG
			printf("[I] Connected from %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif
			
			flags = fcntl(clientSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(clientSock, F_SETFL, flags);
			
			pthread_t thread;
			
			param.clientSock = clientSock;
			param.clientSsl = NULL;
			param.tv_sec = tv_sec;
			param.tv_usec = tv_usec;
			param.forwarder_tv_sec = forwarder_tv_sec;
			param.forwarder_tv_usec = forwarder_tv_usec;
			
			if(pthread_create(&thread, NULL, (void *)worker, &param)){
#ifdef _DEBUG
				printf("[E] pthread_create failed.\n");
#endif
				close(clientSock);
			}else{
				pthread_detach(thread);
			}
		}

		close(serverSock);

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
		
		clientAddr.sin_family = AF_INET;
		clientAddr.sin_addr.s_addr = inet_addr(socks5ClientIp);
		clientAddr.sin_port = htons(atoi(socks5ClientPort));

		clientSock = socket(AF_INET, SOCK_STREAM, 0);
	
		flags = fcntl(clientSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(clientSock, F_SETFL, flags);

#ifdef _DEBUG
		printf("[I] Connecting to %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif
		
		if((err = connect(clientSock, (struct sockaddr *)&clientAddr, sizeof(clientAddr))) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d", err);
#endif
			return -1;
		}
#ifdef _DEBUG
		printf("[I] Connected to %s.\n", inet_ntoa(clientAddr.sin_addr));
#endif

		if(tlsFlag == 1){	// tls
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
			
			// SSL TLS connection
			clientCtx = SSL_CTX_new(TLS_server_method());
			if(clientCtx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
#endif
				close(clientSock);
				return -2;
			}
			sslParam.clientCtx = NULL;

			// server private key
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, serverPrivateKey, strlen(serverPrivateKey));
			PEM_read_bio_PrivateKey(bio, &sprivatekey, NULL, NULL);
			BIO_free(bio);
			
			// server X509 certificate
			bio = BIO_new(BIO_s_mem());
			BIO_write(bio, serverCertificate, strlen(serverCertificate));
			PEM_read_bio_X509(bio, &scert, NULL, NULL);
			BIO_free(bio);

			ret = SSL_CTX_use_certificate(clientCtx, scert);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_certificate error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_use_PrivateKey(clientCtx, sprivatekey);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_use_PrivateKey error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_check_private_key(clientCtx);
			if(ret != 1){
#ifdef _DEBUG
				printf("[E] SSL_CTX_check_private_key error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			SSL_CTX_set_mode(clientCtx, SSL_MODE_AUTO_RETRY);
			
			ret = SSL_CTX_set_min_proto_version(clientCtx, TLS1_2_VERSION);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_min_proto_version error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_set_cipher_list(clientCtx, cipherSuiteTLS1_2);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_cipher_list error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_set_ciphersuites(clientCtx, cipherSuiteTLS1_3);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_ciphersuites error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			
			clientSsl = SSL_new(clientCtx);
			if(clientSsl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
			sslParam.clientSsl = clientSsl;
			
			ret = SSL_set_fd(clientSsl, clientSock);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (SSL_accept)\n");
#endif
			// accept
			ret = SSL_accept(clientSsl);
			if(ret <= 0){
				err = SSL_get_error(clientSsl, ret);
#ifdef _DEBUG
				printf("[E] SSL_accept error:%d:%s.\n", err, ERR_error_string(ERR_peek_last_error(), NULL));
#endif
				finiSsl(&sslParam);
				close(clientSock);
				return -2;
			}
#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (SSL_accept)\n");
#endif
		}

		param.clientSock = clientSock;
		param.clientSsl = clientSsl;
		param.tv_sec = tv_sec;
		param.tv_usec = tv_usec;
		param.forwarder_tv_sec = forwarder_tv_sec;
		param.forwarder_tv_usec = forwarder_tv_usec;
		
		while(1){
			err = worker(&param);
			if(err == -2){
				break;
			}
		}
		
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		close(clientSock);

	}

	return 0;
}


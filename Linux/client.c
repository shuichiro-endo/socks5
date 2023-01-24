/*
 * Title:  socks5 client (Linux)
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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "client.h"
#include "socks5.h"


char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
char *socks5Server2Ip = NULL;
char *socks5Server2Port = NULL;
int reverseFlag = 0;
int tlsFlag = 0;
long tv_sec = 300;
long tv_usec = 0;

char serverCertificateFilename[256] = "server.crt";	// server certificate file name
char serverCertificateFileDirectoryPath[256] = ".";	// server certificate file directory path


int recvData(int sock, void *buffer, int length)
{
	int rec = 0;

	while(1){
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
	
	return rec;
}


int sendData(int sock, void *buffer, int length)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	
	while(len > 0){
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
		
	return sen;
}


int forwarder(int clientSock, int targetSock)
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


int forwarderTls(int clientSock, int targetSock, SSL *targetSsl)
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
			if((rec = read(clientSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = SSL_write(targetSsl, buffer, rec);
					err = SSL_get_error(targetSsl, sen);
					
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
		
		if(FD_ISSET(targetSock, &readfds)){
			rec = SSL_read(targetSsl, buffer, BUFSIZ);
			err = SSL_get_error(targetSsl, rec);
			
			if(err == SSL_ERROR_NONE){
				sen = write(clientSock, buffer, rec);
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
	int targetSock = pParam->targetSock;
	int clientSock = pParam->clientSock;
	
	struct sockaddr_in targetAddr;
	int flags;
	int ret = 0;
	int err = 0;
	
	SSL_CTX *targetCtx = NULL;
	SSL *targetSsl = pParam->targetSsl;

	SSLPARAM sslParam;
	sslParam.targetCtx = NULL;
	sslParam.targetSsl = NULL;
	
	int rec, sen;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
	if(reverseFlag == 0){	// Nomal mode
		targetAddr.sin_family = AF_INET;
		targetAddr.sin_addr.s_addr = inet_addr(socks5TargetIp);
		targetAddr.sin_port = htons(atoi(socks5TargetPort));

		targetSock = socket(AF_INET, SOCK_STREAM, 0);
				
		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);
					
		if(err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr)) < 0){
#ifdef _DEBUG
			printf("[E] Connect failed. errno:%d", err);
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
				close(targetSock);
				close(clientSock);
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
				close(targetSock);
				close(clientSock);
				return -2;
			}

			ret = SSL_CTX_set_default_verify_paths(targetCtx);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_default_verify_paths error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(clientSock);
				return -2;
			}
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, serverCertificateFileDirectoryPath);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_load_verify_locations error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(clientSock);
				return -2;
			}
			
			SSL_CTX_set_verify(targetCtx, SSL_VERIFY_PEER, NULL);
			
			targetSsl = SSL_new(targetCtx);
			if(targetSsl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(clientSock);
				return -2;
			}
			sslParam.targetSsl = targetSsl;
			
			ret = SSL_set_fd(targetSsl, targetSock);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(clientSock);
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
				close(targetSock);
				close(clientSock);
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
			close(targetSock);
		}
		close(clientSock);
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
			close(targetSock);
		}
		close(clientSock);
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
				close(targetSock);
			}
			close(clientSock);
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
				close(targetSock);
			}
			close(clientSock);
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
			close(targetSock);
		}
		close(clientSock);
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
			close(targetSock);
		}
		close(clientSock);
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


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(tlsFlag == 0){
		err = forwarder(clientSock, targetSock);
	}else{	// tls
		err = forwarderTls(clientSock, targetSock, targetSsl);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	if(reverseFlag == 0){	// Nomal mode
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		close(targetSock);
	}
	close(clientSock);

	return 0;
}

void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s -t 1\n", filename);
	printf("             : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050 -s -t 0 -u 500000\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-t tv_sec(forwarder timeout sec) [-u tv_usec(forwarder timeout microsec)]\n", filename);
	printf("example      : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s -t 1\n", filename);
	printf("             : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234 -s -t 0 -u 500000\n", filename);
}

int main(int argc, char **argv)
{

	int opt;
	const char* optstring = "rh:p:H:P:st:u:";
	opterr = 0;

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

	int serverSock, clientSock, server2Sock;
	int targetSock = -1;
	struct sockaddr_in serverAddr, clientAddr, server2Addr, targetAddr;
	int reuse = 1;
	int flags;
	int targetAddrLen = sizeof(targetAddr);
	int clientAddrLen = sizeof(clientAddr);

	PARAM param;
	
	SSL_CTX *targetCtx = NULL;
	SSL *targetSsl = NULL;
	
	SSLPARAM sslParam;
	sslParam.targetCtx = NULL;
	sslParam.targetSsl = NULL;

	int ret = 0;
	int err = 0;

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

			param.targetSock = targetSock;
			param.clientSock = clientSock;
			param.targetSsl = NULL;
			
			if(pthread_create(&thread, NULL, (void *)worker, &param))
			{
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
		printf("[I] Forwarder timeout:%ld sec %ld microsec.\n", tv_sec, tv_usec);
#endif

		server2Addr.sin_family = AF_INET;
		server2Addr.sin_addr.s_addr = inet_addr(socks5Server2Ip);
		server2Addr.sin_port = htons(atoi(socks5Server2Port));

		server2Sock = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(server2Sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
			
		// bind
		if(bind(server2Sock, (struct sockaddr *)&server2Addr, sizeof(server2Addr)) == -1) {
#ifdef _DEBUG
			printf("[E] bind error.\n");
#endif
			return -1;
		}
	
		// listen
		listen(server2Sock, 0);
#ifdef _DEBUG
		printf("[I] Listenning port %d on %s.\n", ntohs(server2Addr.sin_port), inet_ntoa(server2Addr.sin_addr));
#endif

		// accept
		targetSock = accept(server2Sock, (struct sockaddr *)&targetAddr, (socklen_t *)&targetAddrLen);
#ifdef _DEBUG
		printf("[I] Connected from %s.\n", inet_ntoa(targetAddr.sin_addr));
#endif

		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);

		if(tlsFlag == 1){	// tls
			// Initialize
			OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);

			// SSL TLS connection
			targetCtx = SSL_CTX_new(TLS_client_method());
			if(targetCtx == NULL){
#ifdef _DEBUG
				printf("[E] SSL_CTX_new error.\n");
#endif
				close(targetSock);
				close(server2Sock);
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
				close(targetSock);
				close(server2Sock);
				return -2;
			}

			ret = SSL_CTX_set_default_verify_paths(targetCtx);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_set_default_verify_paths error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
			
			ret = SSL_CTX_load_verify_locations(targetCtx, serverCertificateFilename, serverCertificateFileDirectoryPath);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_CTX_load_verify_locations error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
			
			SSL_CTX_set_verify(targetCtx, SSL_VERIFY_PEER, NULL);
			
			targetSsl = SSL_new(targetCtx);
			if(targetSsl == NULL){
#ifdef _DEBUG
				printf("[E] SSL_new error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
			sslParam.targetSsl = targetSsl;

			ret = SSL_set_fd(targetSsl, targetSock);
			if(ret == 0){
#ifdef _DEBUG
				printf("[E] SSL_set_fd error.\n");
#endif
				finiSsl(&sslParam);
				close(targetSock);
				close(server2Sock);
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
				close(targetSock);
				close(server2Sock);
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
		setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
		
		// bind
		if(bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
			printf("[E] bind error.\n");
#endif
			finiSsl(&sslParam);
			close(targetSock);
			close(server2Sock);
			close(serverSock);
			return -1;
		}
		
		// listen
		listen(serverSock, 0);
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
		close(targetSock);
		close(server2Sock);
		close(clientSock);
		close(serverSock);

	}

	return 0;
}


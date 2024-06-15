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
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

#include "client.h"
#include "socks5.h"
#include "servercrt.h"

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
char *socks5Server2Ip = NULL;
char *socks5Server2Port = NULL;
int reverseFlag = 0;
int tlsFlag = 0;

char serverCertificateFilename[256] = "./server.crt";	// server certificate filepath

char servername[MBEDTLS_SSL_MAX_HOST_NAME_LEN] = "socks5";


static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void) level);

	fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
	fflush((FILE *)ctx);
}


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


int recvDataTls(int sock, mbedtls_ssl_context *ssl ,void *buffer, int length, long tv_sec, long tv_usec)
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
			printf("[I] recvDataTls timeout.\n");
#endif
			break;
		}
		
		if(FD_ISSET(sock, &readfds)){
			rec = mbedtls_ssl_read(ssl, buffer, length);
			if(rec > 0){
				break;
			}else if(rec == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
				break;
			}else if(rec == MBEDTLS_ERR_SSL_WANT_READ){
				usleep(5000);
			}else if(rec == MBEDTLS_ERR_SSL_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_read error:%d\n", rec);
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


int sendDataTls(int sock, mbedtls_ssl_context *ssl, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
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
			sen = mbedtls_ssl_write(ssl, buffer, length);
			if(sen > 0){
				break;
			}else if(sen == MBEDTLS_ERR_SSL_WANT_WRITE){
				usleep(5000);
			}else if(sen == MBEDTLS_ERR_SSL_WANT_READ){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_write error:%d\n", sen);
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


int forwarderTls(int clientSock, int targetSock, mbedtls_ssl_context *targetSsl, long tv_sec, long tv_usec)
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
				while(1){
					sen = mbedtls_ssl_write(targetSsl, buffer, rec);
					if(sen > 0){
						break;
					}else if(sen == MBEDTLS_ERR_SSL_WANT_WRITE){
						usleep(5000);
					}else if(sen == MBEDTLS_ERR_SSL_WANT_READ){
						usleep(5000);
					}else{
#ifdef _DEBUG
						printf("[E] mbedtls_ssl_write error:%d\n", sen);
#endif
						return -2;
					}
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			rec = mbedtls_ssl_read(targetSsl, buffer, BUFSIZ);
			if(rec > 0){
				sen = write(clientSock, buffer, rec);
				if(sen <= 0){
					break;
				}
			}else if(rec == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY){
				break;
			}else if(rec == MBEDTLS_ERR_SSL_WANT_READ){
				usleep(5000);
			}else if(rec == MBEDTLS_ERR_SSL_WANT_WRITE){
				usleep(5000);
			}else{
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_read error:%d\n", rec);
#endif
				return -2;
			}
		}
	}

	return 0;
}


void finiSsl(pSSLPARAM pSslParam, int sslConnected)
{
	int ret = 0;

	if(sslConnected == 1){
		while((ret = mbedtls_ssl_close_notify(pSslParam->pTargetSslCtx)) != 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				break;
			}
		}
	}

	if(pSslParam->pCacrt != NULL){
		mbedtls_x509_crt_free(pSslParam->pCacrt);
	}

	if(pSslParam->pCtrDrbgCtx != NULL){
		mbedtls_ctr_drbg_free(pSslParam->pCtrDrbgCtx);
	}

	if(pSslParam->pEntropyCtx != NULL){
		mbedtls_entropy_free(pSslParam->pEntropyCtx);
	}

	if(pSslParam->pTargetSslCtx != NULL){
		mbedtls_ssl_free(pSslParam->pTargetSslCtx);
	}

	if(pSslParam->pTargetSslCfg != NULL){
		mbedtls_ssl_config_free(pSslParam->pTargetSslCfg);
	}

	if(pSslParam->pTargetNetCtx != NULL){
		mbedtls_net_free(pSslParam->pTargetNetCtx);
	}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int targetSock = pParam->targetSock;
	int clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;
	
	struct sockaddr_in targetAddr;
	struct sockaddr_in *tmpIpv4;
	struct sockaddr_in6 targetAddr6;
	struct sockaddr_in6 *tmpIpv6;
	struct addrinfo hints;
	struct addrinfo *targetHost;

	bzero(&targetAddr, sizeof(struct sockaddr_in));
	bzero(&targetAddr6, sizeof(struct sockaddr_in6));
	bzero(&hints, sizeof(struct addrinfo));

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
	int ret = 0;
	int err = 0;
	int targetAddrLen = sizeof(targetAddr);
	int targetAddr6Len = sizeof(targetAddr6);

	const char *pers = "socks5_client";
	uint32_t result;

	mbedtls_net_context targetNetCtx;
	mbedtls_entropy_context entropyCtx;
	mbedtls_ctr_drbg_context ctrDrbgCtx;
	mbedtls_ssl_context targetSslCtx;
	mbedtls_ssl_config targetSslCfg;
	mbedtls_x509_crt cacrt;

	SSLPARAM sslParam;
	sslParam.pTargetNetCtx = NULL;
	sslParam.pEntropyCtx = NULL;
	sslParam.pCtrDrbgCtx = NULL;
	sslParam.pTargetSslCtx = NULL;
	sslParam.pTargetSslCfg = NULL;
	sslParam.pCacrt = NULL;

	mbedtls_ssl_context *pTargetSslCtx = NULL;
	if(reverseFlag == 1){	// Reverse mode
		pTargetSslCtx = pParam->pTargetSslCtx;
	}

	int rec, sen;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
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

			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

			if(err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);

			flags = fcntl(targetSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connecting to ip:%s%%%d port:%d\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connecting to ip:%s port:%d\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif

			if(err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6)) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
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
			// initialize
			mbedtls_net_init(&targetNetCtx);
			mbedtls_ssl_init(&targetSslCtx);
			mbedtls_ssl_config_init(&targetSslCfg);
			mbedtls_x509_crt_init(&cacrt);
			mbedtls_ctr_drbg_init(&ctrDrbgCtx);
			mbedtls_entropy_init(&entropyCtx);

			sslParam.pTargetNetCtx = &targetNetCtx;
			sslParam.pEntropyCtx = &entropyCtx;
			sslParam.pCtrDrbgCtx = &ctrDrbgCtx;
			sslParam.pTargetSslCtx = &targetSslCtx;
			sslParam.pTargetSslCfg = &targetSslCfg;
			sslParam.pCacrt = &cacrt;

			pTargetSslCtx = &targetSslCtx;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
			psa_status_t status = psa_crypt_init();
			if(status != PSA_SUCCESS){
#ifdef _DEBUG
				printf("[E] psa_crypt_init error:%d\n", (int)status);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

			ret = mbedtls_ctr_drbg_seed(&ctrDrbgCtx, mbedtls_entropy_func, &entropyCtx, (const unsigned char *)pers, strlen(pers));
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ctr_drbg_seed error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}
/*
			ret = mbedtls_x509_crt_parse(&cacrt, (const unsigned char *)serverCertificate, strlen(serverCertificate)+1);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_x509_crt_parse error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}
*/
			ret = mbedtls_x509_crt_parse_file(&cacrt, (const char *)serverCertificateFilename);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_x509_crt_parse_file error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}

			targetNetCtx.fd = targetSock;

			// ssl configuration
			ret = mbedtls_ssl_config_defaults(&targetSslCfg, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_config_defaults error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}

//			mbedtls_ssl_conf_authmode(&targetSslCfg, MBEDTLS_SSL_VERIFY_OPTIONAL);
			mbedtls_ssl_conf_authmode(&targetSslCfg, MBEDTLS_SSL_VERIFY_REQUIRED);
			mbedtls_ssl_conf_ca_chain(&targetSslCfg, &cacrt, NULL);
			mbedtls_ssl_conf_rng(&targetSslCfg, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
			mbedtls_ssl_conf_dbg(&targetSslCfg, my_debug, stdout);

			ret = mbedtls_ssl_setup(&targetSslCtx, &targetSslCfg);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_setup error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}
/*
			ret = mbedtls_ssl_set_hostname(&targetSslCtx, servername);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_set_hostname error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(clientSock);
				return -2;
			}
*/
			mbedtls_ssl_set_bio(&targetSslCtx, &targetNetCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

			// handshake
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
#endif
			while((ret = mbedtls_ssl_handshake(&targetSslCtx)) != 0){
				if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
#ifdef _DEBUG
					printf("[E] mbedtls_ssl_handshake error:-0x%x\n", (unsigned int)-ret);
#endif
					finiSsl(&sslParam, 0);
					close(targetSock);
					close(clientSock);
					return -2;
				}
			}

			// verify the server certificate
			result = mbedtls_ssl_get_verify_result(&targetSslCtx);
			if(result != 0){
				char vrfy_buf[512];
				mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", result);
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_get_verify_result error\n");
				printf("%s\n", vrfy_buf);
#endif
				finiSsl(&sslParam, 1);
				close(targetSock);
				close(clientSock);
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
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
				finiSsl(&sslParam, 1);
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
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{	// tls
		sen = sendDataTls(targetSock, pTargetSslCtx, buffer, rec, tv_sec, tv_usec);
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
		rec = recvDataTls(targetSock, pTargetSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
					finiSsl(&sslParam, 1);
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
			sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
		}else{	// tls
			sen = sendDataTls(targetSock, pTargetSslCtx, buffer, rec, tv_sec, tv_usec);
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
			rec = recvDataTls(targetSock, pTargetSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				finiSsl(&sslParam, 1);
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
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{	// tls
		sen = sendDataTls(targetSock, pTargetSslCtx, buffer, rec, tv_sec, tv_usec);
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
		rec = recvDataTls(targetSock, pTargetSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
	sen = sendData(clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder.\n");
#endif
	if(tlsFlag == 0){
		err = forwarder(clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}else{	// tls
		err = forwarderTls(clientSock, targetSock, pTargetSslCtx, forwarder_tv_sec, forwarder_tv_usec);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	if(reverseFlag == 0){	// Nomal mode
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam, 1);
		}
		close(targetSock);
	}
	close(clientSock);

	return 0;
}

void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050\n", filename);
	printf("             : %s -h localhost -p 9050 -H 192.168.0.10 -P 9050 -s\n", filename);
	printf("             : %s -h ::1 -p 9050 -H 192.168.0.10 -P 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -H fe80::yyyy:yyyy:yyyy:yyyy%%eth0 -P 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234\n", filename);
	printf("             : %s -r -h localhost -p 9050 -H 0.0.0.0 -P 1234 -s\n", filename);
	printf("             : %s -r -h ::1 -p 9050 -H 0.0.0.0 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
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
	
	int serverSock, clientSock, server2Sock;
	int targetSock = -1;
	struct sockaddr_in serverAddr, clientAddr, server2Addr, targetAddr;
	struct sockaddr_in *tmpIpv4;
	struct sockaddr_in6 serverAddr6, clientAddr6, server2Addr6, targetAddr6;
	struct sockaddr_in6 *tmpIpv6;
	struct addrinfo hints, hints2;
	struct addrinfo *serverHost;
	struct addrinfo *server2Host;

	bzero(&serverAddr, sizeof(struct sockaddr_in));
	bzero(&clientAddr, sizeof(struct sockaddr_in));
	bzero(&server2Addr, sizeof(struct sockaddr_in));
	bzero(&targetAddr, sizeof(struct sockaddr_in));

	bzero(&serverAddr6, sizeof(struct sockaddr_in6));
	bzero(&clientAddr6, sizeof(struct sockaddr_in6));
	bzero(&server2Addr6, sizeof(struct sockaddr_in6));
	bzero(&targetAddr6, sizeof(struct sockaddr_in6));

	bzero(&hints, sizeof(struct addrinfo));
	bzero(&hints2, sizeof(struct addrinfo));

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
	int reuse = 1;
	int flags;
	int clientAddrLen = sizeof(clientAddr);
	int clientAddr6Len = sizeof(clientAddr6);
	int targetAddrLen = sizeof(targetAddr);
	int targetAddr6Len = sizeof(targetAddr6);

	pPARAM pParam;
	
	const char *pers = "socks5_client";
	uint32_t result;

	mbedtls_net_context targetNetCtx;
	mbedtls_entropy_context entropyCtx;
	mbedtls_ctr_drbg_context ctrDrbgCtx;
	mbedtls_ssl_context targetSslCtx;
	mbedtls_ssl_config targetSslCfg;
	mbedtls_x509_crt cacrt;
	
	SSLPARAM sslParam;
	sslParam.pTargetNetCtx = NULL;
	sslParam.pEntropyCtx = NULL;
	sslParam.pCtrDrbgCtx = NULL;
	sslParam.pTargetSslCtx = NULL;
	sslParam.pTargetSslCfg = NULL;
	sslParam.pCacrt = NULL;

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
			reuse = 1;
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
				printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

				flags = fcntl(clientSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(clientSock, F_SETFL, flags);

				pthread_t thread;

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->pTargetSslCtx = NULL;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				if(pthread_create(&thread, NULL, (void *)worker, pParam))
				{
#ifdef _DEBUG
					printf("[E] pthread_create failed.\n");
#endif
					close(clientSock);
				}else{
					pthread_detach(thread);
				}
			}
		}else if(family == AF_INET6){	// IPv6
			serverSock = socket(AF_INET6, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error.\n");
#endif
				return -1;
			}

			// listen
			listen(serverSock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &serverAddr6.sin6_addr, serverAddr6StringPointer, INET6_ADDRSTRLEN);
			if(serverAddr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer, serverAddr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer);
			}
#endif

			// accept
			while((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len))){
#ifdef _DEBUG
				inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
				if(clientAddr6.sin6_scope_id > 0){
					printf("[I] Connected from ip:%s%%%d port:%d.\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
				}else{
					printf("[I] Connected from ip:%s port:%d.\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
				}
#endif

				flags = fcntl(clientSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(clientSock, F_SETFL, flags);

				pthread_t thread;

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->pTargetSslCtx = NULL;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				if(pthread_create(&thread, NULL, (void *)worker, pParam))
				{
#ifdef _DEBUG
					printf("[E] pthread_create failed.\n");
#endif
					close(clientSock);
				}else{
					pthread_detach(thread);
				}
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
			reuse = 1;
			setsockopt(server2Sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(server2Sock, (struct sockaddr *)&server2Addr, sizeof(server2Addr)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error.\n");
#endif
				return -1;
			}

			// listen
			listen(server2Sock, 5);
#ifdef _DEBUG
			printf("[I] Listenning port %d on %s.\n", ntohs(server2Addr.sin_port), inet_ntoa(server2Addr.sin_addr));
#endif

			// accept
			targetSock = accept(server2Sock, (struct sockaddr *)&targetAddr, (socklen_t *)&targetAddrLen);
#ifdef _DEBUG
			printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			server2Sock = socket(AF_INET6, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(server2Sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(server2Sock, (struct sockaddr *)&server2Addr6, sizeof(server2Addr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error.\n");
#endif
				return -1;
			}

			// listen
			listen(server2Sock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &server2Addr6.sin6_addr, server2Addr6StringPointer, INET6_ADDRSTRLEN);
			if(server2Addr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d.\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer, server2Addr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s.\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer);
			}
#endif

			// accept
			targetSock = accept(server2Sock, (struct sockaddr *)&targetAddr6, (socklen_t *)&targetAddr6Len);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connected from ip:%s%%%d port:%d.\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connected from ip:%s port:%d.\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif
		}

		flags = fcntl(targetSock, F_GETFL, 0);
		flags &= ~O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);

		if(tlsFlag == 1){	// tls
			// initialize
			mbedtls_net_init(&targetNetCtx);
			mbedtls_ssl_init(&targetSslCtx);
			mbedtls_ssl_config_init(&targetSslCfg);
			mbedtls_x509_crt_init(&cacrt);
			mbedtls_ctr_drbg_init(&ctrDrbgCtx);
			mbedtls_entropy_init(&entropyCtx);

			sslParam.pTargetNetCtx = &targetNetCtx;
			sslParam.pEntropyCtx = &entropyCtx;
			sslParam.pCtrDrbgCtx = &ctrDrbgCtx;
			sslParam.pTargetSslCtx = &targetSslCtx;
			sslParam.pTargetSslCfg = &targetSslCfg;
			sslParam.pCacrt = &cacrt;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
			psa_status_t status = psa_crypt_init();
			if(status != PSA_SUCCESS){
#ifdef _DEBUG
				printf("[E] psa_crypt_init error:%d\n", (int)status);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

			ret = mbedtls_ctr_drbg_seed(&ctrDrbgCtx, mbedtls_entropy_func, &entropyCtx, (const unsigned char *)pers, strlen(pers));
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ctr_drbg_seed error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
/*
			ret = mbedtls_x509_crt_parse(&cacrt, (const unsigned char *)serverCertificate, strlen(serverCertificate)+1);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_x509_crt_parse error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
*/
			ret = mbedtls_x509_crt_parse_file(&cacrt, (const char *)serverCertificateFilename);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_x509_crt_parse_file error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}

			targetNetCtx.fd = targetSock;

			// ssl configuration
			ret = mbedtls_ssl_config_defaults(&targetSslCfg, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_config_defaults error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}

//			mbedtls_ssl_conf_authmode(&targetSslCfg, MBEDTLS_SSL_VERIFY_OPTIONAL);
			mbedtls_ssl_conf_authmode(&targetSslCfg, MBEDTLS_SSL_VERIFY_REQUIRED);
			mbedtls_ssl_conf_ca_chain(&targetSslCfg, &cacrt, NULL);
			mbedtls_ssl_conf_rng(&targetSslCfg, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
			mbedtls_ssl_conf_dbg(&targetSslCfg, my_debug, stdout);

			ret = mbedtls_ssl_setup(&targetSslCtx, &targetSslCfg);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_setup error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
/*
			ret = mbedtls_ssl_set_hostname(&targetSslCtx, servername);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_set_hostname error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(targetSock);
				close(server2Sock);
				return -2;
			}
*/
			mbedtls_ssl_set_bio(&targetSslCtx, &targetNetCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

			// handshake
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
#endif
			while((ret = mbedtls_ssl_handshake(&targetSslCtx)) != 0){
				if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
#ifdef _DEBUG
					printf("[E] mbedtls_ssl_handshake error:-0x%x\n", (unsigned int)-ret);
#endif
					finiSsl(&sslParam, 0);
					close(targetSock);
					close(server2Sock);
					return -2;
				}
			}

			// verify the server certificate
			result = mbedtls_ssl_get_verify_result(&targetSslCtx);
			if(result != 0){
				char vrfy_buf[512];
				mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", result);
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_get_verify_result error\n");
				printf("%s\n", vrfy_buf);
#endif
				finiSsl(&sslParam, 1);
				close(targetSock);
				close(server2Sock);
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
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
						finiSsl(&sslParam, 1);
					}
					close(targetSock);
					close(server2Sock);
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
					finiSsl(&sslParam, 1);
				}
				close(targetSock);
				close(server2Sock);
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
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
			}
			close(targetSock);
			close(server2Sock);
			return -1;
		}

		if(family == AF_INET){	// IPv4
			serverSock = socket(AF_INET, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error.\n");
#endif
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
				}
				close(targetSock);
				close(server2Sock);
				close(serverSock);
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
				printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

				flags = fcntl(clientSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(clientSock, F_SETFL, flags);

				pthread_t thread;

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->pTargetSslCtx = &targetSslCtx;
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
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *) &serverAddr6, sizeof(serverAddr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error.\n");
#endif
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
				}
				close(targetSock);
				close(server2Sock);
				close(serverSock);
				return -1;
			}

			// listen
			listen(serverSock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &serverAddr6.sin6_addr, serverAddr6StringPointer, INET6_ADDRSTRLEN);
			if(serverAddr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer, serverAddr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s.\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer);
			}
#endif

			// accept
			while((clientSock = accept(serverSock, (struct sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len))){
#ifdef _DEBUG
				inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
				if(clientAddr6.sin6_scope_id > 0){
					printf("[I] Connected from ip:%s%%%d port:%d.\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
				}else{
					printf("[I] Connected from ip:%s port:%d.\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
				}
#endif

				flags = fcntl(clientSock, F_GETFL, 0);
				flags &= ~O_NONBLOCK;
				fcntl(clientSock, F_SETFL, flags);

				pthread_t thread;

				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->targetSock = targetSock;
				pParam->clientSock = clientSock;
				pParam->pTargetSslCtx = &targetSslCtx;
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
			finiSsl(&sslParam, 1);
		}
		close(targetSock);
		close(server2Sock);
		close(clientSock);
		close(serverSock);

	}

	return 0;
}


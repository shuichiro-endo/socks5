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

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif /* MBEDTLS_SSL_CACHE_C */

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

// ciphersuite	/usr/include/mbedtls/ssl_ciphersuites.h
int ciphersuites[] = {
//MBEDTLS_TLS1_3_AES_256_GCM_SHA384,		// mbedtls v3.5.2
//MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256,	// mbedtls v3.5.2
//MBEDTLS_TLS1_3_AES_128_GCM_SHA256,		// mbedtls v3.5.2
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
0};


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


int forwarderTls(int clientSock, int targetSock, mbedtls_ssl_context *clientSsl, long tv_sec, long tv_usec)
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
			rec = mbedtls_ssl_read(clientSsl, buffer, BUFSIZ);
			if(rec > 0){
				sen = write(targetSock, buffer, rec);
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
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = read(targetSock, buffer, BUFSIZ)) > 0){
				while(1){
					sen = mbedtls_ssl_write(clientSsl, buffer, rec);
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


int sendSocksResponseIpv4Tls(int clientSock, mbedtls_ssl_context *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
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


int sendSocksResponseIpv6Tls(int clientSock, mbedtls_ssl_context *clientSsl, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
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


void finiSsl(pSSLPARAM pSslParam, int sslConnected)
{
	int ret = 0;

	if(sslConnected == 1){
		while((ret = mbedtls_ssl_close_notify(pSslParam->pClientSslCtx)) != 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
				break;
			}
		}
	}

	if(pSslParam->pServerCrt != NULL){
		mbedtls_x509_crt_free(pSslParam->pServerCrt);
	}

	if(pSslParam->pServerKey != NULL){
		mbedtls_pk_free(pSslParam->pServerKey);
	}

#if defined(MBEDTLS_SSL_CACHE_C)
	if(pSslParam->pCache != NULL){
		mbedtls_ssl_cache_free(pSslParam->pCache);
	}
#endif /* MBEDTLS_SSL_CACHE_C */

	if(pSslParam->pCtrDrbgCtx != NULL){
		mbedtls_ctr_drbg_free(pSslParam->pCtrDrbgCtx);
	}

	if(pSslParam->pEntropyCtx != NULL){
		mbedtls_entropy_free(pSslParam->pEntropyCtx);
	}

	if(pSslParam->pClientSslCtx != NULL){
		mbedtls_ssl_free(pSslParam->pClientSslCtx);
	}

	if(pSslParam->pClientSslCfg != NULL){
		mbedtls_ssl_config_free(pSslParam->pClientSslCfg);
	}

	if(pSslParam->pClientNetCtx != NULL){
		mbedtls_net_free(pSslParam->pClientNetCtx);
	}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
	mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */
	
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

	const char *pers = "socks5_server";
	uint32_t result;

	mbedtls_net_context clientNetCtx;
	mbedtls_entropy_context entropyCtx;
	mbedtls_ctr_drbg_context ctrDrbgCtx;
	mbedtls_ssl_context clientSslCtx;
	mbedtls_ssl_config clientSslCfg;
	mbedtls_x509_crt serverCrt;
	mbedtls_pk_context serverKey;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif /* MBEDTLS_SSL_CACHE_C */

	SSLPARAM sslParam;
	sslParam.pClientNetCtx = NULL;
	sslParam.pEntropyCtx = NULL;
	sslParam.pCtrDrbgCtx = NULL;
	sslParam.pClientSslCtx = NULL;
	sslParam.pClientSslCfg = NULL;
	sslParam.pServerCrt = NULL;
	sslParam.pServerKey = NULL;
	sslParam.pCache = NULL;

	mbedtls_ssl_context *pClientSslCtx = NULL;
	if(reverseFlag == 1){	// Reverse mode
		pClientSslCtx = pParam->pClientSslCtx;
	}
	
	free(ptr);
	
	
	if(reverseFlag == 0 && tlsFlag == 1){	// Normal mode and tls
		// initialize
		mbedtls_net_init(&clientNetCtx);
		mbedtls_entropy_init(&entropyCtx);
		mbedtls_ctr_drbg_init(&ctrDrbgCtx);
		mbedtls_ssl_init(&clientSslCtx);
		mbedtls_ssl_config_init(&clientSslCfg);
		mbedtls_x509_crt_init(&serverCrt);
		mbedtls_pk_init(&serverKey);
#if defined(MBEDTLS_SSL_CACHE_C)
		mbedtls_ssl_cache_init(&cache);
#endif /* MBEDTLS_SSL_CACHE_C */

		sslParam.pClientNetCtx = &clientNetCtx;
		sslParam.pEntropyCtx = &entropyCtx;
		sslParam.pCtrDrbgCtx = &ctrDrbgCtx;
		sslParam.pClientSslCtx = &clientSslCtx;
		sslParam.pClientSslCfg = &clientSslCfg;
		sslParam.pServerCrt = &serverCrt;
		sslParam.pServerKey = &serverKey;
#if defined(MBEDTLS_SSL_CACHE_C)
		sslParam.pCache = &cache;
#endif /* MBEDTLS_SSL_CACHE_C */

		pClientSslCtx = &clientSslCtx;

#if defined(MBEDTLS_USE_PSA_CRYPTO)
		psa_status_t status = psa_crypt_init();
		if(status != PSA_SUCCESS){
#ifdef _DEBUG
			printf("[E] psa_crypt_init error:%d\n", (int)status);
#endif
			finiSsl(&sslParam, 0);
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
			close(clientSock);
			return -2;
		}

		ret = mbedtls_x509_crt_parse(&serverCrt, (const unsigned char *)serverCertificate, strlen(serverCertificate)+1);
		if(ret != 0){
#ifdef _DEBUG
			printf("[E] mbedtls_x509_crt_parse error:-0x%x\n", (unsigned int)-ret);
#endif
			finiSsl(&sslParam, 0);
			close(clientSock);
			return -2;
		}

//		ret = mbedtls_pk_parse_key(&serverKey, (const unsigned char *)serverPrivateKey, strlen(serverPrivateKey)+1, NULL, 0, mbedtls_ctr_drbg_random, &ctrDrbgCtx);	// mbedtls v3.5.2
		ret = mbedtls_pk_parse_key(&serverKey, (const unsigned char *)serverPrivateKey, strlen(serverPrivateKey)+1, NULL, 0);	// mbedtls v2.28.8
		if(ret != 0){
#ifdef _DEBUG
			printf("[E] mbedtls_pk_parse_key error:%d\n", ret);
#endif
			finiSsl(&sslParam, 0);
			close(clientSock);
			return -2;
		}

		// ssl configuration
		ret = mbedtls_ssl_config_defaults(&clientSslCfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
		if(ret != 0){
#ifdef _DEBUG
			printf("[E] mbedtls_ssl_config_defaults error:%d\n", ret);
#endif
			finiSsl(&sslParam, 0);
			close(clientSock);
			return -2;
		}

		mbedtls_ssl_conf_rng(&clientSslCfg, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
		mbedtls_ssl_conf_dbg(&clientSslCfg, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
		mbedtls_ssl_conf_session_cache(&clientSslCfg, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif /* MBEDTLS_SSL_CACHE_C */

		ret = mbedtls_ssl_conf_own_cert(&clientSslCfg, &serverCrt, &serverKey);
		if(ret != 0){
#ifdef _DEBUG
			printf("[E] mbedtls_ssl_conf_own_cert error:%d\n", ret);
#endif
			finiSsl(&sslParam, 0);
			close(clientSock);
			return -2;
		}

		mbedtls_ssl_conf_ciphersuites(&clientSslCfg, ciphersuites);

		clientNetCtx.fd = clientSock;

		ret = mbedtls_ssl_setup(&clientSslCtx, &clientSslCfg);
		if(ret != 0){
#ifdef _DEBUG
			printf("[E] mbedtls_ssl_setup error:%d\n", ret);
#endif
			finiSsl(&sslParam, 0);
			close(clientSock);
			return -2;
		}

		mbedtls_ssl_set_bio(&clientSslCtx, &clientNetCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

		// handshake
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
#endif
		while((ret = mbedtls_ssl_handshake(&clientSslCtx)) != 0){
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_handshake error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}
		}

#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
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
				rec = recvDataTls(clientSock, pClientSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
			}else{
				rec = recvDataTls(clientSock, pClientSslCtx, buffer, BUFSIZ, 3600, 0);
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
				finiSsl(&sslParam, 1);
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
		if(pSelectionRequest->methods[i] == authenticationMethod){	// NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
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
		sen = sendDataTls(clientSock, pClientSslCtx, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
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
				finiSsl(&sslParam, 1);
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
			rec = recvDataTls(clientSock, pClientSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receiving username password authentication request error.\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				sen = sendDataTls(clientSock, pClientSslCtx, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
			
#ifdef _DEBUG
			printf("[I] Send username password authentication response:%d bytes.\n", sen);
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
				sen = sendDataTls(clientSock, pClientSslCtx, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
			if(reverseFlag == 0){	// Nomal mode
				finiSsl(&sslParam, 1);
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
		rec = recvDataTls(clientSock, pClientSslCtx, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receiving socks request error.\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
						sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				
				close(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
						sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					close(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
						sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					close(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

				close(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam, 1);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientSslCtx, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam, 1);
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
		err = forwarderTls(clientSock, targetSock, pClientSslCtx, forwarder_tv_sec, forwarder_tv_usec);
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
			finiSsl(&sslParam, 1);
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
	printf("             : %s -h localhost -p 9050 -s\n", filename);
	printf("             : %s -h ::1 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -H socks5client_ip -P socks5client_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -H localhost -P 1234 -s\n", filename);
	printf("             : %s -r -H ::1 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
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
	struct sockaddr_in *tmpIpv4;
	struct sockaddr_in6 serverAddr6, clientAddr6;
	struct sockaddr_in6 *tmpIpv6;
	struct addrinfo hints;
	struct addrinfo *serverHost;
	struct addrinfo *clientHost;

	bzero(&serverAddr, sizeof(struct sockaddr_in));
	bzero(&clientAddr, sizeof(struct sockaddr_in));
	bzero(&serverAddr6, sizeof(struct sockaddr_in6));
	bzero(&clientAddr6, sizeof(struct sockaddr_in6));

	bzero(&hints, sizeof(struct addrinfo));

	char *serverDomainname = socks5ServerIp;
	u_short serverDomainnameLength = 0;
	if(serverDomainname != NULL){
		serverDomainnameLength = strlen(serverDomainname);
	}

	char *clientDomainname = socks5ClientIp;
	u_short clientDomainnameLength = 0;
	if(clientDomainname != NULL){
		clientDomainnameLength = strlen(clientDomainname);
	}

	char *serverPortNumber = socks5ServerPort;
	char *clientPortNumber = socks5ClientPort;

	char serverAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *serverAddr6StringPointer = serverAddr6String;
	char clientAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *clientAddr6StringPointer = clientAddr6String;

	char *colon = NULL;
	int family = 0;
	int reuse = 1;
	int clientAddrLen = sizeof(clientAddr);
	int clientAddr6Len = sizeof(clientAddr6);
	int flags;
	int ret = 0;
	int err = 0;
	
	const char *pers = "socks5_server";
	uint32_t result;

	mbedtls_net_context clientNetCtx;
	mbedtls_entropy_context entropyCtx;
	mbedtls_ctr_drbg_context ctrDrbgCtx;
	mbedtls_ssl_context clientSslCtx;
	mbedtls_ssl_config clientSslCfg;
	mbedtls_x509_crt serverCrt;
	mbedtls_pk_context serverKey;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif /* MBEDTLS_SSL_CACHE_C */

	pPARAM pParam;
	
	SSLPARAM sslParam;
	sslParam.pClientNetCtx = NULL;
	sslParam.pEntropyCtx = NULL;
	sslParam.pCtrDrbgCtx = NULL;
	sslParam.pClientSslCtx = NULL;
	sslParam.pClientSslCfg = NULL;
	sslParam.pServerCrt = NULL;
	sslParam.pServerKey = NULL;
	sslParam.pCache = NULL;


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
				pParam->clientSock = clientSock;
				pParam->pClientSslCtx = NULL;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				if(pthread_create(&thread, NULL, (void *)worker, pParam)){
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
				pParam->clientSock = clientSock;
				pParam->pClientSslCtx = NULL;
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				if(pthread_create(&thread, NULL, (void *)worker, pParam)){
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
		
		colon = strstr(clientDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(clientDomainname, clientPortNumber, &hints, &clientHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(clientDomainname, clientPortNumber, &hints, &clientHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", clientDomainname);
#endif
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(clientDomainname, clientPortNumber, &hints, &clientHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", clientDomainname);
#endif
				return -1;
			}
		}

		if(clientHost->ai_family == AF_INET){
			family = AF_INET;
			clientAddr.sin_family = AF_INET;
			tmpIpv4 = (struct sockaddr_in *)clientHost->ai_addr;
			memcpy(&clientAddr.sin_addr, &tmpIpv4->sin_addr, sizeof(unsigned long));
			memcpy(&clientAddr.sin_port, &tmpIpv4->sin_port, 2);
			freeaddrinfo(clientHost);
		}else if(clientHost->ai_family == AF_INET6){
			family = AF_INET6;
			clientAddr6.sin6_family = AF_INET6;
			tmpIpv6 = (struct sockaddr_in6 *)clientHost->ai_addr;
			memcpy(&clientAddr6.sin6_addr, &tmpIpv6->sin6_addr, sizeof(struct in6_addr));
			memcpy(&clientAddr6.sin6_port, &tmpIpv6->sin6_port, 2);
			clientAddr6.sin6_scope_id = tmpIpv6->sin6_scope_id;
			freeaddrinfo(clientHost);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			freeaddrinfo(clientHost);
			return -1;
		}

		if(family == AF_INET){	// IPv4
			clientSock = socket(AF_INET, SOCK_STREAM, 0);
	
			flags = fcntl(clientSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(clientSock, F_SETFL, flags);

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

			if((err = connect(clientSock, (struct sockaddr *)&clientAddr, sizeof(clientAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				return -1;
			}
#ifdef _DEBUG
			printf("[I] Connected to ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			clientSock = socket(AF_INET6, SOCK_STREAM, 0);

			flags = fcntl(clientSock, F_GETFL, 0);
			flags &= ~O_NONBLOCK;
			fcntl(clientSock, F_SETFL, flags);

#ifdef _DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0){
				printf("[I] Connecting ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else{
				printf("[I] Connecting ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif

			if((err = connect(clientSock, (struct sockaddr *)&clientAddr6, sizeof(clientAddr6))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", err);
#endif
				return -1;
			}

#ifdef _DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0){
				printf("[I] Connected to ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else{
				printf("[I] Connected to ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			return -1;
		}


		if(tlsFlag == 1){	// tls
			// initialize
			mbedtls_net_init(&clientNetCtx);
			mbedtls_entropy_init(&entropyCtx);
			mbedtls_ctr_drbg_init(&ctrDrbgCtx);
			mbedtls_ssl_init(&clientSslCtx);
			mbedtls_ssl_config_init(&clientSslCfg);
			mbedtls_x509_crt_init(&serverCrt);
			mbedtls_pk_init(&serverKey);
#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_cache_init(&cache);
#endif /* MBEDTLS_SSL_CACHE_C */

			sslParam.pClientNetCtx = &clientNetCtx;
			sslParam.pEntropyCtx = &entropyCtx;
			sslParam.pCtrDrbgCtx = &ctrDrbgCtx;
			sslParam.pClientSslCtx = &clientSslCtx;
			sslParam.pClientSslCfg = &clientSslCfg;
			sslParam.pServerCrt = &serverCrt;
			sslParam.pServerKey = &serverKey;
#if defined(MBEDTLS_SSL_CACHE_C)
			sslParam.pCache = &cache;
#endif /* MBEDTLS_SSL_CACHE_C */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
			psa_status_t status = psa_crypt_init();
			if(status != PSA_SUCCESS){
#ifdef _DEBUG
				printf("[E] psa_crypt_init error:%d\n", (int)status);
#endif
				finiSsl(&sslParam, 0);
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
				close(clientSock);
				return -2;
			}

			ret = mbedtls_x509_crt_parse(&serverCrt, (const unsigned char *)serverCertificate, strlen(serverCertificate)+1);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_x509_crt_parse error:-0x%x\n", (unsigned int)-ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}

//			ret = mbedtls_pk_parse_key(&serverKey, (const unsigned char *)serverPrivateKey, strlen(serverPrivateKey)+1, NULL, 0, mbedtls_ctr_drbg_random, &ctrDrbgCtx);	// mbedtls v3.5.2
			ret = mbedtls_pk_parse_key(&serverKey, (const unsigned char *)serverPrivateKey, strlen(serverPrivateKey)+1, NULL, 0);	// mbedtls v2.28.8
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_pk_parse_key error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}

			// ssl configuration
			ret = mbedtls_ssl_config_defaults(&clientSslCfg, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_config_defaults error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}

			mbedtls_ssl_conf_rng(&clientSslCfg, mbedtls_ctr_drbg_random, &ctrDrbgCtx);
			mbedtls_ssl_conf_dbg(&clientSslCfg, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
			mbedtls_ssl_conf_session_cache(&clientSslCfg, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif /* MBEDTLS_SSL_CACHE_C */

			ret = mbedtls_ssl_conf_own_cert(&clientSslCfg, &serverCrt, &serverKey);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_conf_own_cert error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}

			mbedtls_ssl_conf_ciphersuites(&clientSslCfg, ciphersuites);

			clientNetCtx.fd = clientSock;

			ret = mbedtls_ssl_setup(&clientSslCtx, &clientSslCfg);
			if(ret != 0){
#ifdef _DEBUG
				printf("[E] mbedtls_ssl_setup error:%d\n", ret);
#endif
				finiSsl(&sslParam, 0);
				close(clientSock);
				return -2;
			}

			mbedtls_ssl_set_bio(&clientSslCtx, &clientNetCtx, mbedtls_net_send, mbedtls_net_recv, NULL);

		// handshake
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
#endif
			while((ret = mbedtls_ssl_handshake(&clientSslCtx)) != 0){
				if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE){
#ifdef _DEBUG
					printf("[E] mbedtls_ssl_handshake error:-0x%x\n", (unsigned int)-ret);
#endif
					finiSsl(&sslParam, 0);
					close(clientSock);
					return -2;
				}
			}

#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection. (mbedtls_ssl_handshake)\n");
#endif
		}
		
		while(1){
			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->clientSock = clientSock;
			pParam->pClientSslCtx = &clientSslCtx;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;
			
			err = worker(pParam);
			if(err == -2){
				break;
			}
		}
		
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam, 1);
		}
		close(clientSock);

	}

	return 0;
}


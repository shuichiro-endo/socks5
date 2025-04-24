/*
 * Title:  socks5 client (Linux static)
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
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ares.h>

#include "client.h"
#include "socks5.h"


char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
char *socks5Server2Ip = NULL;
char *socks5Server2Port = NULL;
int reverseFlag = 0;
int xorFlag = 0;

pthread_mutex_t channel_mutex;
ares_channel_t *channel = NULL;

char xorDefaultKeyHexstring[201] = "cafedeadcafebabe";
char *xorKeyHexstring = NULL;
int xorKeyHexstringLength = 0;
unsigned char xorKey[101] = {0};
int xorKeyLength = 0;


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


char hexcharToInt(char c)
{
	char ret = 0;

	if((c >= '0') && (c <= '9')){
		ret = c - '0';
	}else if((c >= 'a') && (c <= 'f')){
		ret = c + 10 - 'a';
	}else if((c >= 'A') && (c <= 'F')){
		ret = c + 10 - 'A';
	}else{
		ret = -1;
	}

	return ret;
}


int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize)
{
	char tmp1 = 0;
	char tmp2 = 0;
	int outputLength = 0;

	if(hexstringLength % 2 != 0){
#ifdef _DEBUG
		printf("[E] hexstringLength error\n");
#endif
		return -1;
	}

	if(hexstringLength / 2 > outputSize){
#ifdef _DEBUG
		printf("[E] hexstringLength error\n");
#endif
		return -1;
	}

	for(int i=0; i<hexstringLength; i+=2){
		tmp1 = hexcharToInt(hexstring[i]);
		tmp2 = hexcharToInt(hexstring[i+1]);

		if(tmp1 == -1 || tmp2 == -1){
#ifdef _DEBUG
			printf("[E] hexcharToInt error\n");
#endif
			return -1;
		}

		tmp1 = tmp1 << 4;
		output[outputLength] = (unsigned char)(tmp1 + tmp2);
		outputLength++;
	}

	return outputLength;
}


void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength)
{
	for(int i=0; i<length; i++){
		buffer[i] = buffer[i] ^ key[i%keyLength];
	}

	return;
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


int recvDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec)
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
				xor((unsigned char *)buffer, rec, xorKey, xorKeyLength);
				break;
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


int sendDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = length;
	fd_set writefds;
	int nfds = -1;
	struct timeval tv;

	xor((unsigned char *)buffer, length, xorKey, xorKeyLength);

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


int forwarderXor(int clientSock, int targetSock, long tv_sec, long tv_usec)
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
				xor((unsigned char *)buffer, rec, xorKey, xorKeyLength);
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
				xor((unsigned char *)buffer, rec, xorKey, xorKeyLength);
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


char *getIpv6AddrString(const char *addr)
{
	char *percent = NULL;
	char *addr2 = calloc(INET6_ADDRSTRLEN+1, sizeof(char));
	unsigned int length = strlen(addr);

	percent = strstr(addr, "%");	// separator
	if(percent != NULL){
		memcpy(addr2, addr, percent-addr);
	}else{
		if(length <= INET6_ADDRSTRLEN){
			memcpy(addr2, addr, length);
		}else{
			memcpy(addr2, addr, INET6_ADDRSTRLEN);
		}
	}

#ifdef _DEBUG
//	printf("[I] ipv6 address:%s\n", addr2);
#endif

	return addr2;
}


char *getIpv6InterfaceName(const char *addr)
{
	char *percent = NULL;
	char *interfaceName = calloc(IFNAMSIZ+1, sizeof(char));

	percent = strstr(addr, "%");	// separator
	if(percent != NULL){
		memcpy(interfaceName, percent+1, strlen(addr)-(percent-addr));
#ifdef _DEBUG
//		printf("[I] interface name:%s\n", interfaceName);
#endif
		return interfaceName;
	}

	free(interfaceName);
	return NULL;
}


uint32_t getIpv6ScopeId(const char *addr)
{
	char *interfaceName = NULL;
	uint32_t scopeId = 0;

	interfaceName = getIpv6InterfaceName(addr);
	if(interfaceName != NULL){
		scopeId = if_nametoindex((const char *)interfaceName);
#ifdef _DEBUG
//		printf("[I] scope id:%d\n", scopeId);
#endif
	}

	free(interfaceName);
	return scopeId;
}


void addrinfoCallback(void *arg, int status, int timeouts, struct ares_addrinfo *result)
{
	pAddrinfoCallbackArg pAddrinfoCallbackArg = (addrinfoCallbackArg *)arg;
	pAddrinfoCallbackArg->ret = -1;
	char addr6_string[INET6_ADDRSTRLEN + 1] = {0};
	char *addr6_string_pointer = addr6_string;


#ifdef _DEBUG
	printf("[I] addrinfo_callback result: %s, timeouts: %d\n", ares_strerror(status), timeouts);
#endif

	if(result){
		struct ares_addrinfo_node *node;

		for(node = result->nodes; node != NULL; node = node->ai_next){
			if(node->ai_family == AF_INET && pAddrinfoCallbackArg->addr != NULL){
				const struct sockaddr_in *in_addr = (const struct sockaddr_in *)((void *)node->ai_addr);

				pAddrinfoCallbackArg->addr->sin_family = AF_INET;
				memcpy(&pAddrinfoCallbackArg->addr->sin_addr, &in_addr->sin_addr, sizeof(struct in_addr));
				memcpy(&pAddrinfoCallbackArg->addr->sin_port, &in_addr->sin_port, 2);

#ifdef _DEBUG
				printf("[I] addrinfo_callback ipv4: %s, port: %d\n", inet_ntoa(pAddrinfoCallbackArg->addr->sin_addr), ntohs(pAddrinfoCallbackArg->addr->sin_port));
#endif

				pAddrinfoCallbackArg->ret = 0;

				break;
			}else if(node->ai_family == AF_INET6 && pAddrinfoCallbackArg->addr6 != NULL)
			{
				const struct sockaddr_in6 *in_addr6 = (const struct sockaddr_in6 *)((void *)node->ai_addr);

				pAddrinfoCallbackArg->addr6->sin6_family = AF_INET6;
				memcpy(&pAddrinfoCallbackArg->addr6->sin6_addr, &in_addr6->sin6_addr, sizeof(struct in6_addr));
				memcpy(&pAddrinfoCallbackArg->addr6->sin6_port, &in_addr6->sin6_port, 2);
				pAddrinfoCallbackArg->addr6->sin6_scope_id = in_addr6->sin6_scope_id;

#ifdef _DEBUG
				inet_ntop(AF_INET6, &pAddrinfoCallbackArg->addr6->sin6_addr, addr6_string_pointer, INET6_ADDRSTRLEN);

				printf("[I] addrinfo_callback ipv6: %s, port: %d, scorp_id: %d\n", addr6_string_pointer, ntohs(pAddrinfoCallbackArg->addr6->sin6_port), pAddrinfoCallbackArg->addr6->sin6_scope_id);
#endif

				pAddrinfoCallbackArg->ret = 0;

				break;
			}else
			{
				continue;
			}
		}
	}

	ares_freeaddrinfo(result);
}


int getAddrInfo(const char *domainname, const char *service, int ai_family, struct sockaddr_in *addr, struct sockaddr_in6 *addr6)
{
	struct ares_addrinfo_hints hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = ai_family;
	hints.ai_flags  = ARES_AI_CANONNAME;

	addrinfoCallbackArg addrinfoCallbackArg;
	addrinfoCallbackArg.addr = addr;
	addrinfoCallbackArg.addr6 = addr6;
	addrinfoCallbackArg.ret = -1;


	pthread_mutex_lock(&channel_mutex);

	ares_getaddrinfo(channel, domainname, service, &hints, addrinfoCallback, &addrinfoCallbackArg);

	ares_queue_wait_empty(channel, -1);

	pthread_mutex_unlock(&channel_mutex);

	return addrinfoCallbackArg.ret;
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
	struct sockaddr_in6 targetAddr6;

	bzero(&targetAddr, sizeof(struct sockaddr_in));
	bzero(&targetAddr6, sizeof(struct sockaddr_in6));

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

	char *addr = NULL;
	char *tmp = NULL;
	uint32_t scopeId = 0;
	
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
			family = AF_INET;	// IPv4
			ret = getAddrInfo(targetDomainname, targetPortNumber, AF_INET, &targetAddr, NULL);
			if(ret != 0){
				family = AF_INET6;	// IPv6
				ret = getAddrInfo(targetDomainname, targetPortNumber, AF_INET6, NULL, &targetAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
					return -1;
				}
			}
		}else{	// ipv6 address
			family = AF_INET6;	// IPv6
			scopeId = getIpv6ScopeId(targetDomainname);
			if(scopeId == 0){
				ret = getAddrInfo(targetDomainname, targetPortNumber, AF_INET6, NULL, &targetAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
					return -1;
				}
			}else{
				addr = getIpv6AddrString(targetDomainname);
				if(addr == NULL){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
					return -1;
				}

				ret = getAddrInfo(addr, targetPortNumber, AF_INET6, NULL, &targetAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", targetDomainname);
#endif
					free(addr);
					return -1;
				}

				targetAddr6.sin6_scope_id = scopeId;
				free(addr);
			}
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
	if(xorFlag == 0){
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{
		sen = sendDataXor(targetSock, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(xorFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataXor(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
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
		if(xorFlag == 0){
			sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
		}else{
			sen = sendDataXor(targetSock, buffer, rec, tv_sec, tv_usec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(xorFlag == 0){
			rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{
			rec = recvDataXor(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
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
	if(xorFlag == 0){
		sen = sendData(targetSock, buffer, rec, tv_sec, tv_usec);
	}else{
		sen = sendDataXor(targetSock, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);
#endif
	
	
	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(xorFlag == 0){
		rec = recvData(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataXor(targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
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
	if(xorFlag == 0){
		err = forwarder(clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}else{
		err = forwarderXor(clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}


#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	if(reverseFlag == 0){	// Nomal mode
		close(targetSock);
	}
	close(clientSock);

	return 0;
}

void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h socks5_listen_ip -p socks5_listen_port -H socks5server_ip -P socks5server_port\n", filename);
	printf("             : [-x (xor encryption] [-k key(hexstring)]\n");
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -h 0.0.0.0 -p 9050 -H 192.168.0.10 -P 9050\n", filename);
	printf("             : %s -h localhost -p 9050 -H 192.168.0.10 -P 9050 -x -k deadbeef\n", filename);
	printf("             : %s -h ::1 -p 9050 -H 192.168.0.10 -P 9050 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -H fe80::yyyy:yyyy:yyyy:yyyy%%eth0 -P 9050 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -h socks5_listen_ip -p socks5_listen_port -H socks5server_listen_ip -P socks5server_listen_port\n", filename);
	printf("             : [-x (xor encryption] [-k key(hexstring)]\n");
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -r -h 0.0.0.0 -p 9050 -H 0.0.0.0 -P 1234\n", filename);
	printf("             : %s -r -h localhost -p 9050 -H 0.0.0.0 -P 1234 -x -k deadbeef\n", filename);
	printf("             : %s -r -h ::1 -p 9050 -H 0.0.0.0 -P 1234 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 1234 -x -A 3 -B 0 -C 3 -D 0\n", filename);
}

int main(int argc, char **argv)
{
	int opt;
	const char* optstring = "rh:p:H:P:xk:A:B:C:D:";
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
			
		case 'x':
			xorFlag = 1;
			break;

		case 'k':
			xorKeyHexstring = optarg;
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
	
	if(xorFlag == 1){
		if(xorKeyHexstring == NULL){
			xorKeyHexstringLength = strlen(xorDefaultKeyHexstring);
			if(xorKeyHexstringLength % 2 != 0){
#ifdef _DEBUG
				printf("[E] xorDefaultKeyHexstring length is odd:%d\n", xorKeyHexstringLength);
#endif
				return -1;
			}

			if(xorKeyHexstringLength > 200){
#ifdef _DEBUG
				printf("[E] xorDefaultKeyHexstring is too long:%d (>200)\n", xorKeyHexstringLength);
#endif
				return -1;
			}

			xorKeyLength = hexstringToArray(xorDefaultKeyHexstring, xorKeyHexstringLength, xorKey, 100);
			if(xorKeyLength <= 0){
#ifdef _DEBUG
				printf("[E] hexstringToArray error\n");
#endif
				return -1;
			}
		}else{
			xorKeyHexstringLength = strlen(xorKeyHexstring);
			if(xorKeyHexstringLength % 2 != 0){
#ifdef _DEBUG
				printf("[E] xorKeyHexstring length is odd:%d\n", xorKeyHexstringLength);
#endif
				return -1;
			}

			if(xorKeyHexstringLength > 200){
#ifdef _DEBUG
				printf("[E] xorKeyHexstring is too long:%d (>200)\n", xorKeyHexstringLength);
#endif
				return -1;
			}

			xorKeyLength = hexstringToArray(xorKeyHexstring, xorKeyHexstringLength, xorKey, 100);
			if(xorKeyLength <= 0){
#ifdef _DEBUG
				printf("[E] hexstringToArray error\n");
#endif
				return -1;
			}
		}
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

	pthread_mutex_init(&channel_mutex, NULL);
	struct ares_options options;
	int optmask = 0;

	ares_library_init(ARES_LIB_INIT_ALL);

	if(ares_threadsafety())
	{
		memset(&options, 0, sizeof(options));
		optmask |= ARES_OPT_EVENT_THREAD;
		options.evsys = ARES_EVSYS_DEFAULT;

		if(ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
		{
			printf("[E] c-ares inisialization issue\n");
			return -1;
		}
	}else
	{
		printf("[E] c-ares not compiled with thread support\n");
		return -1;
	}
	
	int serverSock, clientSock, server2Sock;
	int targetSock = -1;
	struct sockaddr_in serverAddr, clientAddr, server2Addr, targetAddr;
	struct sockaddr_in6 serverAddr6, clientAddr6, server2Addr6, targetAddr6;

	bzero(&serverAddr, sizeof(struct sockaddr_in));
	bzero(&clientAddr, sizeof(struct sockaddr_in));
	bzero(&server2Addr, sizeof(struct sockaddr_in));
	bzero(&targetAddr, sizeof(struct sockaddr_in));

	bzero(&serverAddr6, sizeof(struct sockaddr_in6));
	bzero(&clientAddr6, sizeof(struct sockaddr_in6));
	bzero(&server2Addr6, sizeof(struct sockaddr_in6));
	bzero(&targetAddr6, sizeof(struct sockaddr_in6));

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
	uint16_t serverPort = 0;
	if(serverPortNumber != NULL)
	{
		serverPort = (uint16_t)atoi(serverPortNumber);
	}
	char *server2PortNumber = socks5Server2Port;
	uint16_t server2Port = 0;
	if(server2PortNumber != NULL)
	{
		server2Port = (uint16_t)atoi(server2PortNumber);
	}

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

	char *addr = NULL;
	char *tmp = NULL;
	uint32_t scopeId = 0;

	pPARAM pParam;

	int ret = 0;
	int err = 0;


	if(reverseFlag == 0){	// Nomal mode
#ifdef _DEBUG
		printf("[I] Nomal mode.\n");
#endif
		if(xorFlag == 1){
#ifdef _DEBUG
			printf("[I] Xor encryption:on.\n");
			printf("[I] Xor key:\n");
			printBytes(xorKey, xorKeyLength);
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Xor encryption:off.\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif

		colon = strstr(serverDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			family = AF_INET;	// IPv4
			ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET, &serverAddr, NULL);
			if(ret != 0){
				family = AF_INET6;
				ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					goto error;
				}
			}
		}else{	// ipv6 address
			family = AF_INET6;	// IPv6
			scopeId = getIpv6ScopeId(serverDomainname);
			if(scopeId == 0){
				ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					goto error;
				}
			}else{
				addr = getIpv6AddrString(serverDomainname);
				if(addr == NULL){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					goto error;
				}

				ret = getAddrInfo(addr, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					free(addr);
					goto error;
				}

				serverAddr6.sin6_scope_id = scopeId;
				free(addr);
			}
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
				goto error;
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
				goto error;
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
		if(xorFlag == 1){
#ifdef _DEBUG
			printf("[I] Xor encryption:on.\n");
			printf("[I] Xor key:\n");
			printBytes(xorKey, xorKeyLength);
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Xor encryption:off.\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec.\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec.\n", forwarder_tv_sec, forwarder_tv_usec);
#endif

		colon = strstr(server2Domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			family = AF_INET;	// IPv4
			ret = getAddrInfo(server2Domainname, server2PortNumber, AF_INET, &server2Addr, NULL);
			if(ret != 0){
				family = AF_INET6;	// IPv6
				ret = getAddrInfo(server2Domainname, server2PortNumber, AF_INET6, NULL, &server2Addr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					goto error;
				}
			}
		}else{	// ipv6 address
			family = AF_INET6;	// IPv6
			scopeId = getIpv6ScopeId(server2Domainname);
			if(scopeId == 0){
				ret = getAddrInfo(server2Domainname, server2PortNumber, AF_INET6, NULL, &server2Addr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					goto error;
				}
			}else{
				addr = getIpv6AddrString(server2Domainname);
				if(addr == NULL){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					goto error;
				}

				ret = getAddrInfo(addr, server2PortNumber, AF_INET6, NULL, &server2Addr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					free(addr);
					goto error;
				}

				server2Addr6.sin6_scope_id = scopeId;
				free(addr);
			}
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
				goto error;
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
				goto error;
			}

			// listen
			listen(server2Sock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &server2Addr6.sin6_addr, server2Addr6StringPointer, INET6_ADDRSTRLEN);
			if(serverAddr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d.\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer, serverAddr6.sin6_scope_id);
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

		colon = strstr(serverDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			family = AF_INET;	// IPv4
			ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET, &serverAddr, NULL);
			if(ret != 0){
				family = AF_INET6;	// IPv6
				ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					close(targetSock);
					close(server2Sock);
					goto error;
				}
			}
		}else{	// ipv6 address
			family = AF_INET6;	// IPv6
			scopeId = getIpv6ScopeId(serverDomainname);
			if(scopeId == 0){
				ret = getAddrInfo(serverDomainname, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					close(targetSock);
					close(server2Sock);
					goto error;
				}
			}else{
				addr = getIpv6AddrString(serverDomainname);
				if(addr == NULL){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					close(targetSock);
					close(server2Sock);
					goto error;
				}

				ret = getAddrInfo(addr, serverPortNumber, AF_INET6, NULL, &serverAddr6);
				if(ret != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					free(addr);
					close(targetSock);
					close(server2Sock);
					goto error;
				}

				serverAddr6.sin6_scope_id = scopeId;
				free(addr);
			}
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
				close(targetSock);
				close(server2Sock);
				close(serverSock);
				goto error;
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
				close(targetSock);
				close(server2Sock);
				close(serverSock);
				goto error;
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

		close(targetSock);
		close(server2Sock);
		close(clientSock);
		close(serverSock);
	}

	pthread_mutex_lock(&channel_mutex);
	ares_destroy(channel);
	pthread_mutex_unlock(&channel_mutex);

	ares_library_cleanup();
	pthread_mutex_destroy(&channel_mutex);

	return 0;

error:
	pthread_mutex_lock(&channel_mutex);
	ares_destroy(channel);
	pthread_mutex_unlock(&channel_mutex);

	ares_library_cleanup();
	pthread_mutex_destroy(&channel_mutex);

	return -1;
}

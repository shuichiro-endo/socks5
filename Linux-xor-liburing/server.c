/*
 * Title:  socks5 server (Linux liburing)
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
#include <liburing.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "socks5.h"
#include "server.h"

#define RING_QUEUE_DEPTH	8


char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5ClientIp = NULL;
char *socks5ClientPort = NULL;
int reverseFlag = 0;
int xorFlag = 0;

static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
char username[256] = "socks5user";
char password[256] = "supersecretpassword";

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


int recvData(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int ret = 0;
	int rec = 0;
	uint64_t idRecv = (uint64_t)random();
	uint64_t idTimeout = idRecv + 1;
	uint64_t idCancelRecv = idRecv + 2;
	uint64_t idCancelTimeout = idRecv + 3;
	struct io_uring_sqe *sqeRecv = NULL;
	struct io_uring_sqe *sqeTimeout = NULL;
	struct io_uring_sqe *sqeCancel = NULL;
	struct io_uring_cqe *cqe = NULL;
	struct __kernel_timespec ts = {0};
	int timeoutActive = 0;
	int recvActive = 0;

	bzero(buffer, length+1);

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeRecv = io_uring_get_sqe(ring);
	if(sqeRecv == NULL){
		goto error;
	}

	io_uring_prep_recv(sqeRecv, sock, buffer, length, 0);
	sqeRecv->user_data = idRecv;
	recvActive = 1;

	sqeTimeout = io_uring_get_sqe(ring);
	if(sqeTimeout == NULL){
		goto error;
	}

	ts.tv_sec = tv_sec;
	ts.tv_nsec = tv_usec * 1000;
	io_uring_prep_timeout(sqeTimeout, &ts, 1, 0);
	sqeTimeout->user_data = idTimeout;
	timeoutActive = 1;

	ret = io_uring_submit(ring);
	if(ret < 0){
		goto error;
	}

	while(1){
		ret = io_uring_wait_cqe(ring, &cqe);
		if(ret < 0){
			goto error;
		}

		if(cqe->user_data == idRecv){
			rec = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(rec >= 0){
				recvActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}else if(rec == -EAGAIN || rec == -EWOULDBLOCK){
				usleep(5000);

				sqeRecv = io_uring_get_sqe(ring);
				if(sqeRecv == NULL){
					goto error;
				}

				io_uring_prep_recv(sqeRecv, sock, buffer, length, 0);
				sqeRecv->user_data = idRecv;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}

				recvActive = 1;
			}else{
				recvActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}
		}else if(cqe->user_data == idTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			timeoutActive = 0;

			if(recvActive == 1){
#ifdef _DEBUG
				printf("[I] recvData timeout\n");
#endif

				sqeCancel = io_uring_get_sqe(ring);
				if(sqeCancel == NULL){
					goto error;
				}

				io_uring_prep_cancel(sqeCancel, (void *)&idRecv, 0);
				sqeCancel->user_data = idCancelRecv;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				break;
			}
		}else if(cqe->user_data == idCancelRecv){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			recvActive = 0;

			if(timeoutActive == 0)
			{
				break;
			}
		}else if(cqe->user_data == idCancelTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			timeoutActive = 0;

			if(recvActive == 0){
				break;
			}
		}else{
			ret = cqe->res;

#ifdef _DEBUG
			printf("[E] recvData unknown cqe user_data:%llu res=%d\n", (unsigned long long)cqe->user_data, cqe->res);
#endif

			io_uring_cqe_seen(ring, cqe);

			goto error;
		}
	}

	return rec;

error:
	return -1;
}


int recvDataXor(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int ret = 0;
	int rec = 0;
	uint64_t idRecv = (uint64_t)random();
	uint64_t idTimeout = idRecv + 1;
	uint64_t idCancelRecv = idRecv + 2;
	uint64_t idCancelTimeout = idRecv + 3;
	struct io_uring_sqe *sqeRecv = NULL;
	struct io_uring_sqe *sqeTimeout = NULL;
	struct io_uring_sqe *sqeCancel = NULL;
	struct io_uring_cqe *cqe = NULL;
	struct __kernel_timespec ts = {0};
	int timeoutActive = 0;
	int recvActive = 0;

	bzero(buffer, length+1);

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeRecv = io_uring_get_sqe(ring);
	if(sqeRecv == NULL){
		goto error;
	}

	io_uring_prep_recv(sqeRecv, sock, buffer, length, 0);
	sqeRecv->user_data = idRecv;
	recvActive = 1;

	sqeTimeout = io_uring_get_sqe(ring);
	if(sqeTimeout == NULL){
		goto error;
	}

	ts.tv_sec = tv_sec;
	ts.tv_nsec = tv_usec * 1000;
	io_uring_prep_timeout(sqeTimeout, &ts, 1, 0);
	sqeTimeout->user_data = idTimeout;
	timeoutActive = 1;

	ret = io_uring_submit(ring);
	if(ret < 0){
		goto error;
	}

	while(1){
		ret = io_uring_wait_cqe(ring, &cqe);
		if(ret < 0){
			goto error;
		}

		if(cqe->user_data == idRecv){
			rec = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(rec >= 0){
				recvActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}else if(rec == -EAGAIN || rec == -EWOULDBLOCK){
				usleep(5000);

				sqeRecv = io_uring_get_sqe(ring);
				if(sqeRecv == NULL){
					goto error;
				}

				io_uring_prep_recv(sqeRecv, sock, buffer, length, 0);
				sqeRecv->user_data = idRecv;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}

				recvActive = 1;
			}else{
				recvActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}
		}else if(cqe->user_data == idTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			timeoutActive = 0;

			if(recvActive == 1){
#ifdef _DEBUG
				printf("[I] recvDataXor timeout\n");
#endif

				sqeCancel = io_uring_get_sqe(ring);
				if(sqeCancel == NULL){
					goto error;
				}

				io_uring_prep_cancel(sqeCancel, (void *)&idRecv, 0);
				sqeCancel->user_data = idCancelRecv;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				break;
			}
		}else if(cqe->user_data == idCancelRecv){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			recvActive = 0;

			if(timeoutActive == 0)
			{
				break;
			}
		}else if(cqe->user_data == idCancelTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			timeoutActive = 0;

			if(recvActive == 0){
				break;
			}
		}else{
			ret = cqe->res;

#ifdef _DEBUG
			printf("[E] recvDataXor unknown cqe user_data:%llu res:%d\n", (unsigned long long)cqe->user_data, cqe->res);
#endif

			io_uring_cqe_seen(ring, cqe);

			goto error;
		}
	}

	xor((unsigned char *)buffer, rec, xorKey, xorKeyLength);

	return rec;

error:
	return -1;
}


int sendData(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int ret = 0;
	int sen = 0;
	int sendLength = 0;
	int len = length;

	uint64_t idSend = (uint64_t)random();
	uint64_t idTimeout = idSend + 1;
	uint64_t idCancelSend = idSend + 2;
	uint64_t idCancelTimeout = idSend + 3;
	struct io_uring_sqe *sqeSend = NULL;
	struct io_uring_sqe *sqeTimeout = NULL;
	struct io_uring_sqe *sqeCancel = NULL;
	struct io_uring_cqe *cqe = NULL;
	struct __kernel_timespec ts = {0};
	int timeoutActive = 0;
	int sendActive = 0;

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeSend = io_uring_get_sqe(ring);
	if(sqeSend == NULL){
		goto error;
	}

	io_uring_prep_send(sqeSend, sock, buffer, len, 0);
	sqeSend->user_data = idSend;
	sendActive = 1;

	sqeTimeout = io_uring_get_sqe(ring);
	if(sqeTimeout == NULL){
		goto error;
	}

	ts.tv_sec = tv_sec;
	ts.tv_nsec = tv_usec * 1000;
	io_uring_prep_timeout(sqeTimeout, &ts, 1, 0);
	sqeTimeout->user_data = idTimeout;
	timeoutActive = 1;

	ret = io_uring_submit(ring);
	if(ret < 0){
		goto error;
	}

	while(len > 0){
		ret = io_uring_wait_cqe(ring, &cqe);
		if(ret < 0){
			goto error;
		}

		if(cqe->user_data == idSend){
			sen = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(sen >= 0){
				sendLength += sen;
				len -= sen;

				if(len > 0){
					sqeSend = io_uring_get_sqe(ring);
					if(sqeSend == NULL){
						goto error;
					}

					io_uring_prep_send(sqeSend, sock, buffer+sendLength, len, 0);
					sqeSend->user_data = idSend;
					sendActive = 1;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					sendActive = 0;

					if(timeoutActive == 1){
						sqeCancel = io_uring_get_sqe(ring);
						if(sqeCancel == NULL){
							goto error;
						}

						io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
						sqeCancel->user_data = idCancelTimeout;

						ret = io_uring_submit(ring);
						if(ret < 0){
							goto error;
						}
					}else{
						break;
					}
				}
			}else if(sen == -EAGAIN || sen == -EWOULDBLOCK){
				usleep(5000);

				sqeSend = io_uring_get_sqe(ring);
				if(sqeSend == NULL){
					goto error;
				}

				io_uring_prep_send(sqeSend, sock, buffer+sendLength, len, 0);
				sqeSend->user_data = idSend;
				sendActive = 1;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				sendActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}
		}else if(cqe->user_data == idTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			timeoutActive = 0;

			if(sendActive == 1){
#ifdef _DEBUG
				printf("[I] sendData timeout\n");
#endif

				sqeCancel = io_uring_get_sqe(ring);
				if(sqeCancel == NULL){
					goto error;
				}

				io_uring_prep_cancel(sqeCancel, (void *)&idSend, 0);
				sqeCancel->user_data = idCancelSend;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				break;
			}
		}else if(cqe->user_data == idCancelSend){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			sendActive = 0;

			if(timeoutActive == 0)
			{
				break;
			}
		}else if(cqe->user_data == idCancelTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			timeoutActive = 0;

			if(sendActive == 0){
				break;
			}
		}else{
			ret = cqe->res;

#ifdef _DEBUG
			printf("[E] sendData unknown cqe user_data:%llu res=%d\n", (unsigned long long)cqe->user_data, cqe->res);
#endif

			io_uring_cqe_seen(ring, cqe);

			goto error;
		}
	}

	return sendLength;

error:
	return -1;
}


int sendDataXor(struct io_uring *ring, int sock, void *buffer, int length, long tv_sec, long tv_usec)
{
	int ret = 0;
	int sen = 0;
	int sendLength = 0;
	int len = length;

	uint64_t idSend = (uint64_t)random();
	uint64_t idTimeout = idSend + 1;
	uint64_t idCancelSend = idSend + 2;
	uint64_t idCancelTimeout = idSend + 3;
	struct io_uring_sqe *sqeSend = NULL;
	struct io_uring_sqe *sqeTimeout = NULL;
	struct io_uring_sqe *sqeCancel = NULL;
	struct io_uring_cqe *cqe = NULL;
	struct __kernel_timespec ts = {0};
	int timeoutActive = 0;
	int sendActive = 0;

	xor((unsigned char *)buffer, length, xorKey, xorKeyLength);

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeSend = io_uring_get_sqe(ring);
	if(sqeSend == NULL){
		goto error;
	}

	io_uring_prep_send(sqeSend, sock, buffer, len, 0);
	sqeSend->user_data = idSend;
	sendActive = 1;

	sqeTimeout = io_uring_get_sqe(ring);
	if(sqeTimeout == NULL){
		goto error;
	}

	ts.tv_sec = tv_sec;
	ts.tv_nsec = tv_usec * 1000;
	io_uring_prep_timeout(sqeTimeout, &ts, 1, 0);
	sqeTimeout->user_data = idTimeout;
	timeoutActive = 1;

	ret = io_uring_submit(ring);
	if(ret < 0){
		goto error;
	}

	while(len > 0){
		ret = io_uring_wait_cqe(ring, &cqe);
		if(ret < 0){
			goto error;
		}

		if(cqe->user_data == idSend){
			sen = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(sen >= 0){
				sendLength += sen;
				len -= sen;

				if(len > 0){
					sqeSend = io_uring_get_sqe(ring);
					if(sqeSend == NULL){
						goto error;
					}

					io_uring_prep_send(sqeSend, sock, buffer+sendLength, len, 0);
					sqeSend->user_data = idSend;
					sendActive = 1;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					sendActive = 0;

					if(timeoutActive == 1){
						sqeCancel = io_uring_get_sqe(ring);
						if(sqeCancel == NULL){
							goto error;
						}

						io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
						sqeCancel->user_data = idCancelTimeout;

						ret = io_uring_submit(ring);
						if(ret < 0){
							goto error;
						}
					}else{
						break;
					}
				}
			}else if(sen == -EAGAIN || sen == -EWOULDBLOCK){
				usleep(5000);

				sqeSend = io_uring_get_sqe(ring);
				if(sqeSend == NULL){
					goto error;
				}

				io_uring_prep_send(sqeSend, sock, buffer+sendLength, len, 0);
				sqeSend->user_data = idSend;
				sendActive = 1;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				sendActive = 0;

				if(timeoutActive == 1){
					sqeCancel = io_uring_get_sqe(ring);
					if(sqeCancel == NULL){
						goto error;
					}

					io_uring_prep_timeout_remove(sqeCancel, idTimeout, 0);
					sqeCancel->user_data = idCancelTimeout;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}
				}else{
					break;
				}
			}
		}else if(cqe->user_data == idTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			timeoutActive = 0;

			if(sendActive == 1){
#ifdef _DEBUG
				printf("[I] sendDataXor timeout\n");
#endif

				sqeCancel = io_uring_get_sqe(ring);
				if(sqeCancel == NULL){
					goto error;
				}

				io_uring_prep_cancel(sqeCancel, (void *)&idSend, 0);
				sqeCancel->user_data = idCancelSend;

				ret = io_uring_submit(ring);
				if(ret < 0){
					goto error;
				}
			}else{
				break;
			}
		}else if(cqe->user_data == idCancelSend){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			sendActive = 0;

			if(timeoutActive == 0)
			{
				break;
			}
		}else if(cqe->user_data == idCancelTimeout){
			ret = cqe->res;
			io_uring_cqe_seen(ring, cqe);

			if(ret == -ENOENT || ret < 0){
				goto error;
			}

			timeoutActive = 0;

			if(sendActive == 0){
				break;
			}
		}else{
			ret = cqe->res;

#ifdef _DEBUG
			printf("[E] sendDataXor unknown cqe user_data:%llu res=%d\n", (unsigned long long)cqe->user_data, cqe->res);
#endif

			io_uring_cqe_seen(ring, cqe);

			goto error;
		}
	}

	return sendLength;

error:
	return -1;
}


int forwarderWorker1(void *ptr)
{
	pPARAM2 pParam = (pPARAM2)ptr;
	struct io_uring *ring = pParam->ring;
	int clientSock = pParam->clientSock;
	int targetSock = pParam->targetSock;
	long tv_sec = pParam->tv_sec;
	long tv_usec = pParam->tv_usec;

	free(ptr);

	int ret = 0;
	int rec = 0;
	int sen = 0;
	char buffer[BUFSIZ+1];

	while(1){
		bzero(buffer, BUFSIZ+1);

		rec = recvData(ring, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		if(rec > 0){
			sen = sendData(ring, targetSock, buffer, rec, tv_sec, tv_usec);
			if(sen <= 0){
				break;
			}
		}else{
			break;
		}
	}

	return 0;
}


int forwarderWorker2(void *ptr)
{
	pPARAM2 pParam = (pPARAM2)ptr;
	struct io_uring *ring = pParam->ring;
	int clientSock = pParam->clientSock;
	int targetSock = pParam->targetSock;
	long tv_sec = pParam->tv_sec;
	long tv_usec = pParam->tv_usec;

	free(ptr);

	int ret = 0;
	int rec = 0;
	int sen = 0;
	char buffer[BUFSIZ+1];

	while(1){
		bzero(buffer, BUFSIZ+1);

		rec = recvData(ring, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		if(rec > 0){
			sen = sendData(ring, clientSock, buffer, rec, tv_sec, tv_usec);
			if(sen <= 0){
				break;
			}
		}else{
			break;
		}
	}

	return 0;
}


int forwarder(struct io_uring *ring1, struct io_uring *ring2, int clientSock, int targetSock, long tv_sec, long tv_usec)
{
	int ret = 0;
	void *ret1, *ret2;

	pthread_t thread1;
	pthread_t thread2;
	pPARAM2 pParam1 = NULL;
	pPARAM2 pParam2 = NULL;

	pParam1 = (pPARAM2)calloc(1, sizeof(PARAM2));
	pParam2 = (pPARAM2)calloc(1, sizeof(PARAM2));

	pParam1->ring = ring1;
	pParam1->clientSock = clientSock;
	pParam1->targetSock = targetSock;
	pParam1->tv_sec = tv_sec;
	pParam1->tv_usec = tv_usec;

	pParam2->ring = ring2;
	pParam2->clientSock = clientSock;
	pParam2->targetSock = targetSock;
	pParam2->tv_sec = tv_sec;
	pParam2->tv_usec = tv_usec;

	ret = pthread_create(&thread1, NULL, (void *)forwarderWorker1, pParam1);
	ret = pthread_create(&thread2, NULL, (void *)forwarderWorker2, pParam2);

	ret = pthread_join(thread1, &ret1);
	ret = pthread_join(thread2, &ret2);

	return 0;
}


int forwarderXorWorker1(void *ptr)
{
	pPARAM2 pParam = (pPARAM2)ptr;
	struct io_uring *ring = pParam->ring;
	int clientSock = pParam->clientSock;
	int targetSock = pParam->targetSock;
	long tv_sec = pParam->tv_sec;
	long tv_usec = pParam->tv_usec;

	free(ptr);

	int ret = 0;
	int rec = 0;
	int sen = 0;
	char buffer[BUFSIZ+1];

	while(1){
		bzero(buffer, BUFSIZ+1);

		rec = recvDataXor(ring, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		if(rec > 0){
			sen = sendData(ring, targetSock, buffer, rec, tv_sec, tv_usec);
			if(sen <= 0){
				break;
			}
		}else{
			break;
		}
	}

	return 0;
}


int forwarderXorWorker2(void *ptr)
{
	pPARAM2 pParam = (pPARAM2)ptr;
	struct io_uring *ring = pParam->ring;
	int clientSock = pParam->clientSock;
	int targetSock = pParam->targetSock;
	long tv_sec = pParam->tv_sec;
	long tv_usec = pParam->tv_usec;

	free(ptr);

	int ret = 0;
	int rec = 0;
	int sen = 0;
	char buffer[BUFSIZ+1];

	while(1){
		bzero(buffer, BUFSIZ+1);

		rec = recvData(ring, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		if(rec > 0){
			sen = sendDataXor(ring, clientSock, buffer, rec, tv_sec, tv_usec);
			if(sen <= 0){
				break;
			}
		}else{
			break;
		}
	}

	return 0;
}


int forwarderXor(struct io_uring *ring1, struct io_uring *ring2, int clientSock, int targetSock, long tv_sec, long tv_usec)
{
	int ret = 0;
	void *ret1, *ret2;

	pthread_t thread1;
	pthread_t thread2;

	pPARAM2 pParam1 = (pPARAM2)calloc(1, sizeof(PARAM2));
	pPARAM2 pParam2 = (pPARAM2)calloc(1, sizeof(PARAM2));

	pParam1->ring = ring1;
	pParam1->clientSock = clientSock;
	pParam1->targetSock = targetSock;
	pParam1->tv_sec = tv_sec;
	pParam1->tv_usec = tv_usec;

	pParam2->ring = ring2;
	pParam2->clientSock = clientSock;
	pParam2->targetSock = targetSock;
	pParam2->tv_sec = tv_sec;
	pParam2->tv_usec = tv_usec;

	ret = pthread_create(&thread1, NULL, (void *)forwarderXorWorker1, pParam1);
	ret = pthread_create(&thread2, NULL, (void *)forwarderXorWorker2, pParam2);

	ret = pthread_join(thread1, &ret1);
	ret = pthread_join(thread2, &ret2);

	return 0;
}


int sendSocksResponseIpv4(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));

	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendData(ring, clientSock, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv4Xor(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));

	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	bzero(pSocksResponseIpv4->bndAddr, 4);	// BND.ADDR
	bzero(pSocksResponseIpv4->bndPort, 2);	// BND.PORT

	sen = sendDataXor(ring, clientSock, pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv6(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));

	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT

	sen = sendData(ring, clientSock, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);

	free(pSocksResponseIpv6);

	return sen;
}


int sendSocksResponseIpv6Xor(struct io_uring *ring, int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));

	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	bzero(pSocksResponseIpv6->bndAddr, 16);	// BND.ADDR
	bzero(pSocksResponseIpv6->bndPort, 2);	// BND.PORT

	sen = sendDataXor(ring, clientSock, pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);

	free(pSocksResponseIpv6);

	return sen;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	int clientSock = pParam->clientSock;
	int targetSock = -1;
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

	free(ptr);

	struct io_uring ring1;
	struct io_uring ring2;
	struct io_uring_sqe *sqe1 = NULL;
	struct io_uring_cqe *cqe1 = NULL;
	struct io_uring_params ringParams1;
	struct io_uring_params ringParams2;
	memset(&ringParams1, 0, sizeof(struct io_uring_params));
	ringParams1.flags = 0;
	memset(&ringParams2, 0, sizeof(struct io_uring_params));
	ringParams2.flags = 0;

	ret = io_uring_queue_init_params(RING_QUEUE_DEPTH, &ring1, &ringParams1);
	if(ret < 0){
#ifdef _DEBUG
		printf("[E] io_uring_queue_init_params error:%d\n", ret);
#endif
		return -1;
	}

	ret = io_uring_queue_init_params(RING_QUEUE_DEPTH, &ring2, &ringParams2);
	if(ret < 0){
#ifdef _DEBUG
		printf("[E] io_uring_queue_init_params error:%d\n", ret);
#endif
		io_uring_queue_exit(&ring1);
		return -1;
	}


	// socks SELECTION_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving selection request\n");
#endif
	do{
		if(xorFlag == 0){
			if(reverseFlag == 0){
				rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
			}else{
				rec = recvData(&ring1, clientSock, buffer, BUFSIZ, 3600, 0);
			}
		}else{
			if(reverseFlag == 0){
				rec = recvDataXor(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
			}else{
				rec = recvDataXor(&ring1, clientSock, buffer, BUFSIZ, 3600, 0);
			}
		}

		if(rec == -1 || rec == -2){
			break;
		}
	}while((rec > 0 && rec < 3) || rec > 257);

	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Cannot receive selection request\n");
#endif
		goto error;
	}

#ifdef _DEBUG
	printf("[I] Receive selection request:%d bytes\n", rec);
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
		printf("[E] Selection request method error\n");
#endif
	}


	// socks SELECTION_RESPONSE
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)malloc(sizeof(SELECTION_RESPONSE));
	pSelectionResponse->ver = 0x5;		// socks version 5
	pSelectionResponse->method = method;	// no authentication required or username/password
	if(pSelectionRequest->ver != 0x5 || authenticationMethod != method){
		pSelectionResponse->method = 0xFF;
	}
	if(xorFlag == 0){
		sen = sendData(&ring1, clientSock, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}else{
		sen = sendDataXor(&ring1, clientSock, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
	}
	free(pSelectionResponse);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes\n", sen);
#endif

	if(authenticationMethod != method){
#ifdef _DEBUG
		printf("[E] Authentication method error. server:0x%x client:0x%x\n", authenticationMethod, method);
#endif
		goto error;
	}


	// socks USERNAME_PASSWORD_AUTHENTICATION
	unsigned char ulen = 0;
	unsigned char plen = 0;
	char uname[256] = {0};
	char passwd[256] = {0};
	if(method == 0x2){
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST
#ifdef _DEBUG
		printf("[I] Receiving username password authentication request\n");
#endif
		if(xorFlag == 0){
			rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{
			rec = recvDataXor(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receiving username password authentication request error\n");
#endif
			goto error;
		}
#ifdef _DEBUG
		printf("[I] Receive username password authentication request:%d bytes\n", rec);
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
			printf("[I] Succeed username password authentication\n");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0x0;

			if(xorFlag == 0){
				sen = sendData(&ring1, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{
				sen = sendDataXor(&ring1, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}

#ifdef _DEBUG
			printf("[I] Send username password authentication response:%d bytes\n", sen);
#endif

			free(pUsernamePasswordAuthenticationResponse);
		}else{
#ifdef _DEBUG
			printf("[E] Fail username password authentication\n");
#endif
			pUsernamePasswordAuthenticationResponse->status = 0xFF;

			if(xorFlag == 0){
				sen = sendData(&ring1, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}else{
				sen = sendDataXor(&ring1, clientSock, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes\n", sen);
#endif

			free(pUsernamePasswordAuthenticationResponse);
			goto error;
		}
	}


	// socks SOCKS_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving socks request\n");
#endif
	bzero(buffer, BUFSIZ+1);
	if(xorFlag == 0){
		rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataXor(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receiving socks request error\n");
#endif
		goto error;
	}
#ifdef _DEBUG
	printf("[I] Receive socks request:%d bytes\n", rec);
#endif

	pSOCKS_REQUEST pSocksRequest = (pSOCKS_REQUEST)buffer;
	pSOCKS_REQUEST_IPV4 pSocksRequestIpv4;
	pSOCKS_REQUEST_DOMAINNAME pSocksRequestDomainname;
	pSOCKS_REQUEST_IPV6 pSocksRequestIpv6;

	char atyp = pSocksRequest->atyp;
	if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4){
#ifdef _DEBUG
		printf("[E] Socks request atyp(%d) error\n", atyp);
		printf("[E] Not implemented\n");
#endif

		// socks SOCKS_RESPONSE send error
		if(xorFlag == 0){
			sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}

		goto error;
	}

	char cmd = pSocksRequest->cmd;
	if(cmd != 0x1){	// CONNECT only
#ifdef _DEBUG
		printf("[E] Socks request cmd(%d) error\n", cmd);
		printf("[E] Not implemented\n");
#endif

		// socks SOCKS_RESPONSE send error
		if(atyp == 0x1 || atyp == 0x3){	// IPv4
			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(xorFlag == 0){
				sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}

		goto error;
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
		printf("[I] Domainname:%s, Length:%d\n", domainname, domainnameLength);
#endif

		colon = strstr(domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", (char *)domainname);
#endif

					// socks SOCKS_RESPONSE send error
					if(xorFlag == 0){
						sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}

					goto error;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", (char *)domainname);
#endif

				// socks SOCKS_RESPONSE send error
				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}

				goto error;
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
			printf("[E] Not implemented\n");
#endif

			// socks SOCKS_RESPONSE send error
			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}

			freeaddrinfo(pTargetHost);
			goto error;
		}
	}else if(pSocksRequest->atyp == 0x4){	// IPv6
		family = AF_INET6;
		targetAddr6.sin6_family = AF_INET6;
		pSocksRequestIpv6 = (pSOCKS_REQUEST_IPV6)buffer;
		memcpy(&targetAddr6.sin6_addr, &pSocksRequestIpv6->dstAddr, 16);
		memcpy(&targetAddr6.sin6_port, &pSocksRequestIpv6->dstPort, 2);
	}else {
#ifdef _DEBUG
		printf("[E] Not implemented\n");
#endif

		// socks SOCKS_RESPONSE send error
		if(xorFlag == 0){
			sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}

		goto error;
	}


	// socks SOCKS_RESPONSE
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *pTargetAddr6String = targetAddr6String;
	int flags = 0;

	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT\n");
#endif
			targetSock = socket(AF_INET, SOCK_STREAM, 0);

			flags = fcntl(targetSock, F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

			while(io_uring_peek_cqe(&ring1, &cqe1) == 0){
				io_uring_cqe_seen(&ring1, cqe1);
			}

			sqe1 = io_uring_get_sqe(&ring1);

			io_uring_prep_connect(sqe1, targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr));

			ret = io_uring_submit(&ring1);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error;
			}

			ret = io_uring_wait_cqe(&ring1, &cqe1);
			if(ret >= 0 && cqe1->res >= 0){
				io_uring_cqe_seen(&ring1, cqe1);

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
			}else{
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", cqe1->res);
#endif

				io_uring_cqe_seen(&ring1, cqe1);

				if(xorFlag == 0){
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
				goto error;
			}
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND\n");
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}

			goto error;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE\n");
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}

			goto error;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}

			goto error;
		}
	}else if(atyp == 0x3){	// domain name
		if(family == AF_INET){	// IPv4
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT\n");
#endif
				targetSock = socket(AF_INET, SOCK_STREAM, 0);

				flags = fcntl(targetSock, F_GETFL, 0);
				flags |= O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);

				while(io_uring_peek_cqe(&ring1, &cqe1) == 0){
					io_uring_cqe_seen(&ring1, cqe1);
				}

				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_connect(sqe1, targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr));

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					io_uring_cqe_seen(&ring1, cqe1);

#ifdef _DEBUG
					printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

					if(xorFlag == 0){
						sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
				}else{
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", cqe1->res);
#endif

					io_uring_cqe_seen(&ring1, cqe1);

					if(xorFlag == 0){
						sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
					goto error;
				}
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND\n");
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}

				goto error;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE\n");
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}

				goto error;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}

				goto error;
			}
		}else if(family == AF_INET6){	// IPv6
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
			printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

			if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:CONNECT\n");
#endif
				targetSock = socket(AF_INET6, SOCK_STREAM, 0);

				flags = fcntl(targetSock, F_GETFL, 0);
				flags |= O_NONBLOCK;
				fcntl(targetSock, F_SETFL, flags);

				while(io_uring_peek_cqe(&ring1, &cqe1) == 0){
					io_uring_cqe_seen(&ring1, cqe1);
				}

				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_connect(sqe1, targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6));

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					io_uring_cqe_seen(&ring1, cqe1);

#ifdef _DEBUG
					printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

					if(xorFlag == 0){
						sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
				}else{
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", cqe1->res);
#endif

					io_uring_cqe_seen(&ring1, cqe1);

					if(xorFlag == 0){
						sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
					goto error;
				}
			}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:BIND\n");
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}

				goto error;
			}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
				printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE\n");
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}

				goto error;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented\n");
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}

				goto error;
			}
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}

			goto error;
		}
	}else if(atyp == 0x4){	// IPv6
		inet_ntop(AF_INET6, &targetAddr6.sin6_addr, pTargetAddr6String, INET6_ADDRSTRLEN);
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT\n");
#endif
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);

			flags = fcntl(targetSock, F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

			while(io_uring_peek_cqe(&ring1, &cqe1) == 0){
				io_uring_cqe_seen(&ring1, cqe1);
			}

			sqe1 = io_uring_get_sqe(&ring1);

			io_uring_prep_connect(sqe1, targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6));

			ret = io_uring_submit(&ring1);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error;
			}

			ret = io_uring_wait_cqe(&ring1, &cqe1);
			if(ret >= 0 && cqe1->res >= 0){
				io_uring_cqe_seen(&ring1, cqe1);

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif

				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
			}else{
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", cqe1->res);
#endif

				io_uring_cqe_seen(&ring1, cqe1);

				if(xorFlag == 0){
					sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes\n", rec, sen);
#endif
				goto error;
			}
		}else if(cmd == 0x2){	// BIND
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:BIND\n");
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}

			goto error;
		}else if(cmd == 0x3){	// UDP ASSOCIATE
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:UDP ASSOCIATE\n");
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}

			goto error;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif

			if(xorFlag == 0){
				sen = sendSocksResponseIpv6(&ring1, clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}

			goto error;
		}
	}else{
#ifdef _DEBUG
		printf("[E] Not implemented\n");
#endif

		if(xorFlag == 0){
			sen = sendSocksResponseIpv4(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}else{
			sen = sendSocksResponseIpv4Xor(&ring1, clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}

		goto error;
	}


	// forwarder
#ifdef _DEBUG
	printf("[I] Forwarder\n");
#endif
	if(xorFlag == 0){
		err = forwarder(&ring1, &ring2, clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}else{
		err = forwarderXor(&ring1, &ring2, clientSock, targetSock, forwarder_tv_sec, forwarder_tv_usec);
	}


#ifdef _DEBUG
	printf("[I] Worker exit\n");
#endif
	io_uring_queue_exit(&ring1);
	io_uring_queue_exit(&ring2);

	close(targetSock);
	if(reverseFlag == 0){	// Nomal mode
		close(clientSock);
	}

	return 0;

error:
	io_uring_queue_exit(&ring1);
	io_uring_queue_exit(&ring2);

	close(targetSock);
	if(reverseFlag == 0){	// Nomal mode
		close(clientSock);
	}

	return -1;
}

void usage(char *filename)
{
	printf("Normal mode  : client -> server\n");
	printf("usage        : %s -h listen_ip -p listen_port\n", filename);
	printf("             : [-x (xor encryption] [-k key(hexstring)]\n");
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -h 0.0.0.0 -p 9050\n", filename);
	printf("             : %s -h localhost -p 9050 -x -k deadbeef\n", filename);
	printf("             : %s -h ::1 -p 9050 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -p 9050 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -H socks5client_ip -P socks5client_port\n", filename);
	printf("             : [-x (xor encryption] [-k key(hexstring)]\n");
	printf("             : [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n");
	printf("example      : %s -r -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -H localhost -P 1234 -x -k deadbeef\n", filename);
	printf("             : %s -r -H ::1 -P 1234 -x -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -H fe80::xxxx:xxxx:xxxx:xxxx%%eth0 -P 1234 -x -A 3 -B 0 -C 3 -D 0\n", filename);
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
			socks5ClientIp = optarg;
			break;

		case 'P':
			socks5ClientPort = optarg;
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

	if(reverseFlag == 0 && socks5ServerIp == NULL || reverseFlag == 0 && socks5ServerPort == NULL || reverseFlag == 1 && socks5ClientIp == NULL || reverseFlag == 1 && socks5ClientPort == NULL){
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

	int serverSock = -1;
	int clientSock = -1;
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

	struct io_uring ring;
	struct io_uring_sqe *sqe = NULL;
	struct io_uring_cqe *cqe = NULL;
	struct io_uring_params ringParams;
	memset(&ringParams, 0, sizeof(struct io_uring_params));
	ringParams.flags = 0;

	ret = io_uring_queue_init_params(RING_QUEUE_DEPTH, &ring, &ringParams);
	if(ret < 0){
#ifdef _DEBUG
		printf("[E] io_uring_queue_init_params error:%d\n", ret);
#endif
		return -1;
	}

	pPARAM pParam;


	if(reverseFlag == 0){	// Nomal mode
#ifdef _DEBUG
		printf("[I] Nomal mode\n");
#endif
		if(xorFlag == 1){
#ifdef _DEBUG
			printf("[I] Xor encryption:on\n");
			printf("[I] Xor key:\n");
			printBytes(xorKey, xorKeyLength);
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Xor encryption:off\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec\n", forwarder_tv_sec, forwarder_tv_usec);
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
					goto error1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
				goto error1;
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
			goto error1;
		}

		if(family == AF_INET){	// IPv4
			serverSock = socket(AF_INET, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error1;
			}

			// listen
			listen(serverSock, 5);
#ifdef _DEBUG
			printf("[I] Listenning port %d on %s\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

			// accept
			while(1){
				sqe = io_uring_get_sqe(&ring);

				io_uring_prep_accept(sqe, serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error1;
				}

				ret = io_uring_wait_cqe(&ring, &cqe);
				if(ret >= 0 && cqe->res >= 0){
					clientSock = cqe->res;

#ifdef _DEBUG
					printf("[I] Connected from ip:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

					flags = fcntl(clientSock, F_GETFL, 0);
					flags |= O_NONBLOCK;
					fcntl(clientSock, F_SETFL, flags);

					pthread_t thread;

					pParam = (pPARAM)calloc(1, sizeof(PARAM));
					pParam->clientSock = clientSock;
					pParam->tv_sec = tv_sec;
					pParam->tv_usec = tv_usec;
					pParam->forwarder_tv_sec = forwarder_tv_sec;
					pParam->forwarder_tv_usec = forwarder_tv_usec;

					if(pthread_create(&thread, NULL, (void *)worker, pParam)){
#ifdef _DEBUG
						printf("[E] pthread_create failed\n");
#endif
						close(clientSock);
					}else{
						pthread_detach(thread);
					}
				}else{
#ifdef _DEBUG
					printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif
				}

				io_uring_cqe_seen(&ring, cqe);
			}
		}else if(family == AF_INET6){	// IPv6
			serverSock = socket(AF_INET6, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error1;
			}

			// listen
			listen(serverSock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &serverAddr6.sin6_addr, serverAddr6StringPointer, INET6_ADDRSTRLEN);
			if(serverAddr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer, serverAddr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s\n", ntohs(serverAddr6.sin6_port), serverAddr6StringPointer);
			}
#endif

			// accept
			while(1){
				sqe = io_uring_get_sqe(&ring);

				io_uring_prep_accept(sqe, serverSock, (struct sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error1;
				}

				ret = io_uring_wait_cqe(&ring, &cqe);
				if(ret >= 0 && cqe->res >= 0){
					clientSock = cqe->res;

#ifdef _DEBUG
					inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
					if(clientAddr6.sin6_scope_id > 0){
						printf("[I] Connected from ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
					}else{
						printf("[I] Connected from ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
					}
#endif

					flags = fcntl(clientSock, F_GETFL, 0);
					flags |= O_NONBLOCK;
					fcntl(clientSock, F_SETFL, flags);

					pthread_t thread;

					pParam = (pPARAM)calloc(1, sizeof(PARAM));
					pParam->clientSock = clientSock;
					pParam->tv_sec = tv_sec;
					pParam->tv_usec = tv_usec;
					pParam->forwarder_tv_sec = forwarder_tv_sec;
					pParam->forwarder_tv_usec = forwarder_tv_usec;

					if(pthread_create(&thread, NULL, (void *)worker, pParam)){
#ifdef _DEBUG
						printf("[E] pthread_create failed\n");
#endif
						close(clientSock);
					}else{
						pthread_detach(thread);
					}
				}else{
#ifdef _DEBUG
					printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif
				}

				io_uring_cqe_seen(&ring, cqe);
			}
		}

		io_uring_queue_exit(&ring);
		close(serverSock);

	}else{	// Reverse mode
#ifdef _DEBUG
		printf("[I] Reverse mode\n");
#endif
		if(xorFlag == 1){
#ifdef _DEBUG
			printf("[I] Xor encryption:on\n");
			printf("[I] Xor key:\n");
			printBytes(xorKey, xorKeyLength);
#endif
		}else{
#ifdef _DEBUG
			printf("[I] Xor encryption:off\n");
#endif
		}
#ifdef _DEBUG
		printf("[I] Timeout recv/send tv_sec(0-10 sec):%ld sec recv/send tv_usec(0-1000000 microsec):%ld microsec\n", tv_sec, tv_usec);
		printf("[I] Timeout forwarder tv_sec(0-3600 sec):%ld sec forwarder tv_usec(0-1000000 microsec):%ld microsec\n", forwarder_tv_sec, forwarder_tv_usec);
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
					goto error2;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(clientDomainname, clientPortNumber, &hints, &clientHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", clientDomainname);
#endif
				goto error2;
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
			goto error2;
		}

		if(family == AF_INET){	// IPv4
			clientSock = socket(AF_INET, SOCK_STREAM, 0);

			flags = fcntl(clientSock, F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(clientSock, F_SETFL, flags);

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

			sqe = io_uring_get_sqe(&ring);

			io_uring_prep_connect(sqe, clientSock, (struct sockaddr *)&clientAddr, sizeof(clientAddr));

			ret = io_uring_submit(&ring);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error2;
			}

			ret = io_uring_wait_cqe(&ring, &cqe);
			if(ret >= 0 && cqe->res >= 0){
#ifdef _DEBUG
				printf("[I] Connected to ip:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif
			}else{
#ifdef _DEBUG
				printf("[E] Connect failed. errno: %d", cqe->res);
#endif

				io_uring_cqe_seen(&ring, cqe);

				goto error2;
			}

			io_uring_cqe_seen(&ring, cqe);
		}else if(family == AF_INET6){	// IPv6
			clientSock = socket(AF_INET6, SOCK_STREAM, 0);

			flags = fcntl(clientSock, F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(clientSock, F_SETFL, flags);

#ifdef _DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0){
				printf("[I] Connecting ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else{
				printf("[I] Connecting ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif

			sqe = io_uring_get_sqe(&ring);

			io_uring_prep_connect(sqe, clientSock, (struct sockaddr *)&clientAddr6, sizeof(clientAddr6));

			ret = io_uring_submit(&ring);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error2;
			}

			ret = io_uring_wait_cqe(&ring, &cqe);
			if(ret >= 0 && cqe->res >= 0){
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
				printf("[E] Connect failed. errno: %d", cqe->res);
#endif

				io_uring_cqe_seen(&ring, cqe);

				goto error2;
			}

			io_uring_cqe_seen(&ring, cqe);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			goto error2;
		}


		while(1){
			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->clientSock = clientSock;
			pParam->tv_sec = tv_sec;
			pParam->tv_usec = tv_usec;
			pParam->forwarder_tv_sec = forwarder_tv_sec;
			pParam->forwarder_tv_usec = forwarder_tv_usec;

			err = worker(pParam);
			if(err < 0){
				break;
			}
		}

		io_uring_queue_exit(&ring);
		close(clientSock);
	}

	return 0;

error1:
	io_uring_queue_exit(&ring);
	close(serverSock);

	return -1;

error2:
	io_uring_queue_exit(&ring);
	close(clientSock);

	return -1;
}


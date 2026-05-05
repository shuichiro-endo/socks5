/*
 * Title:  socks5 client (Linux liburing)
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

#include "client.h"
#include "socks5.h"

#define RING_QUEUE_DEPTH	8
#define UINT32_SIZE			sizeof(uint32_t)


char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5TargetIp = NULL;
char *socks5TargetPort = NULL;
char *socks5Server2Ip = NULL;
char *socks5Server2Port = NULL;
int reverseFlag = 0;
int xorFlag = 0;

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


int loadLengthFromBuffer(const char *buffer)
{
	uint32_t net = 0;
	uint32_t host = 0;

	memcpy(&net, buffer, sizeof(net));
	host = ntohl(net);

	return (int)host;
}


void storeLengthToBuffer(int length, char *buffer)
{
	uint32_t u = (uint32_t)length;
	uint32_t net = htonl(u);

	memcpy(buffer, &net, sizeof(net));
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
	int recvLength = 0;
	int len = 0;
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
	int recvSizeActive = 0;
	int recvActive = 0;

	bzero(buffer, length+1);

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeRecv = io_uring_get_sqe(ring);
	if(sqeRecv == NULL){
		goto error;
	}

	io_uring_prep_recv(sqeRecv, sock, buffer, UINT32_SIZE, 0);
	sqeRecv->user_data = idRecv;
	recvSizeActive = 1;
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
				recvLength += rec;

				if(recvSizeActive == 1){
					if(recvLength == UINT32_SIZE){
						recvSizeActive = 0;

						len = loadLengthFromBuffer(buffer);
						bzero(buffer, length+1);

						sqeRecv = io_uring_get_sqe(ring);
						if(sqeRecv == NULL){
							goto error;
						}

						io_uring_prep_recv(sqeRecv, sock, buffer, len, 0);
						sqeRecv->user_data = idRecv;

						ret = io_uring_submit(ring);
						if(ret < 0){
							goto error;
						}

						recvLength = 0;
						recvActive = 1;
					}else if(recvLength < UINT32_SIZE){
						sqeRecv = io_uring_get_sqe(ring);
						if(sqeRecv == NULL){
							goto error;
						}

						io_uring_prep_recv(sqeRecv, sock, buffer+recvLength, UINT32_SIZE-recvLength, 0);
						sqeRecv->user_data = idRecv;

						ret = io_uring_submit(ring);
						if(ret < 0){
							goto error;
						}

						recvSizeActive = 1;
						recvActive = 1;
					}else{
						recvSizeActive = 0;
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
				}else{
					if(recvActive == 1){
						if(recvLength == len){
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
						}else if(recvLength < len){
							sqeRecv = io_uring_get_sqe(ring);
							if(sqeRecv == NULL){
								goto error;
							}

							io_uring_prep_recv(sqeRecv, sock, buffer+recvLength, len-recvLength, 0);
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

					}else{
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
				}
			}else if(rec == -EAGAIN || rec == -EWOULDBLOCK){
				usleep(5000);

				if(recvSizeActive == 1){
					sqeRecv = io_uring_get_sqe(ring);
					if(sqeRecv == NULL){
						goto error;
					}

					io_uring_prep_recv(sqeRecv, sock, buffer+recvLength, UINT32_SIZE-recvLength, 0);
					sqeRecv->user_data = idRecv;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}

					recvSizeActive = 1;
					recvActive = 1;
				}else{
					sqeRecv = io_uring_get_sqe(ring);
					if(sqeRecv == NULL){
						goto error;
					}

					io_uring_prep_recv(sqeRecv, sock, buffer+recvLength, len-recvLength, 0);
					sqeRecv->user_data = idRecv;

					ret = io_uring_submit(ring);
					if(ret < 0){
						goto error;
					}

					recvActive = 1;
				}
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

	if(recvLength > 0 && recvLength <= BUFSIZ){
		xor((unsigned char *)buffer, recvLength, xorKey, xorKeyLength);
	}else{
		goto error;
	}

	return recvLength;

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
	int len = 0;
	char buffer2[BUFSIZ+UINT32_SIZE+1] = {0};
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

	if(length > 0 && length <= BUFSIZ){
		xor((unsigned char *)buffer, length, xorKey, xorKeyLength);
	}else{
		goto error;
	}

	storeLengthToBuffer(length, buffer2);
	memcpy(buffer2+UINT32_SIZE, buffer, length);
	len = length + UINT32_SIZE;

	while(io_uring_peek_cqe(ring, &cqe) == 0){
		io_uring_cqe_seen(ring, cqe);
	}

	sqeSend = io_uring_get_sqe(ring);
	if(sqeSend == NULL){
		goto error;
	}

	io_uring_prep_send(sqeSend, sock, buffer2, len, 0);
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

					io_uring_prep_send(sqeSend, sock, buffer2+sendLength, len, 0);
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

				io_uring_prep_send(sqeSend, sock, buffer2+sendLength, len, 0);
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

	return sendLength - UINT32_SIZE;

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

		rec = recvData(ring, clientSock, buffer, BUFSIZ, tv_sec, tv_usec);
		if(rec > 0){
			sen = sendDataXor(ring, targetSock, buffer, rec, tv_sec, tv_usec);
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

		rec = recvDataXor(ring, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
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
	
	int rec, sen;
	char buffer[BUFSIZ+1];
	bzero(buffer, BUFSIZ+1);
	
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
			flags |= O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

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
#ifdef _DEBUG
				printf("[I] Connected to ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
			}else{
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d", cqe1->res);
#endif

				io_uring_cqe_seen(&ring1, cqe1);

				goto error;
			}

			io_uring_cqe_seen(&ring1, cqe1);
		}else if(family == AF_INET6){	// IPv6
			targetSock = socket(AF_INET6, SOCK_STREAM, 0);

			flags = fcntl(targetSock, F_GETFL, 0);
			flags |= O_NONBLOCK;
			fcntl(targetSock, F_SETFL, flags);

#ifdef _DEBUG
			inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
			if(targetAddr6.sin6_scope_id > 0){
				printf("[I] Connecting to ip:%s%%%d port:%d\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
			}else{
				printf("[I] Connecting to ip:%s port:%d\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
			}
#endif

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
				printf("[E] Connect failed. errno:%d", cqe1->res);
#endif

				io_uring_cqe_seen(&ring1, cqe1);

				goto error;
			}

			io_uring_cqe_seen(&ring1, cqe1);
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented\n");
#endif
			goto error;
		}
	}


	// socks SELECTION_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving selection request. client -> server\n");
#endif
	if((rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving selection request error. client -> server\n");
#endif
		goto error;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection request:%d bytes. client -> server\n", rec);
#endif


	// socks SELECTION_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending selection request. server -> target\n");
#endif
	if(xorFlag == 0){
		sen = sendData(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
	}else{
		sen = sendDataXor(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send selection request:%d bytes. server -> target\n", sen);
#endif


	// socks SELECTION_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving selection response. server <- target\n");
#endif
	if(xorFlag == 0){
		rec = recvData(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataXor(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec != sizeof(SELECTION_RESPONSE)){
#ifdef _DEBUG
		printf("[E] Recieving selection response error. server <- target\n");
#endif
		goto error;
	}
#ifdef _DEBUG
	printf("[I] Recieve selection response:%d bytes. server <- target\n", rec);
#endif


	// socks SELECTION_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending selection response. client <- server\n");
#endif
	sen = sendData(&ring1, clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send selection response:%d bytes. client <- server\n", sen);
#endif
	pSELECTION_RESPONSE pSelectionResponse = (pSELECTION_RESPONSE)buffer;
	if((unsigned char)pSelectionResponse->method == 0xFF){
#ifdef _DEBUG
		printf("[E] Target socks5server Authentication Method error\n");
#endif
	}

	if(pSelectionResponse->method == 0x2){	// USERNAME_PASSWORD_AUTHENTICATION
		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		client -> server
#ifdef _DEBUG
		printf("[I] Recieving username password authentication request. client -> server\n");
#endif
		if((rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication request error. client -> server\n");
#endif
			goto error;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication request:%d bytes. client -> server\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST		server -> target
#ifdef _DEBUG
		printf("[I] Sending username password authentication request. server -> target\n");
#endif
		if(xorFlag == 0){
			sen = sendData(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
		}else{
			sen = sendDataXor(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
		}
#ifdef _DEBUG
		printf("[I] Send username password authentication request:%d bytes. server -> target\n", sen);
#endif
		

		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	server <- target
#ifdef _DEBUG
		printf("[I] Recieving username password authentication response. server <- target\n");
#endif
		if(xorFlag == 0){
			rec = recvData(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}else{
			rec = recvDataXor(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Recieving username password authentication response error. server <- target\n");
#endif
			goto error;
		}
#ifdef _DEBUG
		printf("[I] Recieve username password authentication response:%d bytes. server <- target\n", rec);
#endif


		// socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE	client <- server
#ifdef _DEBUG
		printf("[I] Sending username password authentication response. client <- server\n");
#endif
		sen = sendData(&ring1, clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
		printf("[I] Send username password authentication response:%d bytes. client <- server\n", sen);
#endif
	}


	// socks SOCKS_REQUEST	client -> server
#ifdef _DEBUG
	printf("[I] Recieving socks request. client -> server\n");
#endif
	if((rec = recvData(&ring1, clientSock, buffer, BUFSIZ, tv_sec, tv_usec)) <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks request error. client -> server\n");
#endif
		goto error;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks request:%d bytes. client -> server\n", rec);
#endif


	// socks SOCKS_REQUEST	server -> target
#ifdef _DEBUG
	printf("[I] Sending socks request. server -> target\n");
#endif
	if(xorFlag == 0){
		sen = sendData(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
	}else{
		sen = sendDataXor(&ring1, targetSock, buffer, rec, tv_sec, tv_usec);
	}
#ifdef _DEBUG
	printf("[I] Send socks request:%d bytes. server -> target\n", sen);
#endif
	
	
	// socks SOCKS_RESPONSE	server <- target
#ifdef _DEBUG
	printf("[I] Recieving socks response. server <- target\n");
#endif
	if(xorFlag == 0){
		rec = recvData(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}else{
		rec = recvDataXor(&ring1, targetSock, buffer, BUFSIZ, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Recieving socks response error. server <- target\n");
#endif
		goto error;
	}
#ifdef _DEBUG
	printf("[I] Recieve socks response:%d bytes. server <- target\n", rec);
#endif


	// socks SOCKS_RESPONSE	client <- server
#ifdef _DEBUG
	printf("[I] Sending socks response. client <- server\n");
#endif
	sen = sendData(&ring1, clientSock, buffer, rec, tv_sec, tv_usec);
#ifdef _DEBUG
	printf("[I] Send socks response:%d bytes. client <- server\n", sen);
#endif


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

	if(reverseFlag == 0){	// Nomal mode
		close(targetSock);
	}
	close(clientSock);

	return 0;

error:
	io_uring_queue_exit(&ring1);
	io_uring_queue_exit(&ring2);

	if(reverseFlag == 0){	// Nomal mode
		close(targetSock);
	}
	close(clientSock);

	return -1;
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
	
	int serverSock = -1;
	int clientSock = -1;
	int server2Sock = -1;
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
	int ret = 0;
	int err = 0;

	struct io_uring ring1;
	struct io_uring ring2;
	struct io_uring_sqe *sqe1 = NULL;
	struct io_uring_sqe *sqe2 = NULL;
	struct io_uring_cqe *cqe1 = NULL;
	struct io_uring_cqe *cqe2 = NULL;
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
				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_accept(sqe1, serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error1;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					clientSock = cqe1->res;

#ifdef _DEBUG
					printf("[I] Connected from ip:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

					flags = fcntl(clientSock, F_GETFL, 0);
					flags |= O_NONBLOCK;
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

				io_uring_cqe_seen(&ring1, cqe1);
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
				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_accept(sqe1, serverSock, (struct sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error1;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					clientSock = cqe1->res;

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
					pParam->targetSock = targetSock;
					pParam->clientSock = clientSock;
					pParam->tv_sec = tv_sec;
					pParam->tv_usec = tv_usec;
					pParam->forwarder_tv_sec = forwarder_tv_sec;
					pParam->forwarder_tv_usec = forwarder_tv_usec;

					if(pthread_create(&thread, NULL, (void *)worker, pParam))
					{
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

				io_uring_cqe_seen(&ring1, cqe1);
			}
		}

		io_uring_queue_exit(&ring1);
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

		ret = io_uring_queue_init_params(RING_QUEUE_DEPTH, &ring2, &ringParams2);
		if(ret < 0){
#ifdef _DEBUG
			printf("[E] io_uring_queue_init_params error:%d\n", ret);
#endif

			io_uring_queue_exit(&ring1);
			return -1;
		}

		colon = strstr(server2Domainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints2.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
				hints2.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
					goto error2;
				}
			}
		}else{	// ipv6 address
			hints2.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(server2Domainname, server2PortNumber, &hints2, &server2Host) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", server2Domainname);
#endif
				goto error2;
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
			goto error2;
		}

		if(family == AF_INET){	// IPv4
			server2Sock = socket(AF_INET, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(server2Sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(server2Sock, (struct sockaddr *)&server2Addr, sizeof(server2Addr)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error2;
			}

			// listen
			listen(server2Sock, 5);
#ifdef _DEBUG
			printf("[I] Listenning port %d on %s\n", ntohs(server2Addr.sin_port), inet_ntoa(server2Addr.sin_addr));
#endif

			// accept
			sqe2 = io_uring_get_sqe(&ring2);

			io_uring_prep_accept(sqe2, server2Sock, (struct sockaddr *)&targetAddr, (socklen_t *)&targetAddrLen, SOCK_NONBLOCK);

			ret = io_uring_submit(&ring2);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error2;
			}

			ret = io_uring_wait_cqe(&ring2, &cqe2);
			if(ret >= 0 && cqe2->res >= 0){
				targetSock = cqe2->res;

#ifdef _DEBUG
				printf("[I] Connected from ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

				io_uring_cqe_seen(&ring2, cqe2);
			}else{
#ifdef _DEBUG
				printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif
				io_uring_cqe_seen(&ring2, cqe2);
				goto error2;
			}
		}else if(family == AF_INET6){	// IPv6
			server2Sock = socket(AF_INET6, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(server2Sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(server2Sock, (struct sockaddr *)&server2Addr6, sizeof(server2Addr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error2;
			}

			// listen
			listen(server2Sock, 5);
#ifdef _DEBUG
			inet_ntop(AF_INET6, &server2Addr6.sin6_addr, server2Addr6StringPointer, INET6_ADDRSTRLEN);
			if(server2Addr6.sin6_scope_id > 0){
				printf("[I] Listening port %d on %s%%%d\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer, server2Addr6.sin6_scope_id);
			}else{
				printf("[I] Listening port %d on %s\n", ntohs(server2Addr6.sin6_port), server2Addr6StringPointer);
			}
#endif

			// accept
			sqe2 = io_uring_get_sqe(&ring2);

			io_uring_prep_accept(sqe2, server2Sock, (struct sockaddr *)&targetAddr6, (socklen_t *)&targetAddr6Len, SOCK_NONBLOCK);

			ret = io_uring_submit(&ring2);
			if(ret < 0){
#ifdef _DEBUG
				printf("[E] io_uring_submit error:%d\n", ret);
#endif
				goto error2;
			}

			ret = io_uring_wait_cqe(&ring2, &cqe2);
			if(ret >= 0 && cqe2->res >= 0){
				targetSock = cqe2->res;

#ifdef _DEBUG
				inet_ntop(AF_INET6, &targetAddr6.sin6_addr, targetAddr6StringPointer, INET6_ADDRSTRLEN);
				if(targetAddr6.sin6_scope_id > 0){
					printf("[I] Connected from ip:%s%%%d port:%d\n", targetAddr6StringPointer, targetAddr6.sin6_scope_id, ntohs(targetAddr6.sin6_port));
				}else{
					printf("[I] Connected from ip:%s port:%d\n", targetAddr6StringPointer, ntohs(targetAddr6.sin6_port));
				}
#endif

				io_uring_cqe_seen(&ring2, cqe2);
			}else{
#ifdef _DEBUG
				printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif
				io_uring_cqe_seen(&ring2, cqe2);
				goto error2;
			}
		}

		flags = fcntl(targetSock, F_GETFL, 0);
		flags |= O_NONBLOCK;
		fcntl(targetSock, F_SETFL, flags);

		colon = strstr(serverDomainname, ":");	// check ipv6 address
		if(colon == NULL){	// ipv4 address or domainname
			hints.ai_family = AF_INET;	// IPv4
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
				hints.ai_family = AF_INET6;	// IPv6
				if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
					printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
					goto error2;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(serverDomainname, serverPortNumber, &hints, &serverHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", serverDomainname);
#endif
				goto error2;
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
			goto error2;
		}

		if(family == AF_INET){	// IPv4
			serverSock = socket(AF_INET, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error2;
			}

			// listen
			listen(serverSock, 5);
#ifdef _DEBUG
			printf("[I] Listenning port %d on %s\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

			// accept
			while(1){
				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_accept(sqe1, serverSock, (struct sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error2;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					clientSock = cqe1->res;

#ifdef _DEBUG
					printf("[I] Connected from ip:%s port:%d\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

					io_uring_cqe_seen(&ring1, cqe1);

					flags = fcntl(clientSock, F_GETFL, 0);
					flags |= O_NONBLOCK;
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
					if(err < 0){
						break;
					}
				}else{
#ifdef _DEBUG
					printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif

					io_uring_cqe_seen(&ring1, cqe1);
				}
			}
		}else if(family == AF_INET6){	// IPv6
			serverSock = socket(AF_INET6, SOCK_STREAM, 0);
			reuse = 1;
			setsockopt(serverSock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

			// bind
			if(bind(serverSock, (struct sockaddr *) &serverAddr6, sizeof(serverAddr6)) == -1) {
#ifdef _DEBUG
				printf("[E] bind error\n");
#endif
				goto error2;
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
				sqe1 = io_uring_get_sqe(&ring1);

				io_uring_prep_accept(sqe1, serverSock, (struct sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len, SOCK_NONBLOCK);

				ret = io_uring_submit(&ring1);
				if(ret < 0){
#ifdef _DEBUG
					printf("[E] io_uring_submit error:%d\n", ret);
#endif
					goto error2;
				}

				ret = io_uring_wait_cqe(&ring1, &cqe1);
				if(ret >= 0 && cqe1->res >= 0){
					clientSock = cqe1->res;

#ifdef _DEBUG
					inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
					if(clientAddr6.sin6_scope_id > 0){
						printf("[I] Connected from ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
					}else{
						printf("[I] Connected from ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
					}
#endif

					io_uring_cqe_seen(&ring1, cqe1);

					flags = fcntl(clientSock, F_GETFL, 0);
					flags |= O_NONBLOCK;
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
					if(err < 0){
						break;
					}
				}else{
#ifdef _DEBUG
					printf("[E] io_uring_wait_cqe error:%d\n", ret);
#endif

					io_uring_cqe_seen(&ring1, cqe1);
				}
			}
		}

		io_uring_queue_exit(&ring2);
		io_uring_queue_exit(&ring1);
		close(targetSock);
		close(server2Sock);
		close(serverSock);
	}

	return 0;

error1:
	io_uring_queue_exit(&ring1);
	close(serverSock);

	return -1;

error2:
	io_uring_queue_exit(&ring2);
	io_uring_queue_exit(&ring1);
	close(targetSock);
	close(server2Sock);
	close(serverSock);

	return -1;
}

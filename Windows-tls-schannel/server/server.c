/*
 * Title:  socks5 server (Windows)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#define SECURITY_WIN32
#include <stdio.h>
#include <stdbool.h>
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <string.h>
#include <iostream>
#include <stdlib.h>
#include <process.h>

#include <Security.h>
#include <schannel.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include "socks5.h"
#include "server.h"

#pragma comment(lib,"ws2_32.lib")	// Winsock Library
#pragma comment(lib,"Secur32.lib")	// Secur32 Library
#pragma comment(lib,"Crypt32.lib")	// Crypt32 Library
#pragma comment(lib,"Ncrypt.lib")	// Ncrypt Library

#define BUFFER_SIZE 81920
#define CERT_NAME_MAX_SIZE 1024

int optstringIndex = 0;
char *optarg = NULL;

char *socks5ServerIp = NULL;
char *socks5ServerPort = NULL;
char *socks5ClientIp = NULL;
char *socks5ClientPort = NULL;
int reverseFlag = 0;
int tlsFlag = 0;

static char authenticationMethod = 0x0;	// 0x0:No Authentication Required	0x2:Username/Password Authentication
char username[256] = "socks5user";
char password[256] = "supersecretpassword";


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



int encryptMessage(CtxtHandle *pClientContextHandle, SecPkgContext_StreamSizes streamSizes, char *input, int inputLength, char *output, int outputLength)
{
	SecBuffer secBuffer[4] = {0};
	SecBufferDesc secBufferDesc = {0};
	SECURITY_STATUS status;
	int encryptMessageLength = 0;

	if(inputLength > (int)streamSizes.cbMaximumMessage){
#ifdef _DEBUG
		printf("[E] input length is too long.\n");
#endif
		return -1;
	}

	if(outputLength < streamSizes.cbHeader + inputLength + streamSizes.cbTrailer){
#ifdef _DEBUG
		printf("[E] output length is too small.\n");
#endif
		return -1;
	}

	secBuffer[0].BufferType = SECBUFFER_STREAM_HEADER;
	secBuffer[0].pvBuffer = output;
	secBuffer[0].cbBuffer = streamSizes.cbHeader;
	secBuffer[1].BufferType = SECBUFFER_DATA;
	secBuffer[1].pvBuffer = output + streamSizes.cbHeader;
	secBuffer[1].cbBuffer = inputLength;
	secBuffer[2].BufferType = SECBUFFER_STREAM_TRAILER;
	secBuffer[2].pvBuffer = output + streamSizes.cbHeader + inputLength;
	secBuffer[2].cbBuffer = streamSizes.cbTrailer;
	secBuffer[3].BufferType = SECBUFFER_EMPTY;
	secBuffer[3].pvBuffer = NULL;
	secBuffer[3].cbBuffer = 0;

	memcpy(secBuffer[1].pvBuffer, input, inputLength);

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = secBuffer;

	status = EncryptMessage(pClientContextHandle, 0, &secBufferDesc, 0);
	if(status != SEC_E_OK){
#ifdef _DEBUG
		printf("[E] EncryptMessage error:%x\n", status);
#endif
		return -1;
	}

	encryptMessageLength = secBuffer[0].cbBuffer + secBuffer[1].cbBuffer + secBuffer[2].cbBuffer;

	return encryptMessageLength;
}

/*
 * Reference:
 * https://stackoverflow.com/questions/61197818/how-to-detect-termination-character-in-schannel-based-https-client
 */
int decryptMessage(CtxtHandle *pClientContextHandle, SecPkgContext_StreamSizes streamSizes, char *input, int *inputLength, char *output, int outputLength, int *decryptMessageLength)
{
	int messageLength = 0;
	SecBuffer secBuffer[4] = {0};
	SecBufferDesc secBufferDesc = {0};
	SECURITY_STATUS status;

	messageLength = *inputLength - streamSizes.cbHeader - streamSizes.cbTrailer;
	if(messageLength > (int)streamSizes.cbMaximumMessage){
#ifdef _DEBUG
		printf("[E] message length is too long.\n");
#endif
		return -1;
	}

	if(outputLength < messageLength){
#ifdef _DEBUG
		printf("[E] output length is too small.\n");
#endif
		return -1;
	}

	secBuffer[0].BufferType = SECBUFFER_DATA;
	secBuffer[0].pvBuffer = input;
	secBuffer[0].cbBuffer = *inputLength;
	secBuffer[1].BufferType = SECBUFFER_EMPTY;
	secBuffer[1].pvBuffer = NULL;
	secBuffer[1].cbBuffer = 0;
	secBuffer[2].BufferType = SECBUFFER_EMPTY;
	secBuffer[2].pvBuffer = NULL;
	secBuffer[2].cbBuffer = 0;
	secBuffer[3].BufferType = SECBUFFER_EMPTY;
	secBuffer[3].pvBuffer = NULL;
	secBuffer[3].cbBuffer = 0;

	secBufferDesc.ulVersion = SECBUFFER_VERSION;
	secBufferDesc.cBuffers = 4;
	secBufferDesc.pBuffers = secBuffer;

	while(1){
		status = DecryptMessage(pClientContextHandle, &secBufferDesc, 0, NULL);
		if(status == SEC_E_INCOMPLETE_MESSAGE){
#ifdef _DEBUG
			printf("[I] SEC_E_INCOMPLETE_MESSAGE\n");
#endif
			return 1;
		}else if(status == SEC_E_DECRYPT_FAILURE){
#ifdef _DEBUG
			printf("[I] SEC_E_DECRYPT_FAILURE\n");
#endif
			return 2;
		}else if(status != SEC_E_OK){
#ifdef _DEBUG
			printf("[E] DecryptMessage error:%x\n", status);
#endif
			return -1;
		}

		if(secBuffer[1].BufferType == SECBUFFER_DATA){
			memcpy(output + *decryptMessageLength, secBuffer[1].pvBuffer, secBuffer[1].cbBuffer);
			*decryptMessageLength += secBuffer[1].cbBuffer;

			if(secBuffer[3].cbBuffer != 0){
				memcpy(input, secBuffer[3].pvBuffer, secBuffer[3].cbBuffer);
				*inputLength = secBuffer[3].cbBuffer;

				secBuffer[0].BufferType = SECBUFFER_DATA;
				secBuffer[0].pvBuffer = input;
				secBuffer[0].cbBuffer = *inputLength;
				secBuffer[1].BufferType = SECBUFFER_EMPTY;
				secBuffer[1].pvBuffer = NULL;
				secBuffer[1].cbBuffer = 0;
				secBuffer[2].BufferType = SECBUFFER_EMPTY;
				secBuffer[2].pvBuffer = NULL;
				secBuffer[2].cbBuffer = 0;
				secBuffer[3].BufferType = SECBUFFER_EMPTY;
				secBuffer[3].pvBuffer = NULL;
				secBuffer[3].cbBuffer = 0;

				continue;
			}else{
				break;
			}
		}else{
#ifdef _DEBUG
			printf("[E] secBuffer[1].BufferType error:%x\n", secBuffer[1].BufferType);
#endif
			return -1;
		}
	}

	return 0;
}


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


int recvDataTls(SOCKET socket, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, void *buffer, int length, long tv_sec, long tv_usec)
{
	int rec = 0;
	int tmprec = 0;
	int ret = 0;
	int err = 0;
	fd_set readfds;
	timeval tv;
	char buffer2[BUFFER_SIZE+1];
	char tmp[BUFFER_SIZE+1];
	ZeroMemory(buffer, length+1);
	ZeroMemory(buffer2, BUFFER_SIZE+1);
	ZeroMemory(tmp, BUFFER_SIZE+1);
	int decryptMessageLength = 0;

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
			}else if(rec == 0){
				decryptMessageLength = 0;
				break;
			}else{
				if(tmprec + rec <= BUFFER_SIZE){
					memcpy(tmp+tmprec, buffer, rec);
					tmprec += rec;
					ZeroMemory(buffer, length+1);

					ret = decryptMessage(pContextHandle, streamSizes, (char *)tmp, &tmprec, buffer2, BUFFER_SIZE, &decryptMessageLength);
					if(ret == 1){	// SEC_E_INCOMPLETE_MESSAGE
						continue;
					}else if(ret == 2){	// SEC_E_DECRYPT_FAILURE
						tmprec = 0;
						ZeroMemory(tmp, BUFFER_SIZE+1);
						continue;
					}else if(ret < 0){
#ifdef _DEBUG
						printf("[E] decryptMessage error\n");
#endif
						return -2;
					}else{
						memcpy(buffer, buffer2, decryptMessageLength);
						break;
					}
				}else{
#ifdef _DEBUG
						printf("[E] received data size has exceeded the maximum value\n");
#endif
						return -2;
				}
			}
		}
	}

	return decryptMessageLength;
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


int sendDataTls(SOCKET socket, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, void *buffer, int length, long tv_sec, long tv_usec)
{
	int sen = 0;
	int sendLength = 0;
	int len = 0;
	int err = 0;
	fd_set writefds;
	timeval tv;
	char buffer2[BUFFER_SIZE+1];
	ZeroMemory(buffer2, BUFFER_SIZE+1);

	len = encryptMessage(pContextHandle, streamSizes, (char *)buffer, length, buffer2, BUFFER_SIZE);
	if(len < 0){
#ifdef _DEBUG
		printf("[E] encryptMessage error\n");
#endif
		return -2;
	}
	memcpy(buffer, buffer2, len);

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

	return length;
}


int forwarder(SOCKET clientSock, SOCKET targetSock, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	timeval tv;
	char buffer[BUFFER_SIZE+1];
	ZeroMemory(buffer, BUFFER_SIZE+1);
	
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
			if((rec = recv(clientSock, buffer, BUFFER_SIZE, 0)) > 0){
				sen = send(targetSock, buffer, rec, 0);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}
		
		if(FD_ISSET(targetSock, &readfds)){
			if((rec = recv(targetSock, buffer, BUFFER_SIZE, 0)) > 0){
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


int forwarderTls(SOCKET clientSock, SOCKET targetSock, CtxtHandle *pClientContextHandle, SecPkgContext_StreamSizes streamSizes, long tv_sec, long tv_usec)
{
	int rec, sen;
	fd_set readfds;
	timeval tv;
	char buffer[BUFFER_SIZE+1];
	ZeroMemory(buffer, BUFFER_SIZE+1);

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
			if((rec = recvDataTls(clientSock, pClientContextHandle, streamSizes, buffer, BUFFER_SIZE, tv_sec, tv_usec)) > 0){
				if(rec < 0){
					break;
				}

				sen = send(targetSock, buffer, rec, 0);
				if(sen <= 0){
					break;
				}
			}else{
				break;
			}
		}

		if(FD_ISSET(targetSock, &readfds)){
			if((rec = recv(targetSock, buffer, BUFFER_SIZE, 0)) > 0){
				sen = sendDataTls(clientSock, pClientContextHandle, streamSizes, buffer, rec, tv_sec, tv_usec);
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


int sendSocksResponseIpv4(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
	
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	memset(pSocksResponseIpv4->bndAddr, 0, 4);	// BND.ADDR
	memset(pSocksResponseIpv4->bndPort, 0, 2);	// BND.PORT

	sen = sendData(clientSock, (char *)pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv4Tls(SOCKET clientSock, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)malloc(sizeof(SOCKS_RESPONSE_IPV4));
	
	pSocksResponseIpv4->ver = ver;		// protocol version
	pSocksResponseIpv4->req = req;		// Connection refused
	pSocksResponseIpv4->rsv = rsv;		// RESERVED
	pSocksResponseIpv4->atyp = atyp;	// IPv4
	memset(pSocksResponseIpv4->bndAddr, 0, 4);	// BND.ADDR
	memset(pSocksResponseIpv4->bndPort, 0, 2);	// BND.PORT

	sen = sendDataTls(clientSock, pContextHandle, streamSizes, (char *)pSocksResponseIpv4, sizeof(SOCKS_RESPONSE_IPV4), tv_sec, tv_usec);

	free(pSocksResponseIpv4);

	return sen;
}


int sendSocksResponseIpv6(SOCKET clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	memset(pSocksResponseIpv6->bndAddr, 0, 16);	// BND.ADDR
	memset(pSocksResponseIpv6->bndPort, 0, 2);		// BND.PORT
	
	sen = sendData(clientSock, (char *)pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
	
	free(pSocksResponseIpv6);

	return sen;
}


int sendSocksResponseIpv6Tls(SOCKET clientSock, CtxtHandle *pContextHandle, SecPkgContext_StreamSizes streamSizes, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec)
{
	int sen;
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)malloc(sizeof(SOCKS_RESPONSE_IPV6));
	
	pSocksResponseIpv6->ver = ver;		// protocol version
	pSocksResponseIpv6->req = req;		// Connection refused
	pSocksResponseIpv6->rsv = rsv;		// RESERVED
	pSocksResponseIpv6->atyp = atyp;	// IPv6
	memset(pSocksResponseIpv6->bndAddr, 0, 16);	// BND.ADDR
	memset(pSocksResponseIpv6->bndPort, 0, 2);		// BND.PORT
	
	sen = sendDataTls(clientSock, pContextHandle, streamSizes, (char *)pSocksResponseIpv6, sizeof(SOCKS_RESPONSE_IPV6), tv_sec, tv_usec);
	
	free(pSocksResponseIpv6);

	return sen;
}


/*
 * Reference:
 * https://stackoverflow.com/questions/15616396/need-help-to-find-certificate-by-subject-name-x500-format-cert-x500-name-str
 */
PCCERT_CONTEXT findCertificate(const HCERTSTORE hCertStore, const char* certSearchString)
{
	PCCERT_CONTEXT pCert = NULL;
	DWORD dType = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;
	char certName[CERT_NAME_MAX_SIZE] = {0};

	for(;;){
		pCert = CertEnumCertificatesInStore(hCertStore, pCert);
		if(pCert == NULL){
			break;
		}

		if(CertGetNameStringA(pCert, CERT_NAME_RDN_TYPE, 0, &dType, certName, CERT_NAME_MAX_SIZE) == FALSE){
			CertFreeCertificateContext(pCert);
			pCert = NULL;
			break;
		}

		if((strncmp(certName, certSearchString, CERT_NAME_MAX_SIZE) == 0) && (pCert->dwCertEncodingType == X509_ASN_ENCODING)){
			break;
		}
	}

	return pCert;
}


void freeAllBuffers(SecBufferDesc *pSecBufferDesc)
{
	for(unsigned long i=0; i<pSecBufferDesc->cBuffers; i++){
		if(pSecBufferDesc->pBuffers[i].pvBuffer != NULL){
			FreeContextBuffer(pSecBufferDesc->pBuffers[i].pvBuffer);
		}
	}

	return;
}


void finiSsl(pSSLPARAM pSslParam)
{
	if(pSslParam->hCryptProv != NULL){
		if(NCryptFreeObject(pSslParam->hCryptProv) != SEC_E_OK){
#ifdef _DEBUG
			printf("[E] NCryptFreeObject error:%d\n", GetLastError());
#endif
		}
	}

	if(pSslParam->pServerCert != NULL){
		CertFreeCertificateContext(pSslParam->pServerCert);
	}

	if(pSslParam->hCertStore != NULL){
		if(!CertCloseStore(pSslParam->hCertStore, 0)){
#ifdef _DEBUG
			printf("[E] CertCloseStore error:%d\n", GetLastError());
#endif
		}
	}

	if(pSslParam->pClientContextHandle != NULL){
		DeleteSecurityContext(pSslParam->pClientContextHandle);
	}

	if(pSslParam->pClientCredHandle != NULL){
		FreeCredentialsHandle(pSslParam->pClientCredHandle);
	}

	return;
}


int worker(void *ptr)
{
	pPARAM pParam = (pPARAM)ptr;
	SOCKET clientSock = pParam->clientSock;
	long tv_sec = pParam->tv_sec;		// recv send
	long tv_usec = pParam->tv_usec;		// recv send
	long forwarder_tv_sec = pParam->forwarder_tv_sec;
	long forwarder_tv_usec = pParam->forwarder_tv_usec;

	char buffer[BUFFER_SIZE+1];
	char tmp[BUFFER_SIZE+1];
	ZeroMemory(buffer, BUFFER_SIZE+1);
	ZeroMemory(tmp, BUFFER_SIZE+1);
	
	u_long iMode = 1;	// non-blocking mode
	
	int rec, sen, tmprec;
	int ret = 0;
	int err = 0;
	int count = 0;

	SCHANNEL_CRED clientSchannelCred;
	CredHandle clientCredHandle;
	CtxtHandle clientContextHandle;
	SecPkgContext_StreamSizes streamSizes;
	SECURITY_STATUS status;
	unsigned long fContextReq;
	unsigned long fContextAttr;
	TimeStamp tsExpiry;
	SecBufferDesc inputSecBufferDesc;
	SecBufferDesc outputSecBufferDesc;
	SecBuffer inputSecBuffer[2];
	SecBuffer outputSecBuffer[3];
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pServerCert = NULL;
	HCRYPTPROV hCryptProv;
	DWORD dwKeySpec;
	BOOL bCallerFreeProvOrNCryptKey = false;
	int firstFlag = 1;

	CtxtHandle *pClientContextHandle;
	if(reverseFlag == 1){	// Reverse mode
		pClientContextHandle = pParam->pClientContextHandle;
		streamSizes = pParam->streamSizes;
	}

	SSLPARAM sslParam;
	sslParam.hCertStore = NULL;
	sslParam.pServerCert = NULL;
	sslParam.hCryptProv = NULL;
	sslParam.pClientCredHandle = NULL;
	sslParam.pClientContextHandle = NULL;
	
	free(ptr);
	
	
	if(reverseFlag == 0 && tlsFlag == 1){	// Normal mode and tls
		// read certificate
		hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
//		hCertStore = CertOpenSystemStoreA(NULL, "MY");
		if(hCertStore == NULL){
#ifdef _DEBUG
			printf("[E] CertOpenStore error\n");
#endif
			closesocket(clientSock);
			return -2;
		}

		sslParam.hCertStore = hCertStore;

//		pServerCert = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, L"CN=socks5", NULL);
		pServerCert = findCertificate(hCertStore, "CN=socks5");
		if(pServerCert == NULL){
#ifdef _DEBUG
			printf("[E] findCertificate error\n");
#endif
			finiSsl(&sslParam);
			closesocket(clientSock);
			return -2;
		}

		sslParam.pServerCert = pServerCert;

		if(!CryptAcquireCertificatePrivateKey(pServerCert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hCryptProv, &dwKeySpec, &bCallerFreeProvOrNCryptKey)){
#ifdef _DEBUG
			printf("[E] CryptAcquireCertificatePrivateKey error\n");
#endif
			finiSsl(&sslParam);
			closesocket(clientSock);
			return -2;
		}

		sslParam.hCryptProv = hCryptProv;

		// initialize schannel credentials
		ZeroMemory(&clientSchannelCred, sizeof(clientSchannelCred));
		clientSchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
		clientSchannelCred.cCreds = 1;
		clientSchannelCred.paCred = &pServerCert;
		clientSchannelCred.hRootStore = hCertStore;
		clientSchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
		clientSchannelCred.dwFlags = SCH_USE_STRONG_CRYPTO;

		status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &clientSchannelCred, NULL, NULL, &clientCredHandle, NULL);
		if(status != SEC_E_OK){
#ifdef _DEBUG
			printf("[E] AcquireCredentialsHandleA error:%x\n", status);
#endif
			finiSsl(&sslParam);
			closesocket(clientSock);
			return -2;
		}

		sslParam.pClientCredHandle = &clientCredHandle;

		// establish security context
#ifdef _DEBUG
		printf("[I] Try Socks5 over TLS connection.\n");
#endif
		ZeroMemory(&clientContextHandle, sizeof(clientContextHandle));

		fContextReq = ASC_REQ_ALLOCATE_MEMORY;

		// output buffer
		outputSecBuffer[0].BufferType = SECBUFFER_TOKEN;
		outputSecBuffer[0].pvBuffer = NULL;
		outputSecBuffer[0].cbBuffer = 0;
		outputSecBuffer[1].BufferType = SECBUFFER_ALERT;
		outputSecBuffer[1].pvBuffer = NULL;
		outputSecBuffer[1].cbBuffer = 0;
		outputSecBuffer[2].BufferType = SECBUFFER_EMPTY;
		outputSecBuffer[2].pvBuffer = NULL;
		outputSecBuffer[2].cbBuffer = 0;
		outputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
		outputSecBufferDesc.cBuffers = 3;
		outputSecBufferDesc.pBuffers = outputSecBuffer;

		rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		if(rec <= 0){
			freeAllBuffers(&outputSecBufferDesc);
			DeleteSecurityContext(&clientContextHandle);
			finiSsl(&sslParam);
			closesocket(clientSock);
			return -2;
		}

		while(1){
			// input buffer
			inputSecBuffer[0].BufferType = SECBUFFER_TOKEN;
			inputSecBuffer[0].pvBuffer = &buffer;
			inputSecBuffer[0].cbBuffer = rec;
			inputSecBuffer[1].BufferType = SECBUFFER_EMPTY;
			inputSecBuffer[1].pvBuffer = NULL;
			inputSecBuffer[1].cbBuffer = 0;
			inputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
			inputSecBufferDesc.cBuffers = 2;
			inputSecBufferDesc.pBuffers = inputSecBuffer;

			if(firstFlag == 1){
				status = AcceptSecurityContext(&clientCredHandle, NULL, &inputSecBufferDesc, fContextReq, SECURITY_NATIVE_DREP, &clientContextHandle, &outputSecBufferDesc, &fContextAttr, &tsExpiry);
				firstFlag = 0;
			}else{
				status = AcceptSecurityContext(&clientCredHandle, &clientContextHandle, &inputSecBufferDesc, fContextReq, SECURITY_NATIVE_DREP, &clientContextHandle, &outputSecBufferDesc, &fContextAttr, &tsExpiry);
			}

			if(status == SEC_E_OK){
				if(outputSecBuffer[0].cbBuffer > 0){
					sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
					if(sen <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						return -2;
					}
				}

				freeAllBuffers(&outputSecBufferDesc);
				break;
			}else if(status == SEC_I_CONTINUE_NEEDED){
				if(outputSecBuffer[0].cbBuffer > 0){
					sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
					if(sen <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						return -2;
					}
				}

				freeAllBuffers(&outputSecBufferDesc);

				rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}
			}else if(status == SEC_I_COMPLETE_NEEDED){
				status = CompleteAuthToken(&clientContextHandle, &outputSecBufferDesc);
				if(status != SEC_E_OK){
#ifdef _DEBUG
					printf("[E] CompleteAuthToken error:%x\n", status);
#endif
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}

				if(outputSecBuffer[0].cbBuffer > 0){
					sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
					if(sen <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						return -2;
					}
				}

				freeAllBuffers(&outputSecBufferDesc);
				break;
			}else if(status == SEC_I_COMPLETE_AND_CONTINUE){
				status = CompleteAuthToken(&clientContextHandle, &outputSecBufferDesc);
				if(status != SEC_E_OK){
#ifdef _DEBUG
					printf("[E] CompleteAuthToken error:%x\n", status);
#endif
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}

				if(outputSecBuffer[0].cbBuffer > 0){
					sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
					if(sen <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						return -2;
					}
				}

				freeAllBuffers(&outputSecBufferDesc);

				rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
				if(rec <= 0){
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}
			}else if(status == SEC_E_INCOMPLETE_MESSAGE){
				tmprec = recvData(clientSock, tmp, BUFFER_SIZE, tv_sec, tv_usec);
				if(tmprec <= 0){
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}

				if(rec + tmprec <= BUFFER_SIZE){
					memcpy(buffer+rec, tmp, tmprec);
					rec += tmprec;
				}else{
#ifdef _DEBUG
					printf("[E] received data size has exceeded the maximum value:%d\n", rec + tmprec);
#endif
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					return -2;
				}
			}else{
#ifdef _DEBUG
				printf("[E] AcceptSecurityContext error:%x\n", status);
#endif
				freeAllBuffers(&outputSecBufferDesc);
				DeleteSecurityContext(&clientContextHandle);
				finiSsl(&sslParam);
				closesocket(clientSock);
				return -2;
			}
		}

		sslParam.pClientContextHandle = &clientContextHandle;
		pClientContextHandle = &clientContextHandle;

		// get stream sizes
		status = QueryContextAttributes(&clientContextHandle, SECPKG_ATTR_STREAM_SIZES, &streamSizes);
		if(status != SEC_E_OK){
#ifdef _DEBUG
			printf("[E] QueryContextAttributes error:%x\n", status);
#endif
			finiSsl(&sslParam);
			closesocket(clientSock);
			return -2;
		}

#ifdef _DEBUG
		printf("[I] Succeed Socks5 over TLS connection.\n");
#endif
	}


	// socks SELECTION_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving selection request.\n");
#endif
	do{
		if(tlsFlag == 0){
			if(reverseFlag == 0){
				rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
			}else{
				rec = recvData(clientSock, buffer, BUFFER_SIZE, 3600, 0);
			}
		}else{
			if(reverseFlag == 0){
				rec = recvDataTls(clientSock, pClientContextHandle, streamSizes, buffer, BUFFER_SIZE, tv_sec, tv_usec);
			}else{
				rec = recvDataTls(clientSock, pClientContextHandle, streamSizes, buffer, BUFFER_SIZE, 3600, 0);
			}
		}
		
		if(rec == -1 || rec == -2){
			break;
		}
	}while((rec > 0 && rec < 3) || rec > 257);

	if(rec < 0){
#ifdef _DEBUG
		printf("[E] Cannot receive selection request.\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
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
		sen = sendDataTls(clientSock, pClientContextHandle, streamSizes, pSelectionResponse, sizeof(SELECTION_RESPONSE), tv_sec, tv_usec);
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
			closesocket(clientSock);
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
			rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}else{
			rec = recvDataTls(clientSock, pClientContextHandle, streamSizes, buffer, BUFFER_SIZE, tv_sec, tv_usec);
		}
		if(rec <= 0){
#ifdef _DEBUG
			printf("[E] Receiving username password authentication request error.\n");
#endif
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
				sen = sendDataTls(clientSock, pClientContextHandle, streamSizes, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
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
				sen = sendDataTls(clientSock, pClientContextHandle, streamSizes, pUsernamePasswordAuthenticationResponse, sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE), tv_sec, tv_usec);
			}
#ifdef _DEBUG
			printf("[I] Send selection response:%d bytes.\n", sen);
#endif
			
			free(pUsernamePasswordAuthenticationResponse);
			if(reverseFlag == 0){	// Nomal mode
				finiSsl(&sslParam);
				if(tlsFlag == 1){	// tls
					closesocket(clientSock);
				}
			}
			return -1;
		}
	}	
	
	
	// socks SOCKS_REQUEST
#ifdef _DEBUG
	printf("[I] Receiving socks request.\n");
#endif
	ZeroMemory(buffer, BUFFER_SIZE+1);
	if(tlsFlag == 0){
		rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}else{
		rec = recvDataTls(clientSock, pClientContextHandle, streamSizes, buffer, BUFFER_SIZE, tv_sec, tv_usec);
	}
	if(rec <= 0){
#ifdef _DEBUG
		printf("[E] Receiving socks request error.\n");
#endif
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x8, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
		}else{	// IPv6
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
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
						sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
					
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						closesocket(clientSock);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
		}
		return -1;
	}
	
	
	// socks SOCKS_RESPONSE	
	int targetSock;
	char targetAddr6String[INET6_ADDRSTRLEN+1] = {0};
	char *pTargetAddr6String = targetAddr6String;
	
	if(atyp == 0x1){	// IPv4
#ifdef _DEBUG
		printf("[I] Connecting. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif

		if(cmd == 0x1){	// CONNECT
#ifdef _DEBUG
			printf("[I] SOCKS_RESPONSE cmd:CONNECT.\n");
#endif
			targetSock = socket(AF_INET, SOCK_STREAM, 0);
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif
				
				closesocket(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
				}
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
			}
			return -1;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
				
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(tlsFlag == 0){
						sen = sendSocksResponseIpv4(clientSock, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x1, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					closesocket(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						closesocket(clientSock);
					}
					return -1;
				}
#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", inet_ntoa(targetAddr.sin_addr), ntohs(targetAddr.sin_port));
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x0, 0x0, 0x1, tv_sec, tv_usec);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
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
					sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
				}
				return -1;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv4(clientSock, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
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
			
				if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
					printf("[E] Cannot connect. errno:%d\n", err);
#endif
					
					if(tlsFlag == 0){
						sen = sendSocksResponseIpv6(clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}else{
						sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
					}
#ifdef _DEBUG
					printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

					closesocket(targetSock);
					if(reverseFlag == 0){	// Nomal mode
						if(tlsFlag == 1){	// tls
							finiSsl(&sslParam);
						}
						closesocket(clientSock);
					}
					return -1;
				}

#ifdef _DEBUG
				printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
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
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
				}
				return -1;
			}else{
#ifdef _DEBUG
				printf("[E] Not implemented.\n");
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
				}
				
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
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
				sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
			
			if((err = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
#ifdef _DEBUG
				printf("[E] Cannot connect. errno:%d\n", err);
#endif
				
				if(tlsFlag == 0){
					sen = sendSocksResponseIpv6(clientSock, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}else{
					sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x5, 0x0, 0x4, tv_sec, tv_usec);
				}
#ifdef _DEBUG
				printf("[I] Socks Request:%d bytes, Socks Response:%d bytes.\n", rec, sen);
#endif

				closesocket(targetSock);
				if(reverseFlag == 0){	// Nomal mode
					if(tlsFlag == 1){	// tls
						finiSsl(&sslParam);
					}
					closesocket(clientSock);
				}
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected. ip:%s port:%d\n", pTargetAddr6String, ntohs(targetAddr6.sin6_port));
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x0, 0x0, 0x4, tv_sec, tv_usec);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
				sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x7, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
			}
			return -1;
		}else{
#ifdef _DEBUG
			printf("[E] Not implemented.\n");
#endif
			
			if(tlsFlag == 0){
				sen = sendSocksResponseIpv6(clientSock, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}else{
				sen = sendSocksResponseIpv6Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x4, tv_sec, tv_usec);
			}
			
			if(reverseFlag == 0){	// Nomal mode
				if(tlsFlag == 1){	// tls
					finiSsl(&sslParam);
				}
				closesocket(clientSock);
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
			sen = sendSocksResponseIpv4Tls(clientSock, pClientContextHandle, streamSizes, 0x5, 0x1, 0x0, 0x1, tv_sec, tv_usec);
		}
		
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
		}
		return -1;
	}


	err = ioctlsocket(clientSock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		closesocket(targetSock);
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
		}
		return -1;
	}

	err = ioctlsocket(targetSock, FIONBIO, &iMode);
	if(err != NO_ERROR){
#ifdef _DEBUG
		printf("[E] ioctlsocket error:%d\n.", err);
#endif
		closesocket(targetSock);
		if(reverseFlag == 0){	// Nomal mode
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
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
		err = forwarderTls(clientSock, targetSock, pClientContextHandle, streamSizes, forwarder_tv_sec, forwarder_tv_usec);
		if(reverseFlag == 1 && err == -2){
			closesocket(targetSock);
			return -2;
		}
	}
	
		
	if(reverseFlag == 1){	// Reverse mode
		iMode = 0;	// blocking mode
		err = ioctlsocket(clientSock, FIONBIO, &iMode);
		if(err != NO_ERROR){
#ifdef _DEBUG
			printf("[E] ioctlsocket error:%d\n.", err);
#endif
			closesocket(targetSock);
			if(tlsFlag == 1){	// tls
				finiSsl(&sslParam);
			}
			closesocket(clientSock);
			
			return -2;
		}
	}
	
		
#ifdef _DEBUG
	printf("[I] Worker exit.\n");
#endif
	closesocket(targetSock);
	if(reverseFlag == 0){	// Nomal mode
		if(tlsFlag == 1){	// tls
			finiSsl(&sslParam);
		}
		closesocket(clientSock);
	}

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
	printf("usage        : %s -h listen_ip -p listen_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -h 192.168.0.10 -p 9050\n", filename);
	printf("             : %s -h localhost -p 9050 -s\n", filename);
	printf("             : %s -h ::1 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h 192.168.0.10 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -h fe80::xxxx:xxxx:xxxx:xxxx%%14 -p 9050 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("or\n");
	printf("Reverse mode : client <- server\n");
	printf("usage        : %s -r -H socks5client_ip -P socks5client_port [-s (socks5 over tls)] [-A recv/send tv_sec(timeout 0-10 sec)] [-B recv/send tv_usec(timeout 0-1000000 microsec)] [-C forwarder tv_sec(timeout 0-3600 sec)] [-D forwarder tv_usec(timeout 0-1000000 microsec)]\n", filename);
	printf("example      : %s -r -H 192.168.0.5 -P 1234\n", filename);
	printf("             : %s -r -H localhost -P 1234 -s\n", filename);
	printf("             : %s -r -H ::1 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -H 192.168.0.5 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
	printf("             : %s -r -H fe80::xxxx:xxxx:xxxx:xxxx%%14 -P 1234 -s -A 3 -B 0 -C 3 -D 0\n", filename);
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
int main(int argc, char **argv)
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

	WSADATA wsaData;
	SOCKET serverSock = INVALID_SOCKET;
	SOCKET clientSock = INVALID_SOCKET;
	sockaddr_in serverAddr, clientAddr;
	sockaddr_in *tmpIpv4;
	sockaddr_in6 serverAddr6, clientAddr6;
	sockaddr_in6 *tmpIpv6;
	addrinfo hints;
	addrinfo *serverHost;
	addrinfo *clientHost;

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
	int clientAddrLen = sizeof(clientAddr);
	int clientAddr6Len = sizeof(clientAddr6);
	u_long iMode = 1;	// non-blocking mode
	int ret = 0;
	int err = 0;

	SCHANNEL_CRED clientSchannelCred;
	CredHandle clientCredHandle;
	CtxtHandle clientContextHandle;
	SecPkgContext_StreamSizes streamSizes;
	SECURITY_STATUS status;
	unsigned long fContextReq;
	unsigned long fContextAttr;
	TimeStamp tsExpiry;
	SecBufferDesc inputSecBufferDesc;
	SecBufferDesc outputSecBufferDesc;
	SecBuffer inputSecBuffer[2];
	SecBuffer outputSecBuffer[3];
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pServerCert = NULL;
	HCRYPTPROV hCryptProv;
	DWORD dwKeySpec;
	BOOL bCallerFreeProvOrNCryptKey = false;
	int firstFlag = 1;

	pPARAM pParam;

	SSLPARAM sslParam;
	sslParam.hCertStore = NULL;
	sslParam.pServerCert = NULL;
	sslParam.hCryptProv = NULL;
	sslParam.pClientCredHandle = NULL;
	sslParam.pClientContextHandle = NULL;

	int rec, sen, tmprec;
	char buffer[BUFFER_SIZE+1];
	char tmp[BUFFER_SIZE+1];
	ZeroMemory(buffer, BUFFER_SIZE+1);
	ZeroMemory(tmp, BUFFER_SIZE+1);


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
			printf("[I] Listenning port %d on %s.\n", ntohs(serverAddr.sin_port), inet_ntoa(serverAddr.sin_addr));
#endif

			// accept
			while((clientSock = accept(serverSock, (sockaddr *)&clientAddr, (socklen_t *)&clientAddrLen))){
#ifdef _DEBUG
				printf("[I] Connected from ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif
				pParam = (pPARAM)calloc(1, sizeof(PARAM));
				pParam->clientSock = clientSock;
				pParam->pClientContextHandle = NULL;
				pParam->streamSizes = {0};
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
			while((clientSock = accept(serverSock, (sockaddr *)&clientAddr6, (socklen_t *)&clientAddr6Len))){
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
				pParam->pClientContextHandle = NULL;
				pParam->streamSizes = {0};
				pParam->tv_sec = tv_sec;
				pParam->tv_usec = tv_usec;
				pParam->forwarder_tv_sec = forwarder_tv_sec;
				pParam->forwarder_tv_usec = forwarder_tv_usec;

				_beginthread(workerThread, 0, pParam);
			}
		}

		closesocket(serverSock);

	}else{	// reverse mode
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
					WSACleanup();
					return -1;
				}
			}
		}else{	// ipv6 address
			hints.ai_family = AF_INET6;	// IPv6
			if(getaddrinfo(clientDomainname, clientPortNumber, &hints, &clientHost) != 0){
#ifdef _DEBUG
				printf("[E] Cannot resolv the domain name:%s\n", clientDomainname);
#endif
				WSACleanup();
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
			WSACleanup();
			return -1;
		}

		if(family == AF_INET){	// IPv4
			clientSock = socket(AF_INET, SOCK_STREAM, 0);
			if(clientSock == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connecting to ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif

			if((err = connect(clientSock, (sockaddr *)&clientAddr, sizeof(clientAddr))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				closesocket(clientSock);
				WSACleanup();
				return -1;
			}

#ifdef _DEBUG
			printf("[I] Connected to ip:%s port:%d.\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
#endif
		}else if(family == AF_INET6){	// IPv6
			clientSock = socket(AF_INET6, SOCK_STREAM, 0);
			if(clientSock == INVALID_SOCKET){
#ifdef _DEBUG
				printf("[E] Socket error:%d.\n", WSAGetLastError());
#endif
				WSACleanup();
				return -1;
			}

#ifdef _DEBUG
			inet_ntop(AF_INET6, &clientAddr6.sin6_addr, clientAddr6StringPointer, INET6_ADDRSTRLEN);
			if(clientAddr6.sin6_scope_id > 0){
				printf("[I] Connecting to ip:%s%%%d port:%d\n", clientAddr6StringPointer, clientAddr6.sin6_scope_id, ntohs(clientAddr6.sin6_port));
			}else{
				printf("[I] Connecting to ip:%s port:%d\n", clientAddr6StringPointer, ntohs(clientAddr6.sin6_port));
			}
#endif

			if((err = connect(clientSock, (sockaddr *)&clientAddr6, sizeof(clientAddr6))) < 0){
#ifdef _DEBUG
				printf("[E] Connect failed. errno:%d\n", err);
#endif
				closesocket(clientSock);
				WSACleanup();
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
			WSACleanup();
			return -1;
		}

		if(tlsFlag == 1){	// tls
			// read certificate
			hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"MY");
//			hCertStore = CertOpenSystemStoreA(NULL, "MY");
			if(hCertStore == NULL){
#ifdef _DEBUG
				printf("[E] CertOpenStore error\n");
#endif
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

			sslParam.hCertStore = hCertStore;

//			pServerCert = CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_NAME, L"CN=socks5", NULL);
			pServerCert = findCertificate(hCertStore, "CN=socks5");
			if(pServerCert == NULL){
#ifdef _DEBUG
				printf("[E] findCertificate error\n");
#endif
				finiSsl(&sslParam);
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

			sslParam.pServerCert = pServerCert;

			if(!CryptAcquireCertificatePrivateKey(pServerCert, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG, NULL, &hCryptProv, &dwKeySpec, &bCallerFreeProvOrNCryptKey)){
#ifdef _DEBUG
				printf("[E] CryptAcquireCertificatePrivateKey error\n");
#endif
				finiSsl(&sslParam);
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

			sslParam.hCryptProv = hCryptProv;

			// initialize schannel credentials
			ZeroMemory(&clientSchannelCred, sizeof(clientSchannelCred));
			clientSchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
			clientSchannelCred.cCreds = 1;
			clientSchannelCred.paCred = &pServerCert;
			clientSchannelCred.hRootStore = hCertStore;
			clientSchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
			clientSchannelCred.dwFlags = SCH_USE_STRONG_CRYPTO;

			status = AcquireCredentialsHandleA(NULL, UNISP_NAME_A, SECPKG_CRED_INBOUND, NULL, &clientSchannelCred, NULL, NULL, &clientCredHandle, NULL);
			if(status != SEC_E_OK){
#ifdef _DEBUG
				printf("[E] AcquireCredentialsHandleA error:%x\n", status);
#endif
				finiSsl(&sslParam);
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

			sslParam.pClientCredHandle = &clientCredHandle;

			// establish security context
#ifdef _DEBUG
			printf("[I] Try Socks5 over TLS connection.\n");
#endif
			ZeroMemory(&clientContextHandle, sizeof(clientContextHandle));

			fContextReq = ASC_REQ_ALLOCATE_MEMORY;

			// output buffer
			outputSecBuffer[0].BufferType = SECBUFFER_TOKEN;
			outputSecBuffer[0].pvBuffer = NULL;
			outputSecBuffer[0].cbBuffer = 0;
			outputSecBuffer[1].BufferType = SECBUFFER_ALERT;
			outputSecBuffer[1].pvBuffer = NULL;
			outputSecBuffer[1].cbBuffer = 0;
			outputSecBuffer[2].BufferType = SECBUFFER_EMPTY;
			outputSecBuffer[2].pvBuffer = NULL;
			outputSecBuffer[2].cbBuffer = 0;
			outputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
			outputSecBufferDesc.cBuffers = 3;
			outputSecBufferDesc.pBuffers = outputSecBuffer;

			rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
			if(rec <= 0){
				freeAllBuffers(&outputSecBufferDesc);
				DeleteSecurityContext(&clientContextHandle);
				finiSsl(&sslParam);
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

			while(1){
				// input buffer
				inputSecBuffer[0].BufferType = SECBUFFER_TOKEN;
				inputSecBuffer[0].pvBuffer = &buffer;
				inputSecBuffer[0].cbBuffer = rec;
				inputSecBuffer[1].BufferType = SECBUFFER_EMPTY;
				inputSecBuffer[1].pvBuffer = NULL;
				inputSecBuffer[1].cbBuffer = 0;
				inputSecBufferDesc.ulVersion = SECBUFFER_VERSION;
				inputSecBufferDesc.cBuffers = 2;
				inputSecBufferDesc.pBuffers = inputSecBuffer;

				if(firstFlag == 1){
					status = AcceptSecurityContext(&clientCredHandle, NULL, &inputSecBufferDesc, fContextReq, SECURITY_NATIVE_DREP, &clientContextHandle, &outputSecBufferDesc, &fContextAttr, &tsExpiry);
					firstFlag = 0;
				}else{
					status = AcceptSecurityContext(&clientCredHandle, &clientContextHandle, &inputSecBufferDesc, fContextReq, SECURITY_NATIVE_DREP, &clientContextHandle, &outputSecBufferDesc, &fContextAttr, &tsExpiry);
				}

				if(status == SEC_E_OK){
					if(outputSecBuffer[0].cbBuffer > 0){
						sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
						if(sen <= 0){
							freeAllBuffers(&outputSecBufferDesc);
							DeleteSecurityContext(&clientContextHandle);
							finiSsl(&sslParam);
							closesocket(clientSock);
							WSACleanup();
							return -2;
						}
					}

					freeAllBuffers(&outputSecBufferDesc);
					break;
				}else if(status == SEC_I_CONTINUE_NEEDED){
					if(outputSecBuffer[0].cbBuffer > 0){
						sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
						if(sen <= 0){
							freeAllBuffers(&outputSecBufferDesc);
							DeleteSecurityContext(&clientContextHandle);
							finiSsl(&sslParam);
							closesocket(clientSock);
							WSACleanup();
							return -2;
						}
					}

					freeAllBuffers(&outputSecBufferDesc);

					rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
					if(rec <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}
				}else if(status == SEC_I_COMPLETE_NEEDED){
					status = CompleteAuthToken(&clientContextHandle, &outputSecBufferDesc);
					if(status != SEC_E_OK){
#ifdef _DEBUG
						printf("[E] CompleteAuthToken error:%x\n", status);
#endif
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}

					if(outputSecBuffer[0].cbBuffer > 0){
						sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
						if(sen <= 0){
							freeAllBuffers(&outputSecBufferDesc);
							DeleteSecurityContext(&clientContextHandle);
							finiSsl(&sslParam);
							closesocket(clientSock);
							WSACleanup();
							return -2;
						}
					}

					freeAllBuffers(&outputSecBufferDesc);
					break;
				}else if(status == SEC_I_COMPLETE_AND_CONTINUE){
					status = CompleteAuthToken(&clientContextHandle, &outputSecBufferDesc);
					if(status != SEC_E_OK){
#ifdef _DEBUG
						printf("[E] CompleteAuthToken error:%x\n", status);
#endif
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}

					if(outputSecBuffer[0].cbBuffer > 0){
						sen = sendData(clientSock, (char *)outputSecBuffer[0].pvBuffer, outputSecBuffer[0].cbBuffer, tv_sec, tv_usec);
						if(sen <= 0){
							freeAllBuffers(&outputSecBufferDesc);
							DeleteSecurityContext(&clientContextHandle);
							finiSsl(&sslParam);
							closesocket(clientSock);
							WSACleanup();
							return -2;
						}
					}

					freeAllBuffers(&outputSecBufferDesc);

					rec = recvData(clientSock, buffer, BUFFER_SIZE, tv_sec, tv_usec);
					if(rec <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}
				}else if(status == SEC_E_INCOMPLETE_MESSAGE){
					tmprec = recvData(clientSock, tmp, BUFFER_SIZE, tv_sec, tv_usec);
					if(tmprec <= 0){
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}

					if(rec + tmprec <= BUFFER_SIZE){
						memcpy(buffer+rec, tmp, tmprec);
						rec += tmprec;
					}else{
#ifdef _DEBUG
						printf("[E] received data size has exceeded the maximum value:%d\n", rec + tmprec);
#endif
						freeAllBuffers(&outputSecBufferDesc);
						DeleteSecurityContext(&clientContextHandle);
						finiSsl(&sslParam);
						closesocket(clientSock);
						WSACleanup();
						return -2;
					}
				}else{
#ifdef _DEBUG
					printf("[E] AcceptSecurityContext error:%x\n", status);
#endif
					freeAllBuffers(&outputSecBufferDesc);
					DeleteSecurityContext(&clientContextHandle);
					finiSsl(&sslParam);
					closesocket(clientSock);
					WSACleanup();
					return -2;
				}
			}

			sslParam.pClientContextHandle = &clientContextHandle;

			// get stream sizes
			status = QueryContextAttributes(&clientContextHandle, SECPKG_ATTR_STREAM_SIZES, &streamSizes);
			if(status != SEC_E_OK){
#ifdef _DEBUG
				printf("[E] QueryContextAttributes error:%x\n", status);
#endif
				finiSsl(&sslParam);
				closesocket(clientSock);
				WSACleanup();
				return -2;
			}

#ifdef _DEBUG
			printf("[I] Succeed Socks5 over TLS connection.\n");
#endif
		}

		while(1){
			pParam = (pPARAM)calloc(1, sizeof(PARAM));
			pParam->clientSock = clientSock;
			pParam->pClientContextHandle = &clientContextHandle;
			pParam->streamSizes = streamSizes;
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
			finiSsl(&sslParam);
		}
		closesocket(clientSock);

	}
	
	WSACleanup();
	
	return 0;
}


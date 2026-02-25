/*
 * Title:  socks5server.cpp (Windows RPC)
 * Author: Shuichiro Endo
 */

//#define __DEBUG

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <map>
#include <mutex>

#include "socks5server.h"
#include "socks5.h"

#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"rpcrt4.lib")
#pragma comment(lib,"ws2_32.lib")

#define SOCKS5_START                                0
#define SELECTION_REQUEST                           1
#define SELECTION_RESPONSE                          2
#define USERNAME_PASSWORD_AUTHENTICATION_REQUEST    3
#define USERNAME_PASSWORD_AUTHENTICATION_RESPONSE   4
#define SOCKS5_REQUEST                              5
#define SOCKS5_RESPONSE                             6
#define SOCKS5_FORWARDER                            7
#define SOCKS5_FINISH                               8
#define SOCKS5_ERROR                                9

#define BUFFER_SIZE 8192


typedef struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
} timezone;

typedef struct SESSION_DATA
{
    unsigned int id;
    int state;
    SOCKET socket;
} SESSION_DATA, *pSESSION_DATA;


int optstringIndex = 0;
char *optarg = NULL;

static char authenticationMethod = 0x0;	// 0x0:No Authentication Required  0x2:Username/Password Authentication
static char username[256] = "socks5user";
static char password[256] = "supersecretpassword";

std::map<unsigned int, pSESSION_DATA> sessionDataMap;
std::mutex sessionDataMapMutex;


void* __RPC_USER midl_user_allocate(size_t cBytes)
{
    return malloc(cBytes);
}


void __RPC_USER midl_user_free(void *p)
{
    free(p);
}


void PrintBytes(unsigned char *input, int input_length)
{
    for(int i=0; i<input_length; i++)
    {
        if(i != 0 && i%16 == 0)
        {
            printf("\n");
        }else if(i%16 == 8)
        {
            printf(" ");
        }
        printf("%02x ", input[i]);
    }
    printf("\n");

    return;
}


int GetTimeOfDay(timeval *pTv, timezone *pTz)
{
    if(pTv)
    {
        FILETIME filetime;
        ULARGE_INTEGER x;
        ULONGLONG usec;
        static const ULONGLONG epoch_offset_us = 11644473600000000ULL;

#if _WIN32_WINNT >= WIN32_WINNT_WIN8
        GetSystemTimePreciseAsFileTime(&filetime);
#else
        GetSystemTimeAsFileTime(&filetime);
#endif

        x.LowPart = filetime.dwLowDateTime;
        x.HighPart = filetime.dwHighDateTime;
        usec = x.QuadPart / 10 - epoch_offset_us;
        pTv->tv_sec = (long)(usec / 1000000ULL);
        pTv->tv_usec = (long)(usec % 1000000ULL);
    }else
    {
        return -1;
    }

    if(pTz)
    {
        TIME_ZONE_INFORMATION timezone;
        GetTimeZoneInformation(&timezone);
        pTz->tz_minuteswest = timezone.Bias;
        pTz->tz_dsttime = 0;
    }

    return 0;
}


int SetSocksResponseIpv4(char *buffer, char ver, char req, char rsv, char atyp)
{
    pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)buffer;

    pSocksResponseIpv4->ver = ver;		// protocol version
    pSocksResponseIpv4->req = req;		// Connection refused
    pSocksResponseIpv4->rsv = rsv;		// RESERVED
    pSocksResponseIpv4->atyp = atyp;	// IPv4
    memset(pSocksResponseIpv4->bndAddr, 0, 4);	// BND.ADDR
    memset(pSocksResponseIpv4->bndPort, 0, 2);	// BND.PORT

    return 10;  // sizeof(SOCKS_RESPONSE_IPV4)
}


int SetSocksResponseIpv6(char *buffer, char ver, char req, char rsv, char atyp)
{
    pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)buffer;

    pSocksResponseIpv6->ver = ver;		// protocol version
    pSocksResponseIpv6->req = req;		// Connection refused
    pSocksResponseIpv6->rsv = rsv;		// RESERVED
    pSocksResponseIpv6->atyp = atyp;	// IPv6
    memset(pSocksResponseIpv6->bndAddr, 0, 16);	   // BND.ADDR
    memset(pSocksResponseIpv6->bndPort, 0, 2);     // BND.PORT

    return 22;  // sizeof(SOCKS_RESPONSE_IPV6)
}


int SelectionRequestResponse(handle_t IDL_handle, unsigned int id, int inputBufferLength, const unsigned char *inputBuffer, int *outputBufferLength, unsigned char **outputBuffer)
{
    unsigned char method = 0xFF;
    pSELECTION_REQUEST pSelectionRequest = NULL;
    pSELECTION_RESPONSE pSelectionResponse = NULL;
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    *outputBufferLength = 0;
    *outputBuffer = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount > 0)
    {
        lock.unlock();

#ifdef __DEBUG
        printf("[E] SelectionRequestResponse error id: %u\n", id);
#endif
        goto error;
    }else
    {
        sessionData = (pSESSION_DATA)calloc(1, sizeof(SESSION_DATA));
        sessionData->id = id;
        sessionData->state = SELECTION_REQUEST;
        sessionData->socket = INVALID_SOCKET;

        sessionDataMap.insert({id, sessionData});
    }

    lock.unlock();


    // socks SELECTION_REQUEST
    pSelectionRequest = (pSELECTION_REQUEST)inputBuffer;
    for(int i = 0; i < pSelectionRequest->nmethods; i++)
    {
        if(pSelectionRequest->methods[i] == authenticationMethod)	// NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
        {
            method = pSelectionRequest->methods[i];
            break;
        }
    }


    // socks SELECTION_RESPONSE
    lock.lock();
    sessionData->state = SELECTION_RESPONSE;
    lock.unlock();

    *outputBufferLength = 2;   // sizeof(SELECTION_RESPONSE)
    *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);

    pSelectionResponse = (pSELECTION_RESPONSE)*outputBuffer;
    pSelectionResponse->ver = 0x5;		    // socks version 5
    pSelectionResponse->method = method;	// no authentication required or username/password
    if(pSelectionRequest->ver != 0x5 || authenticationMethod != method)
    {
        pSelectionResponse->method = 0xFF;

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();
    }

    return 0;

error:

    return -1;
}


int UsernamePasswordAuthenticationRequestResponse(handle_t IDL_handle, unsigned int id, int inputBufferLength, const unsigned char *inputBuffer, int *outputBufferLength, unsigned char **outputBuffer)
{
    unsigned char ulen = 0;
    unsigned char plen = 0;
    char uname[256] = {0};
    char passwd[256] = {0};
    pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP pUsernamePasswordAuthenticationRequest = NULL;
    pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE pUsernamePasswordAuthenticationResponse = NULL;
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    *outputBufferLength = 0;
    *outputBuffer = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount != 1)
    {
        lock.unlock();

#ifdef __DEBUG
        printf("[E] UsernamePasswordAuthenticationRequestResponse error id: %u\n", id);
#endif
        goto error;
    }else
    {
        sessionData = sessionDataMap[id];

        if(sessionData->id != id || sessionData->state != SELECTION_RESPONSE || authenticationMethod != 0x2)
        {
            sessionData->state = SOCKS5_ERROR;

            lock.unlock();

#ifdef __DEBUG
            printf("[E] UsernamePasswordAuthenticationRequestResponse error id: %u\n", id);
#endif
            goto error;
        }

        sessionData->state = USERNAME_PASSWORD_AUTHENTICATION_REQUEST;
    }

    lock.unlock();


    // socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST
    pUsernamePasswordAuthenticationRequest = (pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP)inputBuffer;
    ulen = pUsernamePasswordAuthenticationRequest->ulen;
    memcpy(uname, &pUsernamePasswordAuthenticationRequest->uname, ulen);
    memcpy(&plen, &pUsernamePasswordAuthenticationRequest->uname + ulen, 1);
    memcpy(passwd, &pUsernamePasswordAuthenticationRequest->uname + ulen + 1, plen);


    // socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE
    lock.lock();
    sessionData->state = USERNAME_PASSWORD_AUTHENTICATION_RESPONSE;
    lock.unlock();

    *outputBufferLength = 2;   // sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE)
    *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);

    pUsernamePasswordAuthenticationResponse = (pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE)*outputBuffer;
    pUsernamePasswordAuthenticationResponse->ver = 0x1;
    if(pUsernamePasswordAuthenticationRequest->ver == 0x1 && !strncmp(uname, username, sizeof(username)) && !strncmp(passwd, password, sizeof(password)))
    {
        pUsernamePasswordAuthenticationResponse->status = 0x0;
    }else
    {
        pUsernamePasswordAuthenticationResponse->status = 0xFF;

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

#ifdef __DEBUG
        printf("[E] UsernamePasswordAuthenticationRequestResponse username or password error\n");
#endif
    }

    return 0;

error:

    return -1;
}


int Socks5RequestResponse(handle_t IDL_handle, unsigned int id, int inputBufferLength, const unsigned char *inputBuffer, int *outputBufferLength, unsigned char **outputBuffer)
{
    char atyp = 0;
    char cmd = 0;
    SOCKET targetSock = INVALID_SOCKET;
    struct sockaddr_in targetAddr, *pTmpIpv4;	// ipv4
    struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// ipv6
    struct addrinfo hints, *pTargetHost;
    int family = 0;
    char domainname[256] = {0};
    unsigned short domainnameLength = 0;
    char *colon;
    int ret = 0;
    u_long mode = 1;	// non-blocking mode
    pSOCKS_REQUEST pSocksRequest = NULL;
    pSOCKS_REQUEST_IPV4 pSocksRequestIpv4 = NULL;
    pSOCKS_REQUEST_DOMAINNAME pSocksRequestDomainname = NULL;
    pSOCKS_REQUEST_IPV6 pSocksRequestIpv6 = NULL;
    char *pTmp = NULL;
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    *outputBufferLength = 0;
    *outputBuffer = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount != 1)
    {
        lock.unlock();

#ifdef __DEBUG
        printf("[E] Socks5RequestResponse error id: %u\n", id);
#endif
        goto error;
    }else
    {
        sessionData = sessionDataMap[id];

        if(sessionData->id != id || !(sessionData->state == SELECTION_RESPONSE || sessionData->state == USERNAME_PASSWORD_AUTHENTICATION_RESPONSE))
        {
            sessionData->state = SOCKS5_ERROR;

            lock.unlock();

#ifdef __DEBUG
            printf("[E] Socks5RequestResponse error id: %u\n", id);
#endif
            goto error;
        }

        sessionData->state = SOCKS5_REQUEST;
    }

    lock.unlock();


    // socks SOCKS_REQUEST
    pTmp = (char *)calloc(BUFFER_SIZE, sizeof(char));
    pSocksRequest = (pSOCKS_REQUEST)inputBuffer;
    atyp = pSocksRequest->atyp;
    if(atyp != 0x1 && atyp != 0x3 && atyp != 0x4)
    {
#ifdef __DEBUG
		printf("[E] Socks5RequestResponse atyp error: %d\n", atyp);
#endif

        // socks SOCKS_RESPONSE send error
        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x8, 0x0, 0x1);
        *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
        memcpy(*outputBuffer, pTmp, *outputBufferLength);
        free(pTmp);

        goto error;
    }

    cmd = pSocksRequest->cmd;
    if(cmd != 0x1)	// CONNECT only
    {
#ifdef __DEBUG
		printf("[E] Socks5RequestResponse cmd error: %d\n", cmd);
#endif

        // socks SOCKS_RESPONSE send error
        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        if(atyp == 0x1 || atyp == 0x3)	// ipv4
        {
            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
        }else	// ipv6
        {
            *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
        }
        *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
        memcpy(*outputBuffer, pTmp, *outputBufferLength);
        free(pTmp);

        goto error;
    }

    memset(&targetAddr, 0, sizeof(struct sockaddr_in));
    memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));
    memset(&hints, 0, sizeof(struct addrinfo));

    if(pSocksRequest->atyp == 0x1)	// ipv4
    {
        family = AF_INET;
        targetAddr.sin_family = AF_INET;
        pSocksRequestIpv4 = (pSOCKS_REQUEST_IPV4)inputBuffer;
        memcpy(&targetAddr.sin_addr.s_addr, &pSocksRequestIpv4->dstAddr, 4);
        memcpy(&targetAddr.sin_port, &pSocksRequestIpv4->dstPort, 2);
    }else if(pSocksRequest->atyp == 0x3)	// domain name
    {
        pSocksRequestDomainname = (pSOCKS_REQUEST_DOMAINNAME)inputBuffer;
        domainnameLength = pSocksRequestDomainname->dstAddrLen;
        memcpy(&domainname, &pSocksRequestDomainname->dstAddr, domainnameLength);

        colon = strstr(domainname, ":");	// check ipv6 address
        if(colon == NULL)	// ipv4 address or domainname
        {
            hints.ai_family = AF_INET;	// ipv4
            if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0)
            {
                hints.ai_family = AF_INET6;	// ipv6
                if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0)
                {
#ifdef __DEBUG
                    printf("[E] Cannot resolv the domain name: %s\n", domainname);
#endif

                    // socks SOCKS_RESPONSE send error
                    lock.lock();
                    sessionData->state = SOCKS5_ERROR;
                    lock.unlock();

                    *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                    *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                    memcpy(*outputBuffer, pTmp, *outputBufferLength);
                    free(pTmp);

                    goto error;
                }
            }
        }else	// ipv6 address
        {
            hints.ai_family = AF_INET6;	// ipv6
            if(getaddrinfo(domainname, NULL, &hints, &pTargetHost) != 0)
            {
#ifdef __DEBUG
                printf("[E] Cannot resolv the domain name: %s\n", domainname);
#endif

                // socks SOCKS_RESPONSE send error
                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }
        }

        if(pTargetHost->ai_family == AF_INET)
        {
            family = AF_INET;
            targetAddr.sin_family = AF_INET;
            pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
            memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
            memcpy(&targetAddr.sin_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);
            freeaddrinfo(pTargetHost);
        }else if(pTargetHost->ai_family == AF_INET6)
        {
            family = AF_INET6;
            targetAddr6.sin6_family = AF_INET6;
            pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
            memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));
            memcpy(&targetAddr6.sin6_port, &pSocksRequestDomainname->dstAddr[domainnameLength], 2);
            freeaddrinfo(pTargetHost);
        }else
        {
#ifdef __DEBUG
            printf("[E] Not implemented\n");
#endif

            // socks SOCKS_RESPONSE send error
            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            freeaddrinfo(pTargetHost);
            goto error;
        }
    }else if(pSocksRequest->atyp == 0x4)	// ipv6
    {
        family = AF_INET6;
        targetAddr6.sin6_family = AF_INET6;
        pSocksRequestIpv6 = (pSOCKS_REQUEST_IPV6)inputBuffer;
        memcpy(&targetAddr6.sin6_addr, &pSocksRequestIpv6->dstAddr, 16);
        memcpy(&targetAddr6.sin6_port, &pSocksRequestIpv6->dstPort, 2);
    }else
    {
#ifdef __DEBUG
        printf("[E] Not implemented\n");
#endif

        // socks SOCKS_RESPONSE send error
        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
        *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
        memcpy(*outputBuffer, pTmp, *outputBufferLength);
        free(pTmp);

        goto error;
    }


    // socks SOCKS_RESPONSE
    lock.lock();
    sessionData->state = SOCKS5_RESPONSE;
    lock.unlock();

    if(atyp == 0x1)	// ipv4
    {
        if(cmd == 0x1)	// CONNECT
        {
            targetSock = socket(AF_INET, SOCK_STREAM, 0);

            if((ret = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0)
            {
#ifdef __DEBUG
				printf("[E] Cannot connect: %d\n", ret);
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                closesocket(targetSock);
                goto error;
            }

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x0, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);
        }else if(cmd == 0x2)	// BIND
        {
            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }else if(cmd == 0x3)	// UDP ASSOCIATE
        {
            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }else
        {
            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }
    }else if(atyp == 0x3)	// domain name
    {
        if(family == AF_INET)	// ipv4
        {
            if(cmd == 0x1)  // CONNECT
            {
                targetSock = socket(AF_INET, SOCK_STREAM, 0);

                if((ret = connect(targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0)
                {
#ifdef __DEBUG
                    printf("[E] Cannot connect: %d\n", ret);
#endif

                    lock.lock();
                    sessionData->state = SOCKS5_ERROR;
                    lock.unlock();

                    *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                    *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                    memcpy(*outputBuffer, pTmp, *outputBufferLength);
                    free(pTmp);

                    closesocket(targetSock);
                    goto error;
                }

                *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x0, 0x0, 0x1);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);
            }else if(cmd == 0x2)	// BIND
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }else if(cmd == 0x3)	// UDP ASSOCIATE
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }else
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }
        }else if(family == AF_INET6)	// ipv6
        {
            if(cmd == 0x1)	// CONNECT
            {
                targetSock = socket(AF_INET6, SOCK_STREAM, 0);

                if((ret = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0)
                {
#ifdef __DEBUG
                    printf("[E] Cannot connect: %d\n", ret);
#endif

                    lock.lock();
                    sessionData->state = SOCKS5_ERROR;
                    lock.unlock();

                    *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                    *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                    memcpy(*outputBuffer, pTmp, *outputBufferLength);
                    free(pTmp);

                    closesocket(targetSock);
                    goto error;
                }

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x0, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);
            }else if(cmd == 0x2)	// BIND
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }else if(cmd == 0x3)	// UDP ASSOCIATE
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }else
            {
#ifdef __DEBUG
                printf("[E] Not implemented\n");
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                goto error;
            }
        }else
        {
#ifdef __DEBUG
            printf("[E] Not implemented\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

           goto error;
        }
    }else if(atyp == 0x4)	// ipv6
    {
        if(cmd == 0x1)	// CONNECT
        {
            targetSock = socket(AF_INET6, SOCK_STREAM, 0);

            if((ret = connect(targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0)
            {
#ifdef __DEBUG
				printf("[E] Cannot connect: %d\n", ret);
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);
                free(pTmp);

                closesocket(targetSock);
                goto error;
            }

            *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x0, 0x0, 0x4);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);
        }else if(cmd == 0x2)	// BIND
        {
#ifdef __DEBUG
            printf("[E] Not implemented\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }else if(cmd == 0x3)	// UDP ASSOCIATE
        {
#ifdef __DEBUG
            printf("[E] Not implemented\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }else
        {
#ifdef __DEBUG
            printf("[E] Not implemented\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x4);
            *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
            memcpy(*outputBuffer, pTmp, *outputBufferLength);
            free(pTmp);

            goto error;
        }
    }else
    {
#ifdef __DEBUG
        printf("[E] Not implemented\n");
#endif

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        *outputBufferLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x1);
        *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
        memcpy(*outputBuffer, pTmp, *outputBufferLength);
        free(pTmp);

        goto error;
    }

    ret = ioctlsocket(targetSock, FIONBIO, &mode);
    if(ret != NO_ERROR)
    {
#ifdef __DEBUG
        printf("[E] Socks5RequestResponse ioctlsocket error: %d\n", ret);
#endif

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        goto error;
    }

    lock.lock();
    sessionData->state = SOCKS5_FORWARDER;
    sessionData->socket = targetSock;
    lock.unlock();

    return 0;
error:

    return -1;
}


int SendForwarderData(handle_t IDL_handle, unsigned int id, int inputBufferLength, const unsigned char *inputBuffer, long tv_sec, long tv_usec)
{
    int sen = 0;
    int sendLength = 0;
    int len = inputBufferLength;
    int err = 0;
    int ret = 0;
    fd_set writefds;
    timeval tv;
    tv.tv_sec = tv_sec;
    tv.tv_usec = tv_usec;
    timeval start;
    timeval end;
    long t = 0;
    SOCKET targetSock = INVALID_SOCKET;
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount != 1)
    {
        lock.unlock();

#ifdef __DEBUG
        printf("[E] SendForwarderData error id: %u\n", id);
#endif
        goto error;
    }else
    {
        sessionData = sessionDataMap[id];

        if(sessionData->id != id || sessionData->state != SOCKS5_FORWARDER)
        {
            sessionData->state = SOCKS5_ERROR;

            lock.unlock();

#ifdef __DEBUG
            printf("[E] SendForwarderData error id: %u\n", id);
#endif
            goto error;
        }

        targetSock = sessionData->socket;
    }

    lock.unlock();

    if(GetTimeOfDay(&start, NULL) == -1)
    {
#ifdef __DEBUG
        printf("[E] SendForwarderData GetTimeOfDay error\n");
#endif

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        goto error;
    }

    // forwarder
    while(len > 0)
    {
        if(GetTimeOfDay(&end, NULL) == -1)
        {
#ifdef __DEBUG
            printf("[E] SendForwarderData GetTimeOfDay error\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            goto error;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef __DEBUG
            printf("[E] SendForwarderData timeout\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            goto error;
        }

        FD_ZERO(&writefds);
        FD_SET(targetSock, &writefds);

        ret = select(NULL, NULL, &writefds, NULL, &tv);
        if(ret == 0 || ret == SOCKET_ERROR)
        {
#ifdef __DEBUG
            printf("[E] SendForwarderData select timeout\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            goto error;
        }

        if(FD_ISSET(targetSock, &writefds))
        {
            sen = send(targetSock, (char *)inputBuffer+sendLength, len, 0);
            if(sen == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    Sleep(5);
                    continue;
                }
#ifdef __DEBUG
                printf("[E] SendForwarderData send error: %x\n", err);
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                goto error;
            }else if(sen < 0)
            {
#ifdef __DEBUG
                printf("[E] SendForwarderData send error: %d\n", sen);
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                goto error;
            }else if(sen == 0)
            {
                continue;
            }else
            {
                sendLength += sen;
                len -= sen;
            }
        }
    }

    return sen;

error:

    return -1;
}


int RecvForwarderData(handle_t IDL_handle, unsigned int id, long tv_sec, long tv_usec, int *outputBufferLength, unsigned char **outputBuffer)
{
    int rec = 0;
    int err = 0;
    int ret = 0;
    fd_set readfds;
    timeval tv;
    timeval start;
    timeval end;
    long t = 0;
    tv.tv_sec = tv_sec;
    tv.tv_usec = tv_usec;
    char *pTmp = NULL;
    SOCKET targetSock = INVALID_SOCKET;
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    *outputBufferLength = 0;
    *outputBuffer = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount != 1)
    {
        lock.unlock();

#ifdef __DEBUG
        printf("[E] RecvForwarderData error id: %u\n", id);
#endif
        goto error;
    }else
    {
        sessionData = sessionDataMap[id];

        if(sessionData->id != id || sessionData->state != SOCKS5_FORWARDER)
        {
            sessionData->state = SOCKS5_ERROR;

            lock.unlock();

#ifdef __DEBUG
            printf("[E] RecvForwarderData error id: %u\n", id);
#endif
            goto error;
        }

        targetSock = sessionData->socket;
    }

    lock.unlock();

    if(GetTimeOfDay(&start, NULL) == -1)
    {
#ifdef __DEBUG
        printf("[E] RecvForwarderData GetTimeOfDay error\n");
#endif

        lock.lock();
        sessionData->state = SOCKS5_ERROR;
        lock.unlock();

        goto error;
    }

    pTmp = (char *)calloc(BUFFER_SIZE, sizeof(char));
    ZeroMemory(pTmp, BUFFER_SIZE);

    // forwarder
    while(1)
    {
        if(GetTimeOfDay(&end, NULL) == -1)
        {
#ifdef __DEBUG
            printf("[E] RecvForwarderData GetTimeOfDay error\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            free(pTmp);
            goto error;
        }

        t = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
        if(t >= (tv_sec * 1000000 + tv_usec))
        {
#ifdef __DEBUG
            printf("[E] RecvForwarderData timeout\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            free(pTmp);
            goto error;
        }

        FD_ZERO(&readfds);
        FD_SET(targetSock, &readfds);

        ret = select(NULL, &readfds, NULL, NULL, &tv);
        if(ret == 0 || ret == SOCKET_ERROR)
        {
#ifdef __DEBUG
            printf("[E] RecvForwarderData select timeout\n");
#endif

            lock.lock();
            sessionData->state = SOCKS5_ERROR;
            lock.unlock();

            free(pTmp);
            goto error;
        }

        if(FD_ISSET(targetSock, &readfds))
        {
            rec = recv(targetSock, (char *)pTmp, BUFFER_SIZE, 0);
            if(rec == SOCKET_ERROR)
            {
                err = WSAGetLastError();
                if(err == WSAEWOULDBLOCK)
                {
                    Sleep(5);
                    continue;
                }else
                {
#ifdef __DEBUG
                    printf("[E] RecvForwarderData recv error: %x\n", err);
#endif

                    lock.lock();
                    sessionData->state = SOCKS5_ERROR;
                    lock.unlock();

                    free(pTmp);
                    goto error;
                }
            }else if(rec <= 0)
            {
#ifdef __DEBUG
                printf("[E] RecvForwarderData recv error: %d\n", rec);
#endif

                lock.lock();
                sessionData->state = SOCKS5_ERROR;
                lock.unlock();

                free(pTmp);
                goto error;
            }else
            {
                *outputBufferLength = rec;
                *outputBuffer = (unsigned char *)midl_user_allocate(*outputBufferLength);
                memcpy(*outputBuffer, pTmp, *outputBufferLength);

                free(pTmp);
                break;
            }
        }
    }

    return rec;

error:

    return -1;
}


void Close(handle_t IDL_handle, unsigned int id)
{
    std::size_t checkKeyCount = 0;
    pSESSION_DATA sessionData = NULL;

    std::unique_lock<std::mutex> lock(sessionDataMapMutex);

    checkKeyCount = sessionDataMap.count(id);
    if(checkKeyCount == 1)
    {
        sessionData = sessionDataMap[id];

        if(sessionData->socket != INVALID_SOCKET)
        {
            closesocket(sessionData->socket);
        }

//      sessionData->state = SOCKS5_FINISH;

        sessionDataMap.erase(id);
        free(sessionData);
    }

    lock.unlock();
}


void Usage(char *filename)
{
    printf("usage        : %s\n", filename);
    printf("             : [-p socks5server_rpc_endpoint]\n");
    printf("example      : %s\n", filename);
    printf("             : %s -p 45000\n", filename);
}


int GetOpt(int argc, char **argv, char *optstring)
{
    unsigned char opt = '\0';
    unsigned char next = '\0';
    char *argtmp = NULL;

    while(1){
        opt = *(optstring + optstringIndex);
        optstringIndex++;
        if(opt == '\0')
        {
            break;
        }

        next = *(optstring + optstringIndex);
        if(next == ':')
        {
            optstringIndex++;
        }

        for(int i=1; i<argc; i++)
        {
            argtmp = argv[i];
            if(argtmp[0] == '-')
            {
                if(argtmp[1] == opt)
                {
                    if(next == ':')
                    {
                        optarg = argv[i+1];
                        return (int)opt;
                    }else
                    {
                        return (int)opt;
                    }
                }
            }
        }
    }

    return 0;
}


int main(int argc, char **argv)
{
    int opt;
    char optstring[] = "hp:";
    char *socks5ServerRpcEndpoint = NULL;

    RPC_STATUS status;
    RPC_BINDING_VECTOR *rpcBindingVector = NULL;
    int ret = 0;
    WSADATA wsaData;

    while((opt=GetOpt(argc, argv, optstring)) > 0)
    {
        switch(opt)
        {
            case 'h':
                Usage(argv[0]);
                exit(-1);
                break;

            case 'p':
                socks5ServerRpcEndpoint = optarg;
                break;

            default:
                Usage(argv[0]);
                exit(-1);
        }
    }

    ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(ret != 0)
    {
#ifdef __DEBUG
        printf("[E] WSAStartup error: %d\n", ret);
#endif
        goto error;
    }

    if(socks5ServerRpcEndpoint == NULL)
    {
        status = RpcServerUseProtseqA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, NULL);
        if(status)
        {
#ifdef __DEBUG
            printf("[E] RpcServerUseProtseqA error: %x\n", status);
#endif
            goto error;
        }
    }else
    {
        status = RpcServerUseProtseqEpA((RPC_CSTR)"ncacn_ip_tcp", RPC_C_PROTSEQ_MAX_REQS_DEFAULT, (RPC_CSTR)(RPC_CSTR)socks5ServerRpcEndpoint, NULL);
        if(status)
        {
#ifdef __DEBUG
            printf("[E] RpcServerUseProtseqEpA error: %x\n", status);
#endif
            goto error;
        }
    }

    status = RpcServerRegisterIf(Socks5Server_v1_0_s_ifspec, NULL, NULL);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcServerRegisterIf error: %x\n", status);
#endif
        goto error;
    }

    status = RpcServerInqBindings(&rpcBindingVector);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcServerInqBindings error: %x\n", status);
#endif
        goto error;
    }

    status = RpcEpRegister(Socks5Server_v1_0_s_ifspec, rpcBindingVector, NULL, (RPC_CSTR)"socks5");
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcEpRegister error: %x\n", status);
#endif
        goto error;
    }

    printf("Socks5 Server running...\n");

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, 0);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcServerListen error: %x\n", status);
#endif
        goto error;
    }

    status = RpcBindingVectorFree(&rpcBindingVector);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcBindingVectorFree error: %x\n", status);
#endif
        goto error;
    }

    status = RpcServerUnregisterIf(Socks5Server_v1_0_s_ifspec, NULL, 0);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcServerUnregisterIf error: %x\n", status);
#endif
        goto error;
    }

    WSACleanup();

    return 0;

error:
    if(rpcBindingVector != NULL)
    {
        status = RpcBindingVectorFree(&rpcBindingVector);
        if(status)
        {
#ifdef __DEBUG
            printf("[E] RpcBindingVectorFree error: %x\n", status);
#endif
        }
    }

    status = RpcServerUnregisterIf(Socks5Server_v1_0_s_ifspec, NULL, 0);
    if(status)
    {
#ifdef __DEBUG
        printf("[E] RpcServerUnregisterIf error: %x\n", status);
#endif
        goto error;
    }

    WSACleanup();

    return -1;
}


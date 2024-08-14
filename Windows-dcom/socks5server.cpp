/*
 * Title:  socks5server.cpp (Windows DCOM)
 * Author: Shuichiro Endo
 */

#define _DEBUG

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "socks5server.h"
#include "socks5.h"

#pragma comment(lib,"kernel32.lib")
#pragma comment(lib,"user32.lib")
#pragma comment(lib,"advapi32.lib")
#pragma comment(lib,"rpcrt4.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
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

#define BUFFERSIZE 8192


// CLSID:70d2c8cf-f464-414a-84be-95fecc01c132
static const GUID CLSID_Socks5Server =
{0x70d2c8cf, 0xf464, 0x414a, {0x84, 0xbe, 0x95, 0xfe, 0xcc, 0x01, 0xc1, 0x32}};
static const TCHAR clsid[] = TEXT("{70d2c8cf-f464-414a-84be-95fecc01c132}");
static const TCHAR progid[] = TEXT("Socks5.Socks5Server.1");
static const TCHAR appid[] = TEXT("{b1da36cc-d4e7-4f47-b7f8-8ee763fdc7e5}");
static const TCHAR serverfilename[] = TEXT("socks5server.exe");

static HANDLE g_hExitEvent = NULL;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

static char g_cAuthenticationMethod = 0x0;	// 0x0:No Authentication Required  0x2:Username/Password Authentication
static char g_cUsername[256] = "socks5user";
static char g_cPassword[256] = "supersecretpassword";


// CSocks5Server
class CSocks5Server:public ISocks5Server
{
private:
    ULONG m_ulRefCount;
    ULONG m_ulClientCookie;
    DWORD m_dwSocks5State;
    CRITICAL_SECTION m_cs;
    WSADATA m_wsaData;
    SOCKET m_targetSock = INVALID_SOCKET;

    int GetTimeOfDay(timeval *pTv, timezone *pTz);
    int SetSocksResponseIpv4(BYTE *pbBuffer, char cVer, char cReq, char cRsv, char cAtyp);
    int SetSocksResponseIpv6(BYTE *pbBuffer, char cVer, char cReq, char cRsv, char cAtyp);

public:
    CSocks5Server();
    ~CSocks5Server();

    // IUnknown interface
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject);
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();

    // ISocks5Server interface
    HRESULT SelectionRequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer);
    HRESULT UsernamePasswordAuthenticationRequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer);
    HRESULT Socks5RequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer);
    HRESULT SendForwarderData(ULONG ulInputLength, BYTE *pbInputBuffer, LONG ltv_sec, LONG ltv_usec);
    HRESULT RecvForwarderData(ULONG *pulOutputLength, BYTE **pbOutputBuffer, LONG ltv_sec, LONG ltv_usec);
    HRESULT Close();
};


CSocks5Server::CSocks5Server()
    :   m_ulRefCount(0),
        m_ulClientCookie(0),
        m_dwSocks5State(SOCKS5_START)
{
    InitializeCriticalSection(&m_cs);

    int iErr = WSAStartup(MAKEWORD(2, 2), &m_wsaData);
}


CSocks5Server::~CSocks5Server()
{
    DeleteCriticalSection(&m_cs);
}


STDMETHODIMP CSocks5Server::QueryInterface(REFIID riid, void **ppvObject)
{
    if(ppvObject == NULL){
        return E_INVALIDARG;
    }

    if(IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_ISocks5Server)){
        *ppvObject = static_cast<ISocks5Server *>(this);
    }else{
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    reinterpret_cast<IUnknown *>(*ppvObject)->AddRef();

    return S_OK;
}


ULONG STDMETHODCALLTYPE CSocks5Server::AddRef()
{
    return InterlockedIncrement(&m_ulRefCount);
}


ULONG STDMETHODCALLTYPE CSocks5Server::Release()
{
    if(InterlockedDecrement(&m_ulRefCount) == 0){
        delete this;
        return 0;
    }

    return m_ulRefCount;
}


int STDMETHODCALLTYPE CSocks5Server::GetTimeOfDay(timeval *pTv, timezone *pTz)
{
	if(pTv){
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
	}else{
		return -1;
	}

	if(pTz){
		TIME_ZONE_INFORMATION timezone;
		GetTimeZoneInformation(&timezone);
		pTz->tz_minuteswest = timezone.Bias;
		pTz->tz_dsttime = 0;
	}

	return 0;
}


int STDMETHODCALLTYPE CSocks5Server::SetSocksResponseIpv4(BYTE *pbBuffer, char cVer, char cReq, char cRsv, char cAtyp)
{
	pSOCKS_RESPONSE_IPV4 pSocksResponseIpv4 = (pSOCKS_RESPONSE_IPV4)pbBuffer;

	pSocksResponseIpv4->ver = cVer;		// protocol version
	pSocksResponseIpv4->req = cReq;		// Connection refused
	pSocksResponseIpv4->rsv = cRsv;		// RESERVED
	pSocksResponseIpv4->atyp = cAtyp;	// IPv4
	memset(pSocksResponseIpv4->bndAddr, 0, 4);	// BND.ADDR
	memset(pSocksResponseIpv4->bndPort, 0, 2);	// BND.PORT

    return 10;  // sizeof(SOCKS_RESPONSE_IPV4)
}


int STDMETHODCALLTYPE CSocks5Server::SetSocksResponseIpv6(BYTE *pbBuffer, char cVer, char cReq, char cRsv, char cAtyp)
{
	pSOCKS_RESPONSE_IPV6 pSocksResponseIpv6 = (pSOCKS_RESPONSE_IPV6)pbBuffer;

	pSocksResponseIpv6->ver = cVer;		// protocol version
	pSocksResponseIpv6->req = cReq;		// Connection refused
	pSocksResponseIpv6->rsv = cRsv;		// RESERVED
	pSocksResponseIpv6->atyp = cAtyp;	// IPv6
	memset(pSocksResponseIpv6->bndAddr, 0, 16);	   // BND.ADDR
	memset(pSocksResponseIpv6->bndPort, 0, 2);     // BND.PORT

    return 22;  // sizeof(SOCKS_RESPONSE_IPV6)
}


HRESULT STDMETHODCALLTYPE CSocks5Server::SelectionRequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer)
{
    unsigned char ucMethod = 0xFF;
    pSELECTION_REQUEST pSelectionRequest = NULL;
    pSELECTION_RESPONSE pSelectionResponse = NULL;
    BYTE *pTmp = NULL;

    EnterCriticalSection(&m_cs);
    if(m_dwSocks5State == SOCKS5_START){
        pTmp = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));
        ZeroMemory(pTmp, BUFFERSIZE);

        // socks SELECTION_REQUEST
        m_dwSocks5State = SELECTION_REQUEST;

        pSelectionRequest = (pSELECTION_REQUEST)pbInputBuffer;
        for(int i=0; i<pSelectionRequest->nmethods; i++){
            if(pSelectionRequest->methods[i] == g_cAuthenticationMethod){	// NO AUTHENTICATION REQUIRED or USERNAME/PASSWORD
                ucMethod = pSelectionRequest->methods[i];
                break;
            }
        }


        // socks SELECTION_RESPONSE
        m_dwSocks5State = SELECTION_RESPONSE;

        pSelectionResponse = (pSELECTION_RESPONSE)pTmp;
        pSelectionResponse->ver = 0x5;		    // socks version 5
        pSelectionResponse->method = ucMethod;	// no authentication required or username/password
        if(pSelectionRequest->ver != 0x5 || g_cAuthenticationMethod != ucMethod){
            pSelectionResponse->method = 0xFF;

            m_dwSocks5State = SOCKS5_ERROR;
        }

        *pulOutputLength = 2;   // sizeof(SELECTION_RESPONSE)
        *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
        memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
        free(pTmp);
    }else{
         LeaveCriticalSection(&m_cs);
         return E_FAIL;
    }

    LeaveCriticalSection(&m_cs);
    return S_OK;
}


HRESULT STDMETHODCALLTYPE CSocks5Server::UsernamePasswordAuthenticationRequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer)
{
    unsigned char ucUlen = 0;
    unsigned char ucplen = 0;
    char cUname[256] = {0};
    char cPasswd[256] = {0};
    pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP pUsernamePasswordAuthenticationRequest = NULL;
    pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE pUsernamePasswordAuthenticationResponse = NULL;
    BYTE *pTmp = NULL;


    EnterCriticalSection(&m_cs);
    if(m_dwSocks5State == SELECTION_RESPONSE && g_cAuthenticationMethod == 0x2){
        pTmp = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));
        ZeroMemory(pTmp, BUFFERSIZE);

        // socks USERNAME_PASSWORD_AUTHENTICATION_REQUEST
        m_dwSocks5State = USERNAME_PASSWORD_AUTHENTICATION_REQUEST;

        pUsernamePasswordAuthenticationRequest = (pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP)pbInputBuffer;
        ucUlen = pUsernamePasswordAuthenticationRequest->ulen;
        memcpy(cUname, &pUsernamePasswordAuthenticationRequest->uname, ucUlen);
        memcpy(&ucplen, &pUsernamePasswordAuthenticationRequest->uname + ucUlen, 1);
        memcpy(cPasswd, &pUsernamePasswordAuthenticationRequest->uname + ucUlen + 1, ucplen);


        // socks USERNAME_PASSWORD_AUTHENTICATION_RESPONSE
        m_dwSocks5State = USERNAME_PASSWORD_AUTHENTICATION_RESPONSE;

        pUsernamePasswordAuthenticationResponse = (pUSERNAME_PASSWORD_AUTHENTICATION_RESPONSE)pTmp;
        pUsernamePasswordAuthenticationResponse->ver = 0x1;
        if(pUsernamePasswordAuthenticationRequest->ver == 0x1 && !strncmp(cUname, g_cUsername, sizeof(g_cUsername)) && !strncmp(cPasswd, g_cPassword, sizeof(g_cPassword))){
            pUsernamePasswordAuthenticationResponse->status = 0x0;
        }else{
            pUsernamePasswordAuthenticationResponse->status = 0xFF;

            m_dwSocks5State = SOCKS5_ERROR;
        }

        *pulOutputLength = 2;   // sizeof(USERNAME_PASSWORD_AUTHENTICATION_RESPONSE)
        *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
        memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
        free(pTmp);
    }else{
         LeaveCriticalSection(&m_cs);
         return E_FAIL;
    }

    LeaveCriticalSection(&m_cs);
    return S_OK;
}


HRESULT STDMETHODCALLTYPE CSocks5Server::Socks5RequestResponse(ULONG ulInputLength, BYTE *pbInputBuffer, ULONG *pulOutputLength, BYTE **pbOutputBuffer)
{
    char cAtyp = 0;
    char cCmd = 0;
    struct sockaddr_in targetAddr, *pTmpIpv4;	// IPv4
    struct sockaddr_in6 targetAddr6, *pTmpIpv6;	// IPv6
    struct addrinfo hints, *pTargetHost;
    int iFamily = 0;
    char cDomainname[256] = {0};
    u_short unDomainnameLength = 0;
    char *pcColon;
    int iErr = 0;
    u_long ulMode = 1;	// non-blocking mode
    pSOCKS_REQUEST pSocksRequest = NULL;
    pSOCKS_REQUEST_IPV4 pSocksRequestIpv4 = NULL;
    pSOCKS_REQUEST_DOMAINNAME pSocksRequestDomainname = NULL;
    pSOCKS_REQUEST_IPV6 pSocksRequestIpv6 = NULL;
    BYTE *pTmp = NULL;


    EnterCriticalSection(&m_cs);
    if(m_dwSocks5State == SELECTION_RESPONSE || m_dwSocks5State == USERNAME_PASSWORD_AUTHENTICATION_RESPONSE){
        pTmp = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));
        ZeroMemory(pTmp, BUFFERSIZE);

        // socks SOCKS_REQUEST
        m_dwSocks5State = SOCKS5_REQUEST;

        pSocksRequest = (pSOCKS_REQUEST)pbInputBuffer;
        cAtyp = pSocksRequest->atyp;
        if(cAtyp != 0x1 && cAtyp != 0x3 && cAtyp != 0x4){
            // socks SOCKS_RESPONSE send error
            m_dwSocks5State = SOCKS5_ERROR;

            *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x8, 0x0, 0x1);
            *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
            memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
            free(pTmp);

            LeaveCriticalSection(&m_cs);
            return S_OK;
        }

        cCmd = pSocksRequest->cmd;
        if(cCmd != 0x1){	// CONNECT only
            // socks SOCKS_RESPONSE send error
            m_dwSocks5State = SOCKS5_ERROR;

            if(cAtyp == 0x1 || cAtyp == 0x3){	// IPv4
                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
            }else{	// IPv6
                *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
            }
            *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
            memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
            free(pTmp);

            LeaveCriticalSection(&m_cs);
            return S_OK;
        }

        memset(&targetAddr, 0, sizeof(struct sockaddr_in));
        memset(&targetAddr6, 0, sizeof(struct sockaddr_in6));
        memset(&hints, 0, sizeof(struct addrinfo));

        if(pSocksRequest->atyp == 0x1){	// IPv4
            iFamily = AF_INET;
            targetAddr.sin_family = AF_INET;
            pSocksRequestIpv4 = (pSOCKS_REQUEST_IPV4)pbInputBuffer;
            memcpy(&targetAddr.sin_addr.s_addr, &pSocksRequestIpv4->dstAddr, 4);
            memcpy(&targetAddr.sin_port, &pSocksRequestIpv4->dstPort, 2);
        }else if(pSocksRequest->atyp == 0x3){	// domain name
            pSocksRequestDomainname = (pSOCKS_REQUEST_DOMAINNAME)pbInputBuffer;
            unDomainnameLength = pSocksRequestDomainname->dstAddrLen;
            memcpy(&cDomainname, &pSocksRequestDomainname->dstAddr, unDomainnameLength);

            pcColon = strstr(cDomainname, ":");	// check ipv6 address
            if(pcColon == NULL){	// ipv4 address or domainname
                hints.ai_family = AF_INET;	// IPv4
                if(getaddrinfo(cDomainname, NULL, &hints, &pTargetHost) != 0){
                    hints.ai_family = AF_INET6;	// IPv6
                    if(getaddrinfo(cDomainname, NULL, &hints, &pTargetHost) != 0){
                        // socks SOCKS_RESPONSE send error
                        m_dwSocks5State = SOCKS5_ERROR;

                        *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                        *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                        memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                        free(pTmp);

                        LeaveCriticalSection(&m_cs);
                        return S_OK;
                    }
                }
            }else{	// ipv6 address
                hints.ai_family = AF_INET6;	// IPv6
                if(getaddrinfo(cDomainname, NULL, &hints, &pTargetHost) != 0){
                    // socks SOCKS_RESPONSE send error
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }
            }

            if(pTargetHost->ai_family == AF_INET){
                iFamily = AF_INET;
                targetAddr.sin_family = AF_INET;
                pTmpIpv4 = (struct sockaddr_in *)pTargetHost->ai_addr;
                memcpy(&targetAddr.sin_addr, &pTmpIpv4->sin_addr, sizeof(unsigned long));
                memcpy(&targetAddr.sin_port, &pSocksRequestDomainname->dstAddr[unDomainnameLength], 2);
                freeaddrinfo(pTargetHost);
            }else if(pTargetHost->ai_family == AF_INET6){
                iFamily = AF_INET6;
                targetAddr6.sin6_family = AF_INET6;
                pTmpIpv6 = (struct sockaddr_in6 *)pTargetHost->ai_addr;
                memcpy(&targetAddr6.sin6_addr, &pTmpIpv6->sin6_addr, sizeof(struct in6_addr));
                memcpy(&targetAddr6.sin6_port, &pSocksRequestDomainname->dstAddr[unDomainnameLength], 2);
                freeaddrinfo(pTargetHost);
            }else{
                // socks SOCKS_RESPONSE send error
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                freeaddrinfo(pTargetHost);
                LeaveCriticalSection(&m_cs);
                return S_OK;
            }
        }else if(pSocksRequest->atyp == 0x4){	// IPv6
            iFamily = AF_INET6;
            targetAddr6.sin6_family = AF_INET6;
            pSocksRequestIpv6 = (pSOCKS_REQUEST_IPV6)pbInputBuffer;
            memcpy(&targetAddr6.sin6_addr, &pSocksRequestIpv6->dstAddr, 16);
            memcpy(&targetAddr6.sin6_port, &pSocksRequestIpv6->dstPort, 2);
        }else {
            // socks SOCKS_RESPONSE send error
            m_dwSocks5State = SOCKS5_ERROR;

            *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
            *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
            memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
            free(pTmp);

            LeaveCriticalSection(&m_cs);
            return S_OK;
        }

        // socks SOCKS_RESPONSE
        m_dwSocks5State = SOCKS5_RESPONSE;

        if(cAtyp == 0x1){	// IPv4
            if(cCmd == 0x1){	// CONNECT
                m_targetSock = socket(AF_INET, SOCK_STREAM, 0);

                if((iErr = connect(m_targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    closesocket(m_targetSock);
                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x0, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);
            }else if(cCmd == 0x2){	// BIND
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }else if(cCmd == 0x3){	// UDP ASSOCIATE
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }else{
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }
        }else if(cAtyp == 0x3){	// domain name
            if(iFamily == AF_INET){	// IPv4
                if(cCmd == 0x1){	// CONNECT
                    m_targetSock = socket(AF_INET, SOCK_STREAM, 0);

                    if((iErr = connect(m_targetSock, (struct sockaddr *)&targetAddr, sizeof(targetAddr))) < 0){
                        m_dwSocks5State = SOCKS5_ERROR;

                        *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x5, 0x0, 0x1);
                        *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                        memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                        free(pTmp);

                        closesocket(m_targetSock);
                        LeaveCriticalSection(&m_cs);
                        return S_OK;
                    }

                    *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x0, 0x0, 0x1);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);
                }else if(cCmd == 0x2){	// BIND
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }else if(cCmd == 0x3){	// UDP ASSOCIATE
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x7, 0x0, 0x1);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }else{
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }
            }else if(iFamily == AF_INET6){	// IPv6
                if(cCmd == 0x1){	// CONNECT
                    m_targetSock = socket(AF_INET6, SOCK_STREAM, 0);

                    if((iErr = connect(m_targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
                        m_dwSocks5State = SOCKS5_ERROR;

                        *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                        *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                        memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                        free(pTmp);

                        closesocket(m_targetSock);
                        LeaveCriticalSection(&m_cs);
                        return S_OK;
                    }

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x0, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);
                }else if(cCmd == 0x2){	// BIND
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }else if(cCmd == 0x3){	// UDP ASSOCIATE
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }else{
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }
            }else{
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv4(pTmp, 0x5, 0x1, 0x0, 0x1);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }
        }else if(cAtyp == 0x4){	// IPv6
            if(cCmd == 0x1){	// CONNECT
                m_targetSock = socket(AF_INET6, SOCK_STREAM, 0);

                if((iErr = connect(m_targetSock, (struct sockaddr *)&targetAddr6, sizeof(targetAddr6))) < 0){
                    m_dwSocks5State = SOCKS5_ERROR;

                    *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x5, 0x0, 0x4);
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);

                    closesocket(m_targetSock);
                    LeaveCriticalSection(&m_cs);
                    return S_OK;
                }

                *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x0, 0x0, 0x4);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);
            }else if(cCmd == 0x2){	// BIND
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }else if(cCmd == 0x3){	// UDP ASSOCIATE
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x7, 0x0, 0x4);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }else{
                m_dwSocks5State = SOCKS5_ERROR;

                *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x4);
                *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                free(pTmp);

                LeaveCriticalSection(&m_cs);
                return S_OK;
            }
        }else{
            m_dwSocks5State = SOCKS5_ERROR;

            *pulOutputLength = SetSocksResponseIpv6(pTmp, 0x5, 0x1, 0x0, 0x1);
            *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
            memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
            free(pTmp);

            LeaveCriticalSection(&m_cs);
            return S_OK;
        }
    }else{
         LeaveCriticalSection(&m_cs);
         return E_FAIL;
    }

    iErr = ioctlsocket(m_targetSock, FIONBIO, &ulMode);
    if(iErr != NO_ERROR){
        m_dwSocks5State = SOCKS5_ERROR;

        LeaveCriticalSection(&m_cs);
        return E_FAIL;
    }

    m_dwSocks5State = SOCKS5_FORWARDER;

    LeaveCriticalSection(&m_cs);
    return S_OK;
}


HRESULT STDMETHODCALLTYPE CSocks5Server::SendForwarderData(ULONG ulInputLength, BYTE *pbInputBuffer, LONG ltv_sec, LONG ltv_usec)
{
    int iSen = 0;
    int iSendLength = 0;
    int iLen = ulInputLength;
    int iErr = 0;
    int iRet = 0;
    fd_set writefds;
    timeval tv;
    tv.tv_sec = ltv_sec;
    tv.tv_usec = ltv_usec;
	timeval start;
	timeval end;
	long lt = 0;


    if(m_dwSocks5State == SOCKS5_FORWARDER){
        if(GetTimeOfDay(&start, NULL) == -1){
            EnterCriticalSection(&m_cs);
            m_dwSocks5State = SOCKS5_ERROR;
            LeaveCriticalSection(&m_cs);
            return E_FAIL;
        }

        // forwarder
        while(iLen > 0){
            if(GetTimeOfDay(&end, NULL) == -1){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                return E_FAIL;
            }

            lt = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
            if(lt >= (ltv_sec * 1000000 + ltv_usec)){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                return E_FAIL;
            }

            FD_ZERO(&writefds);
            FD_SET(m_targetSock, &writefds);

            iRet = select(NULL, NULL, &writefds, NULL, &tv);
            if(iRet == 0 || iRet == SOCKET_ERROR){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                return E_FAIL;
            }

            if(FD_ISSET(m_targetSock, &writefds)){
                iSen = send(m_targetSock, (char *)pbInputBuffer+iSendLength, iLen, 0);
                if(iSen == SOCKET_ERROR){
                    iErr = WSAGetLastError();
                    if(iErr == WSAEWOULDBLOCK){
                        Sleep(5);
                        continue;
                    }
                    EnterCriticalSection(&m_cs);
                    m_dwSocks5State = SOCKS5_ERROR;
                    LeaveCriticalSection(&m_cs);
                    return E_FAIL;
                }else if(iSen < 0){
                    EnterCriticalSection(&m_cs);
                    m_dwSocks5State = SOCKS5_ERROR;
                    LeaveCriticalSection(&m_cs);
                    return E_FAIL;
                }else if(iSen == 0){
                    continue;
                }else{
                    iSendLength += iSen;
                    iLen -= iSen;
                }
            }
        }
    }else{
         return E_FAIL;
    }

    return S_OK;
}


HRESULT STDMETHODCALLTYPE CSocks5Server::RecvForwarderData(ULONG *pulOutputLength, BYTE **pbOutputBuffer, LONG ltv_sec, LONG ltv_usec)
{
	int iRec = 0;
	int iErr = 0;
    int iRet = 0;
	fd_set readfds;
	timeval tv;
	timeval start;
	timeval end;
	long lt = 0;
    tv.tv_sec = ltv_sec;
    tv.tv_usec = ltv_usec;
    BYTE *pTmp = NULL;


    if(m_dwSocks5State == SOCKS5_FORWARDER){
        if(GetTimeOfDay(&start, NULL) == -1){
            EnterCriticalSection(&m_cs);
            m_dwSocks5State = SOCKS5_ERROR;
            LeaveCriticalSection(&m_cs);
            return E_FAIL;
        }

        pTmp = (BYTE *)calloc(BUFFERSIZE, sizeof(BYTE));
        ZeroMemory(pTmp, BUFFERSIZE);

        // forwarder
        while(1){
            if(GetTimeOfDay(&end, NULL) == -1){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                return E_FAIL;
            }

            lt = (end.tv_sec - start.tv_sec) * 1000000 + (end.tv_usec - start.tv_usec);	// microsecond
            if(lt >= (ltv_sec * 1000000 + ltv_usec)){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                return E_FAIL;
            }

            FD_ZERO(&readfds);
            FD_SET(m_targetSock, &readfds);

            iRet = select(NULL, &readfds, NULL, NULL, &tv);
            if(iRet == 0 || iRet == SOCKET_ERROR){
                EnterCriticalSection(&m_cs);
                m_dwSocks5State = SOCKS5_ERROR;
                LeaveCriticalSection(&m_cs);
                free(pTmp);
                return E_FAIL;
            }

            if(FD_ISSET(m_targetSock, &readfds)){
                iRec = recv(m_targetSock, (char *)pTmp, BUFFERSIZE, 0);
                if(iRec == SOCKET_ERROR){
                    iErr = WSAGetLastError();
                    if(iErr == WSAEWOULDBLOCK){
                        Sleep(5);
                        continue;
                    }else{
                        EnterCriticalSection(&m_cs);
                        m_dwSocks5State = SOCKS5_ERROR;
                        LeaveCriticalSection(&m_cs);
                        free(pTmp);
                        return E_FAIL;
                    }
                }else if(iRec < 0){
                    EnterCriticalSection(&m_cs);
                    m_dwSocks5State = SOCKS5_ERROR;
                    LeaveCriticalSection(&m_cs);
                    free(pTmp);
                    return E_FAIL;
                }else if(iRec == 0){
                    continue;
                }else{
                    *pulOutputLength = (ULONG)iRec;
                    *pbOutputBuffer = static_cast<BYTE *>(CoTaskMemAlloc(*pulOutputLength));
                    memcpy(*pbOutputBuffer, pTmp, *pulOutputLength);
                    free(pTmp);
                    break;
                }
            }
        }
    }else{
         return E_FAIL;
    }

    return S_OK;
}


HRESULT STDMETHODCALLTYPE CSocks5Server::Close()
{
    EnterCriticalSection(&m_cs);
    if(m_targetSock != INVALID_SOCKET){
        closesocket(m_targetSock);
    }
    WSACleanup();

    LeaveCriticalSection(&m_cs);
    return S_OK;
}



// CSocks5ServerFactory
inline ULONG ComponentAddRef()
{
    return (CoAddRefServerProcess());
}


inline ULONG ComponentRelease()
{
    ULONG ul = CoReleaseServerProcess();
    if(ul == 0){
        SetEvent(g_hExitEvent);
    }

    return ul;
}


class CSocks5ServerFactory:public IClassFactory
{
public:
    CSocks5ServerFactory();
    ~CSocks5ServerFactory();

    // IUnknown interface
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject);
    ULONG STDMETHODCALLTYPE AddRef();
    ULONG STDMETHODCALLTYPE Release();

    // IClassFactory interface
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject);
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock);

private:
    LONG m_lRefCount;
};


CSocks5ServerFactory::CSocks5ServerFactory()
    : m_lRefCount(0)
{

}


CSocks5ServerFactory::~CSocks5ServerFactory()
{

}


HRESULT STDMETHODCALLTYPE CSocks5ServerFactory::QueryInterface(REFIID riid, void **ppvObject)
{
    if(ppvObject == NULL){
        return E_INVALIDARG;
    }

    if(IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)){
        *ppvObject = static_cast<IClassFactory *>(this);
    }else{
        *ppvObject = NULL;
        return E_NOINTERFACE;
    }

    AddRef();

    return S_OK;
}


ULONG STDMETHODCALLTYPE CSocks5ServerFactory::AddRef()
{
    return ComponentAddRef();
}


ULONG STDMETHODCALLTYPE CSocks5ServerFactory::Release()
{
    return ComponentRelease();
}


HRESULT STDMETHODCALLTYPE CSocks5ServerFactory::CreateInstance(IUnknown *pUnkOuter, REFIID riid, void **ppvObject)
{
    CSocks5Server *pObject = NULL;
    HRESULT hr;
    *ppvObject = NULL;

    if(pUnkOuter != NULL){
        return CLASS_E_NOAGGREGATION;
    }

    pObject = new CSocks5Server();
    if(pObject == NULL){
        return E_OUTOFMEMORY;
    }

    hr = pObject->QueryInterface(riid, ppvObject);
    if(FAILED(hr)){
        delete pObject;
    }

    return hr;
}


HRESULT STDMETHODCALLTYPE CSocks5ServerFactory::LockServer(BOOL fLock)
{
    if(fLock){
        ComponentAddRef();
    }else{
        ComponentRelease();
    }

    return S_OK;
}



// Function
BOOL CreateRegistryKey(HKEY hkeyRoot, LPTSTR psubkey, LPTSTR pvalue, LPSTR pdata)
{
    HKEY hkey;
    LONG result;
    DWORD size;
    TCHAR message[256];


    result = RegCreateKeyEx(hkeyRoot, psubkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hkey, NULL);
    if(result != ERROR_SUCCESS){
        wsprintf(message, TEXT("[E] RegCreateKeyEx error:0x%x"), result);
        MessageBox(NULL, message, "Socks5Server", MB_ICONERROR);
        return FALSE;
    }

    if(pdata != NULL){
        size = (lstrlen(pdata) + 1) * sizeof(TCHAR);
    }else{
        size = 0;
    }

    result = RegSetValueEx(hkey, pvalue, 0, REG_SZ, (LPBYTE)pdata, size);
    if(result != ERROR_SUCCESS){
        wsprintf(message, TEXT("[E] RegSetValueEx error:0x%x"), result);
        MessageBox(NULL, message, "Socks5Server", MB_ICONERROR);
        return FALSE;
    }

    RegCloseKey(hkey);

    return TRUE;
}


BOOL RemoveRegistryKey(HKEY hkeyRoot, LPTSTR psubkey)
{
    LONG result;
    TCHAR message[256];

    result = RegDeleteTree(hkeyRoot, psubkey);
    if(result != ERROR_SUCCESS){
        wsprintf(message, TEXT("[E] RegDeleteTree error:0x%x"), result);
        MessageBox(NULL, message, "Socks5Server", MB_ICONERROR);

        return FALSE;
    }

    return TRUE;
}


HRESULT RegisterServer(HINSTANCE hinst)
{
    TCHAR modulePath[MAX_PATH + 1];
    DWORD length = 0;
    TCHAR key[256];


    wsprintf(key, TEXT("CLSID\\%s"), clsid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, TEXT("Socks5Server"))){
        return E_FAIL;
    }
    GetModuleFileName(NULL, modulePath, sizeof(modulePath)/sizeof(TCHAR));
    wsprintf(key, TEXT("CLSID\\%s\\LocalServer32"), clsid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, modulePath)){
        return E_FAIL;
    }

    wsprintf(key, TEXT("CLSID\\%s\\ProgID"), clsid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, (LPTSTR)progid)){
        return E_FAIL;
    }
    wsprintf(key, TEXT("%s"), progid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, TEXT("Socks5Server"))){
        return E_FAIL;
    }
    wsprintf(key, TEXT("%s\\CLSID"), progid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, (LPTSTR)clsid)){
        return E_FAIL;
    }

    wsprintf(key, TEXT("CLSID\\%s"), clsid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, TEXT("AppID"), (LPTSTR)appid)){
        return E_FAIL;
    }
    wsprintf(key, TEXT("AppID\\%s"), appid);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, NULL, TEXT("Socks5Server"))){
        return E_FAIL;
    }
    wsprintf(key, TEXT("AppID\\%s"), serverfilename);
    if(!CreateRegistryKey(HKEY_CLASSES_ROOT, key, TEXT("AppID"), (LPTSTR)appid)){
        return E_FAIL;
    }

    return S_OK;
}


HRESULT UnregisterServer()
{
    TCHAR key[256];


    wsprintf(key, TEXT("CLSID\\%s"), clsid);
    if(!RemoveRegistryKey(HKEY_CLASSES_ROOT, key)){
        return E_FAIL;
    }

    wsprintf(key, TEXT("%s"), progid);
    if(!RemoveRegistryKey(HKEY_CLASSES_ROOT, key)){
        return E_FAIL;
    }

    wsprintf(key, TEXT("AppID\\%s"), appid);
    if(!RemoveRegistryKey(HKEY_CLASSES_ROOT, key)){
        return E_FAIL;
    }

    wsprintf(key, TEXT("AppID\\%s"), serverfilename);
    if(!RemoveRegistryKey(HKEY_CLASSES_ROOT, key)){
        return E_FAIL;
    }

    return S_OK;
}


// WinMain
int WINAPI WinMain(HINSTANCE hinst, HINSTANCE hinstPrev, LPSTR lpszCmdLine, int nCmdShow)
{
    CSocks5ServerFactory factory;
    HRESULT hr;
    DWORD dwRegister = 0;
    MSG msg;


    if((lstrcmpA(lpszCmdLine, "-RegServer") == 0) || (lstrcmpA(lpszCmdLine, "/RegServer") == 0)){
        hr = RegisterServer(hinst);
        if(SUCCEEDED(hr)){
            MessageBox(NULL, "[I] RegisterServer:RegServer", "Socks5Server", MB_OK);
        }else{
            MessageBox(NULL, "[E] RegisterServer:RegServer error", "Socks5Server", MB_ICONERROR);
        }
        return 0;
    }else if((lstrcmpA(lpszCmdLine, "-UnregServer") == 0) || (lstrcmpA(lpszCmdLine, "/UnregServer") == 0)){
        hr = UnregisterServer();
        if(SUCCEEDED(hr)){
            MessageBox(NULL, "[I] UnregisterServer:UnregServer", "Socks5Server", MB_OK);
        }else{
            MessageBox(NULL, "[E] UnregisterServer:UnregServer error", "Socks5Server", MB_ICONERROR);
        }
        return 0;
    }else{
        g_hExitEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
        if(g_hExitEvent == NULL){
            return 1;
        }

        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if(FAILED(hr)){
            return 1;
        }

        hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_NONE, RPC_C_IMP_LEVEL_ANONYMOUS, NULL, EOAC_NONE, NULL);
        if(FAILED(hr)){
            return 1;
        }

        hr = CoRegisterClassObject(CLSID_Socks5Server, static_cast<IClassFactory *>(&factory), CLSCTX_LOCAL_SERVER|CLSCTX_REMOTE_SERVER, REGCLS_MULTIPLEUSE|REGCLS_SUSPENDED, &dwRegister);
        if(FAILED(hr)){
            CoUninitialize();
            return 1;
        }

        hr = CoResumeClassObjects();
        if(SUCCEEDED(hr)){
            WaitForSingleObject(g_hExitEvent, INFINITE);
        }

        hr = CoRevokeClassObject(dwRegister);
        CoUninitialize();
        CloseHandle(g_hExitEvent);
    }

    return 0;
}


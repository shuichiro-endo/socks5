/*
 * Title:  socks5 server header (Linux static)
 * Author: Shuichiro Endo
 */

void printBytes(unsigned char *input, int input_length);
char hexcharToInt(char c);
int hexstringToArray(char *hexstring, int hexstringLength, unsigned char *output, int outputSize);
void xor(unsigned char *buffer, int length, unsigned char *key, int keyLength);
int recvData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int recvDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendData(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int sendDataXor(int sock, void *buffer, int length, long tv_sec, long tv_usec);
int forwarder(int clientSock, int targetSock, long tv_sec, long tv_usec);
int forwarderXor(int clientSock, int targetSock, long tv_sec, long tv_usec);
int sendSocksResponseIpv4(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv4Xor(int sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6(int clientSock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
int sendSocksResponseIpv6Xor(int sock, char ver, char req, char rsv, char atyp, long tv_sec, long tv_usec);
char *getIpv6AddrString(const char *addr);
char *getIpv6InterfaceName(const char *addr);
uint32_t getIpv6ScopeId(const char *addr);
void addrinfoCallback(void *arg, int status, int timeouts, struct ares_addrinfo *result);
int getAddrInfo(const char *domainname, const char *service, int ai_family, struct sockaddr_in *addr, struct sockaddr_in6 *addr6);
int worker(void *ptr);
void usage(char *filename);

typedef struct {
	int clientSock;
	long tv_sec;		// recv send
	long tv_usec;		// recv send
	long forwarder_tv_sec;
	long forwarder_tv_usec;
} PARAM, *pPARAM;

typedef struct {
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	int ret;
} addrinfoCallbackArg, *pAddrinfoCallbackArg;

typedef struct
{
	char ver;
	char ulen;
	char uname;
	// variable
} USERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP, *pUSERNAME_PASSWORD_AUTHENTICATION_REQUEST_TMP;


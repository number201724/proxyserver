#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifndef _WIN32
#include <alloca.h>
#endif
#include <assert.h>

#include <vector>
#include <list>
#include <unordered_map>
#include "protocol.h"
#ifndef _WIN32
#include <unistd.h>
#endif
#include <algorithm>
#include <thread>
#include <mutex>

#include "salsa20.h"
#include <openssl/sha.h>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>
typedef SOCKET sock_t;
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
typedef int sock_t;
#endif

#include "MessageIdentifiers.h"
#include "RakPeerInterface.h"
#include "RakNetStatistics.h"
#include "RakNetTypes.h"
#include "BitStream.h"
#include "RakSleep.h"
#include "PacketLogger.h"
#include "SignaledEvent.h"

#include <uv.h>

struct domainaddr
{
    char domain[256];
    uint16_t port;
};

typedef union {
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    struct domainaddr domain;
} socks5_addr;
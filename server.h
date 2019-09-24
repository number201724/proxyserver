#ifndef _SERVER_H_
#define _SERVER_H_

#define SOCKS5_CONN_STAGE_EXMETHOD 0
#define SOCKS5_CONN_STAGE_EXHOST 1
#define SOCKS5_CONN_STAGE_CONNECTING 2
#define SOCKS5_CONN_STAGE_CONNECTED 3
#define SOCKS5_CONN_STAGE_STREAM 4
#define SOCKS5_CONN_STAGE_CLOSING 5
#define SOCKS5_CONN_STAGE_CLOSED 6

#define BLOCK_SIZE 262144

// 如果禁用ACK则UDP性能最高
// 但是在下载数据的时候会导致服务器的内存爆涨
// #define DISABLE_ACK

class ReferneceObject
{
public:
    ReferneceObject()
    {
        _refcnt = 1;
    }
    virtual ~ReferneceObject() {}
    virtual int64_t AddRef()
    {
#ifdef _WIN32
		return InterlockedIncrement64(&_refcnt);
#else
        return __sync_add_and_fetch(&_refcnt, 1);
#endif
    }

    virtual int64_t Release()
    {
#ifdef _WIN32
		int64_t refcnt = InterlockedDecrement64(&_refcnt);
#else
        int64_t refcnt = __sync_sub_and_fetch(&_refcnt, 1);
#endif
        if (refcnt == 0)
        {
            delete this;
        }

        return refcnt;
    }

public:
    int64_t _refcnt;
};

class TcpClose;
class TcpReader;
class ProxyClient;

class Tcp : public ReferneceObject
{
private:
    virtual ~Tcp();

public:
    Tcp(uint64_t g, ProxyClient *_proxyclient);

    int stage;
    uint64_t guid;

    unsigned char remote_addrtype;
    socks5_addr remote_addr;
    unsigned char bnd_addrtype;
    socks5_addr bnd_addr;

    uv_tcp_t sock;
    uv_getaddrinfo_t getaddrinfo;

    TcpClose *close;
    TcpReader *reader;
    ProxyClient *proxyclient;
    bool remote_close;
    uint32_t ack;

public:
    void Send(void *data, size_t len);
};

class TcpShutdown
{
public:
    TcpShutdown(Tcp *_tcp);
    ~TcpShutdown();

    static void shutdown_cb(uv_shutdown_t *req, int status);
    static void shutdown(Tcp *tcp);

    Tcp *tcp;
    uv_shutdown_t req;
};

class TcpClose
{
public:
    TcpClose(Tcp *_tcp) : tcp(_tcp)
    {
        tcp->AddRef();
    }

    ~TcpClose()
    {
        tcp->Release();
    }

    static void close_cb(uv_handle_t *handle);
    static void close(Tcp *handle);
    Tcp *tcp;
};

class TcpReader
{
public:
    TcpReader(Tcp *_tcp);
    ~TcpReader();

    static int begin_read(Tcp *_tcp);
    void pause();
    void resume();

    static void alloc_cb(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf);
    static void read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf);

    Tcp *tcp;
    char buf[BLOCK_SIZE];
    bool reading;
};

class TcpWriter
{
public:
    TcpWriter(Tcp *_tcp, void *data, size_t len);
    ~TcpWriter();

    static void write(Tcp *_tcp, void *data, size_t len);
    static void write_cb(uv_write_t *req, int status);
    Tcp *tcp;
    uv_write_t request;
    uv_buf_t buf;
};

class TcpConnect
{
public:
    TcpConnect(Tcp *_tcp) : tcp(_tcp)
    {
        _tcp->AddRef();
        _connect.data = this;
    }

    ~TcpConnect()
    {
        tcp->Release();
    }

    static int connect(Tcp *_tcp, struct sockaddr *addr);

    uv_connect_t _connect;
    Tcp *tcp;

    static void connect_cb(uv_connect_t *req, int status);
};

class AsyncGetAddrInfo
{
public:
    AsyncGetAddrInfo(Tcp *_tcp) : tcp(_tcp)
    {
        tcp->AddRef();
        _getaddrinfo.data = this;
    }

    ~AsyncGetAddrInfo()
    {
        tcp->Release();
    }

    static int getaddrinfo(Tcp *tcp, const char *node, const char *service, const struct addrinfo *hints);
    Tcp *tcp;
    uv_getaddrinfo_t _getaddrinfo;

    static void getaddrinfo_cb(uv_getaddrinfo_t *req,
                               int status,
                               struct addrinfo *res);
};

class ProxyClient : public ReferneceObject
{
public:
    ProxyClient(uint64_t g);
    ~ProxyClient();

    void AddTcp(Tcp *tcp);
    bool InitTcp(Tcp *tcp, unsigned char addrtype, const socks5_addr &addr);
    void CloseTcp(Tcp *tcp);
    bool FindTcp(uint64_t guid, Tcp *&tcp);
    uint64_t guid;

    std::unordered_map<uint64_t, Tcp *> _tcp_connection_map;
};

class ProxyServer
{
public:
    ProxyServer();
    ~ProxyServer();

    void SetupKey(const char *str_password);

    ProxyClient *AddClient(uint64_t guid);
    void RemoveClient(uint64_t guid);
    bool FindClient(uint64_t guid, ProxyClient *&client);

    void ReadClientMessage(RakNet::Packet *packet);
    void ReadAckMessage(RakNet::Packet *packet);

    void SendConnectResult(ProxyClient *client, uint64_t clientguid, unsigned char rep, unsigned char addrtype, socks5_addr *addr);
#ifdef DISABLE_ACK
    uint32_t SendStreamData(ProxyClient *client, Tcp *tcp, void *data, size_t length, PacketReliability reliability = RELIABLE_ORDERED, PacketPriority priority = MEDIUM_PRIORITY);
    void Send(ProxyClient *client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability = RELIABLE_ORDERED, PacketPriority priority = MEDIUM_PRIORITY);
#else
    uint32_t SendStreamData(ProxyClient *client, Tcp *tcp, void *data, size_t length, PacketReliability reliability = RELIABLE_ORDERED_WITH_ACK_RECEIPT, PacketPriority priority = MEDIUM_PRIORITY);
    void Send(ProxyClient *client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability = RELIABLE_ORDERED_WITH_ACK_RECEIPT, PacketPriority priority = MEDIUM_PRIORITY);
#endif
    void SencClose(ProxyClient *client, uint64_t clientguid);

private:
    unsigned char password[32];
    std::unordered_map<uint64_t, ProxyClient *> _client_instance_map;
};

extern ProxyServer *proxyServer;

#endif
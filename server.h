#ifndef _SERVER_H_
#define _SERVER_H_

#define SOCKS5_CONN_STAGE_EXMETHOD 0
#define SOCKS5_CONN_STAGE_EXHOST 1
#define SOCKS5_CONN_STAGE_CONNECTING 2
#define SOCKS5_CONN_STAGE_CONNECTED 3
#define SOCKS5_CONN_STAGE_STREAM 4
#define SOCKS5_CONN_STAGE_CLOSING 5
#define SOCKS5_CONN_STAGE_CLOSED 6

class ProxyClient;
class Tcp;

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
        return __sync_add_and_fetch(&_refcnt, 1);
    }

    virtual int64_t Release()
    {
        int64_t refcnt = __sync_sub_and_fetch(&_refcnt, 1);

        if (refcnt == 0)
        {
            delete this;
        }

        return refcnt;
    }

private:
    int64_t _refcnt;
};

class CloseRequest
{
public:
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

    static void alloc_cb(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf);
    static void read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf);

    Tcp *tcp;
    char buf[0x10000];
};

class WriteRequest
{
public:
    WriteRequest(Tcp *_tcp, void *data, size_t len);
    ~WriteRequest();

    static void write(Tcp *_tcp, void *data, size_t len);
    static void write_cb(uv_write_t *req, int status);
    Tcp *tcp;
    uv_write_t request;
    uv_buf_t buf;
};

class Tcp : public ReferneceObject
{
private:
    virtual ~Tcp();

public:
    Tcp(uint64_t g);

    int stage;
    uint64_t guid;

    unsigned char remote_addrtype;
    socks5_addr remote_addr;
    unsigned char bnd_addrtype;
    socks5_addr bnd_addr;

    uv_tcp_t sock;
    uv_getaddrinfo_t getaddrinfo;

    CloseRequest *close;
    TcpReader *reader;
    ProxyClient *proxyclient;

    int64_t sequence;

public:
    void Send(void *data, size_t len);
};

class GetAddrInfoRequest
{
public:
    Tcp *_tcp;
    uv_getaddrinfo_t getaddrinfo;

    static void getaddrinfo_cb(uv_getaddrinfo_t *req,
                               int status,
                               struct addrinfo *res);
};

class ConnectRequest
{
public:
    uv_connect_t _connect;
    Tcp *_tcp;

    static void connect_cb(uv_connect_t *req, int status);
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

    void SendConnectResult(ProxyClient *client, uint64_t clientguid, unsigned char rep, unsigned char addrtype, socks5_addr *addr);
    void Send(ProxyClient *client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability = RELIABLE_ORDERED, PacketPriority priority = MEDIUM_PRIORITY);
    void SencClose(ProxyClient *client, uint64_t clientguid);

private:
    unsigned char password[32];
    std::unordered_map<uint64_t, ProxyClient *> _client_instance_map;
};

extern ProxyServer *proxyServer;

#endif
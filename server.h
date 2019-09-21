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

class CloseRequest
{
public:
    static void close_cb(uv_handle_t *handle);
    static void close(std::shared_ptr<Tcp> &handle);
    std::shared_ptr<Tcp> tcp;
};

class TcpReader
{
public:
    TcpReader(std::shared_ptr<Tcp> &_tcp);
    ~TcpReader();
   
    static int begin_read(std::shared_ptr<Tcp> &_tcp);

    static void alloc_cb(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf);
    static void read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf);

     std::shared_ptr<Tcp> tcp;
    char buf[0x10000];
};

class WriteRequest
{
public:
    WriteRequest(std::shared_ptr<Tcp> &_tcp, void *data, size_t len);
    ~WriteRequest();


    static void write(std::shared_ptr<Tcp> &_tcp, void *data, size_t len);
    static void write_cb(uv_write_t* req, int status);
    std::shared_ptr<Tcp> tcp;
    uv_write_t request;
    uv_buf_t buf;
};

class Tcp
{
public:
    Tcp(uint64_t g);
    ~Tcp();

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

    std::shared_ptr<ProxyClient> proxyclient;
};

class GetAddrInfoRequest
{
public:
    std::shared_ptr<Tcp> _tcp;
    uv_getaddrinfo_t getaddrinfo;

    static void getaddrinfo_cb(uv_getaddrinfo_t *req,
                               int status,
                               struct addrinfo *res);
};

class ConnectRequest
{
public:
    uv_connect_t _connect;
    std::shared_ptr<Tcp> _tcp;

    static void connect_cb(uv_connect_t *req, int status);
};

class ProxyClient
{
public:
    ProxyClient(uint64_t g);
    ~ProxyClient();

    void AddTcp(std::shared_ptr<Tcp> &tcp);
    bool InitTcp(std::shared_ptr<Tcp> &tcp, unsigned char addrtype, const socks5_addr &addr);
    void CloseTcp(std::shared_ptr<Tcp> &tcp);
    bool FindTcp(uint64_t guid, std::shared_ptr<Tcp> &tcp);
    void Lock();
    void Unlock();

    uint64_t guid;

    std::unordered_map<uint64_t, std::shared_ptr<Tcp>> _tcp_connection_map;

private:
    std::mutex _lock;
};

class ProxyServer
{
public:
    ProxyServer();
    ~ProxyServer();

    void SetupKey(const char *str_password);

    std::shared_ptr<ProxyClient> AddClient(uint64_t guid);
    void RemoveClient(uint64_t guid);
    bool FindClient(uint64_t guid, std::shared_ptr<ProxyClient> &client);

    void ReadClientMessage(RakNet::Packet *packet);

    void SendConnectResult(std::shared_ptr<ProxyClient> &client, uint64_t clientguid, unsigned char rep, unsigned char addrtype, socks5_addr *addr);
    void Send(std::shared_ptr<ProxyClient> &client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability = RELIABLE_ORDERED, PacketPriority priority = MEDIUM_PRIORITY);
    void SencClose(std::shared_ptr<ProxyClient> &client,uint64_t clientguid);
    void Lock();
    void Unlock();

private:
    unsigned char password[32];
    std::mutex _lock;
    std::unordered_map<uint64_t, std::shared_ptr<ProxyClient>> _client_instance_map;
};

extern ProxyServer *proxyServer;

#endif
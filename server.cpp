#include "defs.h"
#include "server.h"

static ProxyServer s_ProxyServer;
ProxyServer *proxyServer = &s_ProxyServer;

extern RakNet::RakPeerInterface *rakPeer;
uint64_t tcp_usecount = 0;
std::mutex g_lock;

static uint32_t crc32_tab[] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
    0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
    0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
    0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
    0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
    0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
    0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
    0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
    0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
    0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
    0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
    0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
    0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
    0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
    0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
    0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
    0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
    0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
    0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
    0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
    0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
    0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d};

uint32_t
crc32(uint32_t crc, const void *buf, uint32_t size)
{
    const uint8_t *p;

    p = (const uint8_t *)buf;
    crc = crc ^ ~0U;

    while (size--)
        crc = crc32_tab[(crc ^ *p++) & 0xFF] ^ (crc >> 8);

    return crc ^ ~0U;
}

void dump_bytes(void *data, size_t len)
{
    unsigned char *buf = (unsigned char *)data;
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }

    printf("\n");
}

class TcpSocketReader
{
public:
    TcpSocketReader();
    ~TcpSocketReader();
};

TcpReader::TcpReader(Tcp *_tcp) : tcp(_tcp)
{
    _tcp->AddRef();
}

TcpReader::~TcpReader()
{
    tcp->Release();
}

int TcpReader::begin_read(Tcp *_tcp)
{
    TcpReader *tcpreader = new TcpReader(_tcp);
    _tcp->reader = tcpreader;
    return uv_read_start((uv_stream_t *)&_tcp->sock, TcpReader::alloc_cb, TcpReader::read_cb);
}

void TcpReader::alloc_cb(uv_handle_t *handle,
                         size_t suggested_size,
                         uv_buf_t *buf)
{
    Tcp *tcp = (Tcp *)handle->data;
    buf->base = tcp->reader->buf;
    buf->len = sizeof(tcp->reader->buf);
}
void TcpReader::read_cb(uv_stream_t *stream,
                        ssize_t nread,
                        const uv_buf_t *buf)
{
    Tcp *tcp = (Tcp *)stream->data;
    auto reader = tcp->reader;

    if (nread == UV_EOF)
    {
        uv_read_stop(stream);
        CloseRequest::close(reader->tcp);
        tcp->reader = nullptr;
        delete reader;
        return;
    }

    if (nread < 0)
    {
        uv_read_stop(stream);
        CloseRequest::close(reader->tcp);
        tcp->reader = nullptr;
        delete reader;
        return;
    }

    RakNet::BitStream serializer;
    serializer.Write((unsigned char)ID_A2A_TCP_STREAM);
    serializer.Write(tcp->guid);
    serializer.Write(tcp->sequence);
    uint32_t crc = crc32(0, buf->base, nread);
    serializer.Write(crc);

    serializer.Write(buf->base, nread);

    printf("send packet:%lu     %lu    len:%lu  crc32:%08x\n", tcp->guid, tcp->sequence, nread, crc);
    tcp->sequence++;
    proxyServer->Send(tcp->proxyclient, tcp->guid, serializer);
}

WriteRequest::WriteRequest(Tcp *_tcp, void *data, size_t len) : tcp(_tcp)
{
    buf.base = new char[len];
    buf.len = len;

    memcpy(buf.base, data, len);
    tcp->AddRef();
}

WriteRequest::~WriteRequest()
{
    if (buf.base)
    {
        delete[] buf.base;
    }

    tcp->Release();
}

void WriteRequest::write_cb(uv_write_t *req, int status)
{
    WriteRequest *request = (WriteRequest *)req->data;

    delete request;
}

void WriteRequest::write(Tcp *_tcp, void *data, size_t len)
{
    if (_tcp->stage == SOCKS5_CONN_STAGE_STREAM)
    {
        if (!uv_is_writable((uv_stream_t *)&_tcp->sock))
        {
            printf("can't write but write\n");
        }

        WriteRequest *request = new WriteRequest(_tcp, data, len);
        request->request.data = request;

        int code = uv_write(&request->request, (uv_stream_t *)&_tcp->sock, &request->buf, 1, write_cb);
        if (code != 0)
        {
            printf("write fail:%d\n", code);
            delete request;
        }
    }
}

Tcp::Tcp(uint64_t g)
{
    sequence = 0;
    close = nullptr;
    guid = g;
    stage = SOCKS5_CONN_STAGE_EXMETHOD;
    reader = nullptr;
    g_lock.lock();
    tcp_usecount++;
    g_lock.unlock();
}

Tcp::~Tcp()
{
    g_lock.lock();
    tcp_usecount--;
    g_lock.unlock();
    printf("Tcp::~Tcp()   guid:%lu\n", guid);
}

void CloseRequest::close_cb(uv_handle_t *handle)
{
    CloseRequest *close = nullptr;
    Tcp *tcp = (Tcp *)handle->data;
    close = tcp->close;
    tcp->close = nullptr;
    tcp->stage = SOCKS5_CONN_STAGE_CLOSED;

    if (tcp->reader)
    {
        delete tcp->reader;
        tcp->reader = nullptr;
    }

    if (tcp->proxyclient)
    {
        proxyServer->SencClose(tcp->proxyclient, tcp->guid);
        tcp->proxyclient->CloseTcp(tcp);
        tcp->proxyclient->Release();
        tcp->proxyclient = nullptr;
    }

    tcp->Release();
    delete close;
}

void CloseRequest::close(Tcp *handle)
{
    if (handle->stage < SOCKS5_CONN_STAGE_CLOSING)
    {
        handle->stage = SOCKS5_CONN_STAGE_CLOSING;
        handle->close = new CloseRequest();
        handle->close->tcp = handle;
        handle->AddRef();

        uv_close((uv_handle_t *)&handle->sock, close_cb);
    }
}

void ConnectRequest::connect_cb(uv_connect_t *req, int status)
{
    ConnectRequest *connect_request = (ConnectRequest *)req->data;

    if (status == UV_ECANCELED)
    {
        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_SERVER_FAILURE,
                                       connect_request->_tcp->remote_addrtype,
                                       &connect_request->_tcp->remote_addr);
        CloseRequest::close(connect_request->_tcp);
        connect_request->_tcp->Release();
        delete connect_request;
        return;
    }

    if (status == 0)
    {
        struct sockaddr_storage sockaddr = {0};
        int sockaddrlen = sizeof(sockaddr);
        connect_request->_tcp->stage = SOCKS5_CONN_STAGE_CONNECTED;
        uv_tcp_getsockname(&connect_request->_tcp->sock, (struct sockaddr *)&sockaddr, &sockaddrlen);

        if (sockaddr.ss_family == AF_INET)
        {
            connect_request->_tcp->bnd_addrtype = SOCKS5_ADDRTYPE_IPV4;
            connect_request->_tcp->bnd_addr.v4 = *(sockaddr_in *)&sockaddr;
        }
        else if (sockaddr.ss_family == AF_INET6)
        {
            connect_request->_tcp->bnd_addrtype = SOCKS5_ADDRTYPE_IPV6;
            connect_request->_tcp->bnd_addr.v6 = *(sockaddr_in6 *)&sockaddr;
        }

        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_SUCCESS,
                                       connect_request->_tcp->bnd_addrtype,
                                       &connect_request->_tcp->bnd_addr);

        //printf("SOCKS5_CONN_STAGE_CONNECTED\n");

        auto &tcp = connect_request->_tcp;
        if (TcpReader::begin_read(tcp) != 0)
        {
            CloseRequest::close(connect_request->_tcp);
        }
        else
        {
            tcp->stage = SOCKS5_CONN_STAGE_STREAM;
        }

        connect_request->_tcp->Release();
        delete connect_request;
        return;
    }

    if (status == UV_ENETUNREACH)
    {
        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_NETWORK_UNREACHABLE,
                                       connect_request->_tcp->remote_addrtype,
                                       &connect_request->_tcp->remote_addr);
    }
    else if (status == UV_EHOSTUNREACH)
    {
        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_HOST_UNREACHABLE,
                                       connect_request->_tcp->remote_addrtype,
                                       &connect_request->_tcp->remote_addr);
    }
    else if (status == UV_ECONNREFUSED)
    {
        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_CONNECTION_REFUSED,
                                       connect_request->_tcp->remote_addrtype,
                                       &connect_request->_tcp->remote_addr);
    }
    else
    {
        proxyServer->SendConnectResult(connect_request->_tcp->proxyclient,
                                       connect_request->_tcp->guid,
                                       SOCKS5_RESPONSE_TTL_EXPIRED,
                                       connect_request->_tcp->remote_addrtype,
                                       &connect_request->_tcp->remote_addr);
    }

    //printf("SOCKS5_CONN_STAGE_CLOSING\n");

    CloseRequest::close(connect_request->_tcp);
    connect_request->_tcp->Release();
    delete connect_request;
}

void GetAddrInfoRequest::getaddrinfo_cb(uv_getaddrinfo_t *req,
                                        int status,
                                        struct addrinfo *res)
{
    GetAddrInfoRequest *getaddrinfo_request = (GetAddrInfoRequest *)req->data;

    if (status == UV_ECANCELED)
    {
        if (res)
        {
            uv_freeaddrinfo(res);
        }

        CloseRequest::close(getaddrinfo_request->_tcp);
        getaddrinfo_request->_tcp->Release();
        delete getaddrinfo_request;
        return;
    }

    auto &tcp = getaddrinfo_request->_tcp;
    for (auto p = res; p != NULL; p = p->ai_next)
    {
        tcp->stage = SOCKS5_CONN_STAGE_CONNECTING;

        ConnectRequest *connect_request = new ConnectRequest();
        connect_request->_tcp = tcp;
        connect_request->_connect.data = connect_request;
        tcp->AddRef();

        int code = uv_tcp_connect(&connect_request->_connect, &tcp->sock, p->ai_addr, ConnectRequest::connect_cb);
        if (code != 0)
        {
            printf("uv_tcp_connect failed code:%d\n", code);
            CloseRequest::close(getaddrinfo_request->_tcp);
            tcp->Release();
            delete connect_request;
        }

        //printf("SOCKS5_CONN_STAGE_CONNECTING\n");
        break;
    }

    uv_freeaddrinfo(res);
    tcp->Release();
    delete getaddrinfo_request;
}

ProxyClient::ProxyClient(uint64_t g) : guid(g)
{
}

ProxyClient::~ProxyClient()
{
    printf("ProxyClient::~ProxyClient\n");
}

void ProxyClient::AddTcp(Tcp *tcp)
{
    _tcp_connection_map[tcp->guid] = tcp;
}

bool ProxyClient::InitTcp(Tcp *tcp, unsigned char addrtype, const socks5_addr &addr)
{
    tcp->remote_addrtype = addrtype;
    tcp->remote_addr = addr;

    tcp->sock.data = tcp;
    //printf("tcp->sock.data:%p\n", tcp->sock.data);
    int code = uv_tcp_init(uv_default_loop(), &tcp->sock);
    if (code != 0)
    {
        printf("uv_tcp_init failed.\n");
        exit(EXIT_FAILURE);
    }

    if (addrtype == SOCKS5_ADDRTYPE_IPV4 || addrtype == SOCKS5_ADDRTYPE_IPV6)
    {
        struct sockaddr *paddr = NULL;
        struct sockaddr_in addr4 = addr.v4;
        struct sockaddr_in6 addr6 = addr.v6;
        addr6.sin6_family = AF_INET6;
        addr4.sin_family = AF_INET;

        if (addrtype == SOCKS5_ADDRTYPE_IPV4)
        {
            paddr = (struct sockaddr *)&addr4;
        }
        else
        {
            paddr = (struct sockaddr *)&addr6;
        }

        tcp->stage = SOCKS5_CONN_STAGE_CONNECTING;

        ConnectRequest *connect_request = new ConnectRequest();
        connect_request->_tcp = tcp;
        connect_request->_connect.data = connect_request;
        tcp->AddRef();

        int code = uv_tcp_connect(&connect_request->_connect, &tcp->sock, paddr, ConnectRequest::connect_cb);
        if (code != 0)
        {
            printf("uv_tcp_connect failed code:%d\n", code);
            delete connect_request;
            CloseRequest::close(tcp);
            tcp->Release();
            return false;
        }

        //printf("SOCKS5_CONN_STAGE_CONNECTING\n");
    }
    else if (addrtype == SOCKS5_ADDRTYPE_DOMAIN)
    {
        struct addrinfo hints;
        char service[10];
        sprintf(service, "%d", htons(addr.domain.port));

        tcp->stage = SOCKS5_CONN_STAGE_EXHOST;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_flags = AI_PASSIVE;
        hints.ai_protocol = 0;
        hints.ai_socktype = 0;

        GetAddrInfoRequest *getaddrinfo_request = new GetAddrInfoRequest();
        getaddrinfo_request->getaddrinfo.data = getaddrinfo_request;
        getaddrinfo_request->_tcp = tcp;
        tcp->AddRef();

        int code = uv_getaddrinfo(uv_default_loop(), &getaddrinfo_request->getaddrinfo, GetAddrInfoRequest::getaddrinfo_cb, addr.domain.domain, service, &hints);
        if (code != 0)
        {
            printf("uv_getaddrinfo failed code:%d\n", code);
            delete getaddrinfo_request;
            CloseRequest::close(tcp);
            tcp->Release();
            return false;
        }

        //printf("SOCKS5_CONN_STAGE_EXHOST\n");
    }

    return true;
}

void ProxyClient::CloseTcp(Tcp *tcp)
{
    auto iterator = _tcp_connection_map.find(tcp->guid);

    if (iterator != _tcp_connection_map.end())
    {
        _tcp_connection_map.erase(iterator);
        tcp->Release();
    }
}

bool ProxyClient::FindTcp(uint64_t guid, Tcp *&tcp)
{
    auto iterator = _tcp_connection_map.find(guid);

    tcp = nullptr;

    if (iterator != _tcp_connection_map.end())
    {
        tcp = iterator->second;
        return true;
    }

    return false;
}

ProxyServer::ProxyServer()
{
}

ProxyServer::~ProxyServer()
{
}

void ProxyServer::SetupKey(const char *str_password)
{
    SHA256_CTX sha256;
    int len = strlen(str_password);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str_password, len);
    SHA256_Final(password, &sha256);
    printf("password:");
    dump_bytes(password, 32);
}

ProxyClient *ProxyServer::AddClient(uint64_t guid)
{
    ProxyClient *client = new ProxyClient(guid);
    _client_instance_map[guid] = client;
    return client;
}

void ProxyServer::RemoveClient(uint64_t guid)
{
    ProxyClient *client = nullptr;
    auto iterator = _client_instance_map.find(guid);
    if (iterator != _client_instance_map.end())
    {
        client = iterator->second;
        _client_instance_map.erase(iterator);
    }

    if (client)
    {
        for (auto iterator = client->_tcp_connection_map.begin(); iterator != client->_tcp_connection_map.end(); iterator++)
        {
            printf("lost %lu  stage:%d\n", iterator->second->guid, iterator->second->stage);
            CloseRequest::close(iterator->second);
        }
        client->Release();
    }
}
bool ProxyServer::FindClient(uint64_t guid, ProxyClient *&client)
{
    bool f = false;

    client = nullptr;
    auto iterator = _client_instance_map.find(guid);
    if (iterator != _client_instance_map.end())
    {
        client = iterator->second;
        f = true;
    }

    return f;
}

unsigned char GetPacketIdentifier(RakNet::Packet *p);
unsigned char *GetPacketData(RakNet::Packet *p);
size_t GetPacketLength(RakNet::Packet *p);

void ProxyServer::ReadClientMessage(RakNet::Packet *packet)
{
    ProxyClient *client;
    unsigned char *data;
    size_t length;
    unsigned char nonce[8];
    uint64_t guid;
    unsigned char identifier;

    data = GetPacketData(packet);
    length = GetPacketLength(packet);

    RakNet::BitStream reader(data, length, false);

    reader.IgnoreBytes(sizeof(unsigned char));
    if (!reader.Read((char *)nonce, 8))
        return;

    unsigned char *encrypted_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
    size_t encrypted_length = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

    s20_crypt(password, S20_KEYLEN_256, nonce, 0, encrypted_data, encrypted_length);

    //dump_bytes(encrypted_data, encrypted_length);
    if (!reader.Read(identifier) || !reader.Read(guid))
    {
        printf("cant read id\n");
        return;
    }

    // printf("identifier:%d\n", identifier);
    // printf("guid:%lu\n", guid);

    if (!FindClient(packet->guid.g, client))
    {
        printf("not found client guid:%lu\n", guid);
        return;
    }

    if (identifier == ID_C2S_TCP_CONNECT)
    {
        unsigned char remote_addrtype;
        socks5_addr addr;

        bool begin_connect = false;

        if (!reader.Read(remote_addrtype))
        {
            return;
        }

        if (remote_addrtype == SOCKS5_ADDRTYPE_IPV4)
        {
            if (reader.Read(addr.v4.sin_addr) && reader.Read(addr.v4.sin_port))
            {
                begin_connect = true;
                //printf("SOCKS5_ADDRTYPE_IPV4:%s:%d\n", inet_ntoa(addr.v4.sin_addr), htons(addr.v4.sin_port));
            }
            else
            {
                SendConnectResult(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else if (remote_addrtype == SOCKS5_ADDRTYPE_IPV6)
        {
            if (reader.Read(addr.v6.sin6_addr) && reader.Read(addr.v6.sin6_port))
            {
                begin_connect = true;
            }
            else
            {
                SendConnectResult(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else if (remote_addrtype == SOCKS5_ADDRTYPE_DOMAIN)
        {
            RakNet::RakString domain;

            if (reader.Read(domain) && reader.Read(addr.domain.port))
            {
                strncpy(addr.domain.domain, domain.C_String(), 255);
                addr.domain.domain[255] = 0;
                begin_connect = true;
                //printf("SOCKS5_ADDRTYPE_DOMAIN:%s:%d\n", domain.C_String(), htons(addr.domain.port));
            }
            else
            {
                SendConnectResult(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else
        {
            SendConnectResult(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
        }

        if (begin_connect)
        {
            Tcp *tcp = new Tcp(guid);
            if (tcp == NULL)
            {
                printf("create Tcp failed\n");
                exit(EXIT_FAILURE);
            }

            tcp->proxyclient = client;

            client->AddTcp(tcp);

            if (client->InitTcp(tcp, remote_addrtype, addr))
            {
                client->AddRef();
            }
            else
            {
                client->CloseTcp(tcp);
            }
        }
        return;
    }

    if (identifier == ID_A2A_TCP_STREAM)
    {
        Tcp *tcp = nullptr;
        if (client->FindTcp(guid, tcp))
        {
            int64_t sequence;
            uint32_t crc;
            reader.Read(sequence);
            reader.Read(crc);

            unsigned char *stream_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
            size_t stream_len = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

            uint32_t crc2 = crc32(0, stream_data, stream_len);
            printf("recv packet:%lu  sequence:%lu   size:%u   %08X  %08X\n", client->guid, sequence, encrypted_length, crc, crc2);
            WriteRequest::write(tcp, stream_data, stream_len);
        }
        return;
    }

    if (identifier == ID_A2A_TCP_CLOSE)
    {
        printf("ID_A2A_TCP_CLOSE %lu\n", guid);
        Tcp *tcp;
        if (client->FindTcp(guid, tcp))
        {
            printf("success close %lu\n", guid);
            CloseRequest::close(tcp);
        }
        return;
    }
}

void ProxyServer::SendConnectResult(ProxyClient *client, uint64_t guid, unsigned char rep, unsigned char addrtype, socks5_addr *addr)
{
    RakNet::BitStream serializer;
    serializer.Write((unsigned char)ID_S2C_TCP_CONNECT);
    serializer.Write(guid);
    serializer.Write(rep);
    serializer.Write(addrtype);

    if (addrtype == SOCKS5_ADDRTYPE_IPV4)
    {
        printf("guid %lu SOCKS5_ADDRTYPE_IPV4:%d\n", guid, rep);
        serializer.Write(addr->v4.sin_addr);
        serializer.Write(addr->v4.sin_port);
    }
    if (addrtype == SOCKS5_ADDRTYPE_IPV6)
    {
        printf("guid %lu SOCKS5_ADDRTYPE_IPV6:%d\n", guid, rep);
        serializer.Write(addr->v6.sin6_addr);
        serializer.Write(addr->v6.sin6_port);
    }
    if (addrtype == SOCKS5_ADDRTYPE_DOMAIN)
    {
        printf("guid %lu SOCKS5_ADDRTYPE_DOMAIN:%d\n", guid, rep);
        serializer.Write(addr->domain.domain);
        serializer.Write(addr->domain.port);
    }

    Send(client, guid, serializer, RELIABLE_ORDERED, IMMEDIATE_PRIORITY);
}

void ProxyServer::SencClose(ProxyClient *client, uint64_t clientguid)
{
    RakNet::BitStream serializer;
    serializer.Write((unsigned char)ID_A2A_TCP_CLOSE);
    serializer.Write(clientguid);

    Send(client, clientguid, serializer);
}

void ProxyServer::Send(ProxyClient *client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability, PacketPriority priority)
{
    RakNet::BitStream encrypted_packet;

    uint8_t nonce[8];

    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();

    dump_bytes(nonce, 8);
    s20_crypt(password, S20_KEYLEN_256, nonce, 0, packet.GetData(), packet.GetNumberOfBytesUsed());

    encrypted_packet.Write((unsigned char)ID_USER_PACKET_ENUM);
    encrypted_packet.Write((char *)&nonce, 8);
    encrypted_packet.Write(packet);

    char orderingChannel = guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS

    printf("guid %lu send channel:%d\n", guid, orderingChannel);
    rakPeer->Send(&encrypted_packet, priority, reliability, orderingChannel, RakNet::RakNetGUID(client->guid), false);
}
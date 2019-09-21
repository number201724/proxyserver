#include "defs.h"
#include "server.h"

static ProxyServer s_ProxyServer;
ProxyServer *proxyServer = &s_ProxyServer;

extern RakNet::RakPeerInterface *rakPeer;

void dump_bytes(void *data, size_t len)
{
    unsigned char *buf = (unsigned char *)data;
    for (size_t i = 0; i < len; i++)
    {
        printf("%02X", buf[i]);
    }

    printf("\n");
}

TcpReader::TcpReader(std::shared_ptr<Tcp> &_tcp) :tcp(_tcp)
{
}

TcpReader::~TcpReader()
{
}

int TcpReader::begin_read(std::shared_ptr<Tcp> &_tcp)
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

    if (nread == 0)
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
    serializer.Write(buf->base, nread);

    printf("send %u bytes\n", nread);

    proxyServer->Send(tcp->proxyclient, tcp->guid, serializer);
}

WriteRequest::WriteRequest(std::shared_ptr<Tcp> &_tcp, void *data, size_t len) : tcp(_tcp)
{
    buf.base = new char[len];
    buf.len = len;

    memcpy(buf.base, data, len);
}

WriteRequest::~WriteRequest()
{
    if (buf.base)
    {
        delete[] buf.base;
    }
}

void WriteRequest::write_cb(uv_write_t *req, int status)
{
    WriteRequest *request = (WriteRequest *)req->data;

    printf("write_cb:%d\n", status);
    delete request;
}

void WriteRequest::write(std::shared_ptr<Tcp> &_tcp, void *data, size_t len)
{
    if (_tcp->stage == SOCKS5_CONN_STAGE_STREAM)
    {
        WriteRequest *request = new WriteRequest(_tcp, data, len);
        request->request.data = request;
        int code = uv_write(&request->request, (uv_stream_t *)&_tcp->sock, &request->buf, 1, write_cb);
        if (code != 0)
        {
            printf("write fail:%d\n", code);
        }
    }
}

Tcp::Tcp(uint64_t g)
{
    close = nullptr;
    guid = g;
    stage = SOCKS5_CONN_STAGE_EXMETHOD;
    reader = nullptr;
}

Tcp::~Tcp()
{
    printf("Tcp::~Tcp()   guid:%lu\n", guid);
}

void CloseRequest::close_cb(uv_handle_t *handle)
{
    Tcp *ptcp = (Tcp *)handle->data;
    //printf("close_cb ptcp:%p\n", ptcp);

    std::shared_ptr<Tcp> tcp = ptcp->close->tcp;
    delete tcp->close;
    tcp->close = nullptr;
    tcp->stage = SOCKS5_CONN_STAGE_CLOSED;
}

void CloseRequest::close(std::shared_ptr<Tcp> &handle)
{
    if (handle->stage != SOCKS5_CONN_STAGE_CLOSING && handle->stage != SOCKS5_CONN_STAGE_CLOSED)
    {
        handle->stage = SOCKS5_CONN_STAGE_CLOSING;
        handle->close = new CloseRequest();
        handle->close->tcp = handle;

        uv_close((uv_handle_t *)&handle->sock, close_cb);
    }
}

void ConnectRequest::connect_cb(uv_connect_t *req, int status)
{
    ConnectRequest *connect_request = (ConnectRequest *)req->data;

    if (status == UV_ECANCELED)
    {
        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_SERVER_FAILURE,
                                     connect_request->_tcp->remote_addrtype,
                                     &connect_request->_tcp->remote_addr);
        connect_request->_tcp->proxyclient->CloseTcp(connect_request->_tcp);
        CloseRequest::close(connect_request->_tcp);
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

        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_SUCCESS,
                                     connect_request->_tcp->bnd_addrtype,
                                     &connect_request->_tcp->bnd_addr);

        printf("SOCKS5_CONN_STAGE_CONNECTED\n");

        auto &tcp = connect_request->_tcp;
        if (TcpReader::begin_read(tcp) != 0)
        {
            CloseRequest::close(connect_request->_tcp);
        }
        else
        {

            tcp->stage = SOCKS5_CONN_STAGE_STREAM;
            printf("SOCKS5_CONN_STAGE_STREAM\n");
        }

        delete connect_request;
        return;
    }

    if (status == UV_ENETUNREACH)
    {
        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_NETWORK_UNREACHABLE,
                                     connect_request->_tcp->remote_addrtype,
                                     &connect_request->_tcp->remote_addr);
    }
    else if (status == UV_EHOSTUNREACH)
    {
        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_HOST_UNREACHABLE,
                                     connect_request->_tcp->remote_addrtype,
                                     &connect_request->_tcp->remote_addr);
    }
    else if (status == UV_ECONNREFUSED)
    {
        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_CONNECTION_REFUSED,
                                     connect_request->_tcp->remote_addrtype,
                                     &connect_request->_tcp->remote_addr);
    }
    else
    {
        proxyServer->ConnectResponse(connect_request->_tcp->proxyclient,
                                     connect_request->_tcp->guid,
                                     SOCKS5_RESPONSE_TTL_EXPIRED,
                                     connect_request->_tcp->remote_addrtype,
                                     &connect_request->_tcp->remote_addr);
    }

    printf("SOCKS5_CONN_STAGE_CLOSING\n");
    connect_request->_tcp->proxyclient->CloseTcp(connect_request->_tcp);

    CloseRequest::close(connect_request->_tcp);
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

        int code = uv_tcp_connect(&connect_request->_connect, &tcp->sock, p->ai_addr, ConnectRequest::connect_cb);
        if (code != 0)
        {
            printf("uv_tcp_connect failed code:%d\n", code);
            delete connect_request;
            CloseRequest::close(getaddrinfo_request->_tcp);
        }

        printf("SOCKS5_CONN_STAGE_CONNECTING\n");
        break;
    }

    uv_freeaddrinfo(res);
    delete getaddrinfo_request;
}

ProxyClient::ProxyClient(uint64_t g) : guid(g)
{
}

ProxyClient::~ProxyClient()
{
}

void ProxyClient::Lock()
{
    _lock.lock();
}

void ProxyClient::Unlock()
{
    _lock.unlock();
}

void ProxyClient::AddTcp(std::shared_ptr<Tcp> &tcp)
{
    Lock();
    _tcp_connection_map[tcp->guid] = tcp;
    Unlock();
}

bool ProxyClient::InitTcp(std::shared_ptr<Tcp> &tcp, unsigned char addrtype, const socks5_addr &addr)
{
    tcp->remote_addrtype = addrtype;
    tcp->remote_addr = addr;

    tcp->sock.data = tcp.get();
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

        int code = uv_tcp_connect(&connect_request->_connect, &tcp->sock, paddr, ConnectRequest::connect_cb);
        if (code != 0)
        {
            printf("uv_tcp_connect failed code:%d\n", code);
            delete connect_request;
            CloseRequest::close(tcp);
            return false;
        }

        printf("SOCKS5_CONN_STAGE_CONNECTING\n");
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
        int code = uv_getaddrinfo(uv_default_loop(), &getaddrinfo_request->getaddrinfo, GetAddrInfoRequest::getaddrinfo_cb, addr.domain.domain, service, &hints);
        if (code != 0)
        {
            printf("uv_getaddrinfo failed code:%d\n", code);
            delete getaddrinfo_request;
            CloseRequest::close(tcp);
            return false;
        }

        printf("SOCKS5_CONN_STAGE_EXHOST\n");
    }

    return true;
}

void ProxyClient::CloseTcp(std::shared_ptr<Tcp> &tcp)
{
    tcp->proxyclient.reset();

    Lock();

    auto iterator = _tcp_connection_map.find(tcp->guid);

    if (iterator != _tcp_connection_map.end())
    {
        _tcp_connection_map.erase(iterator);
    }

    Unlock();
}

bool ProxyClient::FindTcp(uint64_t guid, std::shared_ptr<Tcp> &tcp)
{
    Lock();

    auto iterator = _tcp_connection_map.find(guid);

    if (iterator != _tcp_connection_map.end())
    {
        tcp = iterator->second;
        Unlock();
        return true;
    }

    Unlock();
    return false;
}

ProxyServer::ProxyServer()
{
}

ProxyServer::~ProxyServer()
{
}

void ProxyServer::Lock()
{
    _lock.lock();
}

void ProxyServer::Unlock()
{
    _lock.unlock();
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

std::shared_ptr<ProxyClient> ProxyServer::AddClient(uint64_t guid)
{
    std::shared_ptr<ProxyClient> client(new ProxyClient(guid));

    Lock();
    _client_instance_map[guid] = client;
    Unlock();

    return client;
}

void ProxyServer::RemoveClient(uint64_t guid)
{
}
bool ProxyServer::FindClient(uint64_t guid, std::shared_ptr<ProxyClient> &client)
{
    bool f = false;

    Lock();

    auto iterator = _client_instance_map.find(guid);
    if (iterator != _client_instance_map.end())
    {
        client = iterator->second;
        f = true;
    }

    Unlock();

    return f;
}

unsigned char GetPacketIdentifier(RakNet::Packet *p);
unsigned char *GetPacketData(RakNet::Packet *p);
size_t GetPacketLength(RakNet::Packet *p);

void ProxyServer::ReadClientMessage(RakNet::Packet *packet)
{
    std::shared_ptr<ProxyClient> client;
    unsigned char *data;
    size_t length;
    unsigned char nonce[8];
    uint64_t guid;
    unsigned char identifier;

    data = GetPacketData(packet);
    length = GetPacketLength(packet);

    RakNet::BitStream reader(data, length, false);

    reader.IgnoreBytes(sizeof(unsigned char));
    if (!reader.Read(nonce))
        return;

    unsigned char *encrypted_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
    size_t encrypted_length = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

    s20_crypt(password, S20_KEYLEN_256, nonce, 0, encrypted_data, encrypted_length);

    //dump_bytes(encrypted_data, encrypted_length);
    if (!reader.Read(identifier) || !reader.Read(guid))
    {
        return;
    }

    // printf("identifier:%d\n", identifier);
    // printf("guid:%lu\n", guid);

    if (!FindClient(packet->guid.g, client))
    {
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
                printf("SOCKS5_ADDRTYPE_IPV4:%s:%d\n", inet_ntoa(addr.v4.sin_addr), htons(addr.v4.sin_port));
            }
            else
            {
                ConnectResponse(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
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
                ConnectResponse(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else if (remote_addrtype == SOCKS5_ADDRTYPE_DOMAIN)
        {
            RakNet::RakString domain;

            if (reader.Read(domain) && reader.Read(addr.domain.port))
            {
                strncpy(addr.domain.domain, domain.C_String(), 255);
                addr.domain.domain[255] = 0;

                printf("%s\n", addr.domain.domain);

                begin_connect = true;
                printf("SOCKS5_ADDRTYPE_DOMAIN:%s:%d\n", domain.C_String(), htons(addr.domain.port));
            }
            else
            {
                ConnectResponse(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else
        {
            ConnectResponse(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
        }

        if (begin_connect)
        {
            Tcp *tcp = new Tcp(guid);
            if (tcp == NULL)
            {
                printf("create Tcp failed\n");
                exit(EXIT_FAILURE);
            }
            std::shared_ptr<Tcp> tcpclient(tcp);
            client->AddTcp(tcpclient);
            if (client->InitTcp(tcpclient, remote_addrtype, addr))
            {
                tcpclient->proxyclient = client;
            }
            else
            {
                client->CloseTcp(tcpclient);
            }
        }
        return;
    }

    if (identifier == ID_A2A_TCP_STREAM)
    {
        printf("ID_A2A_TCP_STREAM:%lu\n", guid);
        std::shared_ptr<Tcp> tcp;
        if (client->FindTcp(guid, tcp))
        {
            printf("write data\n");
            unsigned char *stream_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
            size_t stream_len = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());
            WriteRequest::write(tcp, stream_data, stream_len);
        }
    }

    if (identifier == ID_A2A_TCP_CLOSE)
    {
        printf("ID_A2A_TCP_STREAM\n");
    }
}

void ProxyServer::ConnectResponse(std::shared_ptr<ProxyClient> &client, uint64_t clientguid, unsigned char rep, unsigned char addrtype, socks5_addr *addr)
{
    RakNet::BitStream serializer;
    serializer.Write((unsigned char)ID_S2C_TCP_CONNECT);
    serializer.Write(clientguid);
    serializer.Write(rep);
    serializer.Write(addrtype);

    if (addrtype == SOCKS5_ADDRTYPE_IPV4)
    {
        serializer.Write(addr->v4.sin_addr);
        serializer.Write(addr->v4.sin_port);
    }
    if (addrtype == SOCKS5_ADDRTYPE_IPV6)
    {
        serializer.Write(addr->v6.sin6_addr);
        serializer.Write(addr->v6.sin6_port);
    }
    if (addrtype == SOCKS5_ADDRTYPE_DOMAIN)
    {
        serializer.Write(addr->domain.domain);
        serializer.Write(addr->domain.port);
    }

    Send(client, clientguid, serializer, RELIABLE, IMMEDIATE_PRIORITY);
}

void ProxyServer::Send(std::shared_ptr<ProxyClient> &client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability, PacketPriority priority)
{
    RakNet::BitStream encrypted_packet;
    uint8_t nonce[8];

    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();
    s20_crypt(password, S20_KEYLEN_256, nonce, 0, packet.GetData(), packet.GetNumberOfBytesUsed());

    encrypted_packet.Write((unsigned char)ID_USER_PACKET_ENUM);
    encrypted_packet.Write(nonce);
    encrypted_packet.Write(packet);

    char orderingChannel = guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS
    printf("send resp\n");
    rakPeer->Send(&encrypted_packet, priority, reliability, orderingChannel, RakNet::RakNetGUID(client->guid), false);
}
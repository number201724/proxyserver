#include "defs.h"
#include "server.h"

static ProxyServer s_ProxyServer;
ProxyServer *proxyServer = &s_ProxyServer;

extern RakNet::RakPeerInterface *rakPeer;

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

class TcpSocketReader
{
public:
    TcpSocketReader();
    ~TcpSocketReader();
};

TcpReader::TcpReader(Tcp *_tcp) : tcp(_tcp)
{
    _tcp->AddRef();
    reading = true;
}

TcpReader::~TcpReader()
{
    tcp->Release();
}

void TcpReader::pause()
{
    uv_read_stop((uv_stream_t *)&tcp->sock);
    reading = false;
}

void TcpReader::resume()
{
    if (!reading)
    {
        if (tcp->stage == SOCKS5_CONN_STAGE_STREAM)
        {
            uv_read_start((uv_stream_t *)&tcp->sock, TcpReader::alloc_cb, TcpReader::read_cb);
            reading = true;
        }
    }
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
    TcpReader *reader = tcp->reader;

    if (nread == UV_EOF)
    {
        proxyServer->SendStreamData(tcp->proxyclient, tcp, buf->base, 0);

        tcp->reader = nullptr;
        TcpClose::close(reader->tcp);
        delete reader;
        return;
    }

    if (nread < 0)
    {
        tcp->reader = nullptr;
        TcpClose::close(reader->tcp);
        delete reader;
        return;
    }

    tcp->ack = proxyServer->SendStreamData(tcp->proxyclient, tcp, buf->base, nread);
#ifndef DISABLE_ACK
    reader->pause();
#endif
}

TcpShutdown::TcpShutdown(Tcp *_tcp) : tcp(_tcp)
{
    tcp->AddRef();
    req.data = this;
}

TcpShutdown::~TcpShutdown()
{
    tcp->Release();
}

void TcpShutdown::shutdown_cb(uv_shutdown_t *req, int status)
{
    TcpShutdown *pshutdown = (TcpShutdown *)req->data;
	if (status == UV_ECANCELED) {
		delete pshutdown;
		return;
	}

    Tcp *tcp = pshutdown->tcp;
    TcpClose::close(tcp);
}

void TcpShutdown::shutdown(Tcp *tcp)
{
    if (tcp->stage < SOCKS5_CONN_STAGE_CLOSING)
    {
        tcp->stage = SOCKS5_CONN_STAGE_CLOSING;

        TcpShutdown *pshutdown = new TcpShutdown(tcp);
        int code = uv_shutdown(&pshutdown->req, (uv_stream_t *)&tcp->sock, shutdown_cb);
        if (code)
        {
            TcpClose::close(tcp);
            delete pshutdown;
        }
    }
}

TcpWriter::TcpWriter(Tcp *_tcp, void *data, size_t len) : tcp(_tcp)
{
    buf.base = new char[len];
    buf.len = len;

    memcpy(buf.base, data, len);
    tcp->AddRef();

    request.data = this;
}

TcpWriter::~TcpWriter()
{
    if (buf.base)
    {
        delete[] buf.base;
    }

    tcp->Release();
}

void TcpWriter::write_cb(uv_write_t *req, int status)
{
    TcpWriter *request = (TcpWriter *)req->data;
    delete request;
}

void TcpWriter::write(Tcp *_tcp, void *data, size_t len)
{
    if (_tcp->stage == SOCKS5_CONN_STAGE_STREAM)
    {
        if (len == 0)
        {
            TcpShutdown::shutdown(_tcp);
            return;
        }

        TcpWriter *request = new TcpWriter(_tcp, data, len);
        int code = uv_write(&request->request, (uv_stream_t *)&_tcp->sock, &request->buf, 1, write_cb);
        if (code != 0)
        {
            delete request;
        }
    }
}

Tcp::Tcp(uint64_t g, ProxyClient *_proxyclient) : proxyclient(_proxyclient)
{
    remote_close = false;
    close = nullptr;
    guid = g;
    stage = SOCKS5_CONN_STAGE_EXMETHOD;
    reader = nullptr;
    proxyclient->AddRef();
    ack = 0;
}

Tcp::~Tcp()
{
    proxyclient->Release();
}

void TcpClose::close_cb(uv_handle_t *handle)
{
    Tcp *tcp = (Tcp *)handle->data;
    TcpClose *close = tcp->close;
    tcp->close = nullptr;

    if (tcp->reader)
    {
		uv_read_stop((uv_stream_t*)& tcp->sock);
        delete tcp->reader;
        tcp->reader = nullptr;
    }

    delete close;
}

void TcpClose::close(Tcp *tcp)
{
    if (tcp->stage < SOCKS5_CONN_STAGE_CLOSED)
    {
        tcp->stage = SOCKS5_CONN_STAGE_CLOSED;

        if (tcp->reader)
        {
            uv_read_stop((uv_stream_t *)&tcp->sock);
        }

        if (!tcp->remote_close)
        {
            proxyServer->SencClose(tcp->proxyclient, tcp->guid);
        }

        tcp->close = new TcpClose(tcp);
        uv_close((uv_handle_t *)&tcp->sock, close_cb);
		tcp->proxyclient->CloseTcp(tcp);
    }
}

int TcpConnect::connect(Tcp *tcp, struct sockaddr *addr)
{
    int code;
    TcpConnect *tcpConnect = new TcpConnect(tcp);
    code = uv_tcp_connect(&tcpConnect->_connect, &tcp->sock, addr, TcpConnect::connect_cb);
    if (code)
    {
        delete tcpConnect;
    }

    return code;
}
void TcpConnect::connect_cb(uv_connect_t *req, int status)
{
    TcpConnect *tcpConnect = (TcpConnect *)req->data;
    Tcp *tcp = tcpConnect->tcp;

    if (status == UV_ECANCELED)
    {
        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_SERVER_FAILURE,
                                       tcpConnect->tcp->remote_addrtype,
                                       &tcpConnect->tcp->remote_addr);

		if (tcp->stage < SOCKS5_CONN_STAGE_CLOSING) {
			TcpClose::close(tcp);
		}

        delete tcpConnect;
        return;
    }

    if (status == 0)
    {
        struct sockaddr_storage sockaddr = {0};
        int sockaddrlen = sizeof(sockaddr);
        tcpConnect->tcp->stage = SOCKS5_CONN_STAGE_CONNECTED;
        uv_tcp_getsockname(&tcpConnect->tcp->sock, (struct sockaddr *)&sockaddr, &sockaddrlen);

        if (sockaddr.ss_family == AF_INET)
        {
            tcpConnect->tcp->bnd_addrtype = SOCKS5_ADDRTYPE_IPV4;
            tcpConnect->tcp->bnd_addr.v4 = *(sockaddr_in *)&sockaddr;
        }
        else if (sockaddr.ss_family == AF_INET6)
        {
            tcpConnect->tcp->bnd_addrtype = SOCKS5_ADDRTYPE_IPV6;
            tcpConnect->tcp->bnd_addr.v6 = *(sockaddr_in6 *)&sockaddr;
        }

        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_SUCCESS,
                                       tcpConnect->tcp->bnd_addrtype,
                                       &tcpConnect->tcp->bnd_addr);

        if (TcpReader::begin_read(tcp) != 0)
        {
            TcpClose::close(tcpConnect->tcp);
        }
        else
        {
            tcp->stage = SOCKS5_CONN_STAGE_STREAM;
        }

        delete tcpConnect;
        return;
    }

    if (status == UV_ENETUNREACH)
    {
        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_NETWORK_UNREACHABLE,
                                       tcpConnect->tcp->remote_addrtype,
                                       &tcpConnect->tcp->remote_addr);
    }
    else if (status == UV_EHOSTUNREACH)
    {
        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_HOST_UNREACHABLE,
                                       tcpConnect->tcp->remote_addrtype,
                                       &tcpConnect->tcp->remote_addr);
    }
    else if (status == UV_ECONNREFUSED)
    {
        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_CONNECTION_REFUSED,
                                       tcpConnect->tcp->remote_addrtype,
                                       &tcpConnect->tcp->remote_addr);
    }
    else
    {
        proxyServer->SendConnectResult(tcpConnect->tcp->proxyclient,
                                       tcpConnect->tcp->guid,
                                       SOCKS5_RESPONSE_TTL_EXPIRED,
                                       tcpConnect->tcp->remote_addrtype,
                                       &tcpConnect->tcp->remote_addr);
    }

    TcpClose::close(tcp);
    delete tcpConnect;
}

int AsyncGetAddrInfo::getaddrinfo(Tcp *tcp, const char *node, const char *service, const struct addrinfo *hints)
{
    AsyncGetAddrInfo *async_getaddrinfo = new AsyncGetAddrInfo(tcp);

    int code = uv_getaddrinfo(uv_default_loop(), &async_getaddrinfo->_getaddrinfo, AsyncGetAddrInfo::getaddrinfo_cb, node, service, hints);

    if (code)
    {
        delete async_getaddrinfo;
    }

    return code;
}
void AsyncGetAddrInfo::getaddrinfo_cb(uv_getaddrinfo_t *req,
                                      int status,
                                      struct addrinfo *res)
{
    AsyncGetAddrInfo *asyncgetaddrinfo = (AsyncGetAddrInfo *)req->data;

    if (status == UV_ECANCELED)
    {
        if (res)
        {
            uv_freeaddrinfo(res);
        }

		if (asyncgetaddrinfo->tcp->stage < SOCKS5_CONN_STAGE_CLOSING) {
			TcpClose::close(asyncgetaddrinfo->tcp);
		}
        
        delete asyncgetaddrinfo;
        return;
    }

    auto &tcp = asyncgetaddrinfo->tcp;
    for (auto p = res; p != NULL; p = p->ai_next)
    {
        tcp->stage = SOCKS5_CONN_STAGE_CONNECTING;

        int code = TcpConnect::connect(tcp, p->ai_addr);
        if (code != 0)
        {
            TcpClose::close(asyncgetaddrinfo->tcp);
        }

        break;
    }

    uv_freeaddrinfo(res);
    delete asyncgetaddrinfo;
}

ProxyClient::ProxyClient(uint64_t g) : guid(g)
{
}

ProxyClient::~ProxyClient()
{
}

bool ProxyClient::InitTcp(Tcp *tcp, unsigned char addrtype, const socks5_addr &addr)
{
    tcp->remote_addrtype = addrtype;
    tcp->remote_addr = addr;

    tcp->sock.data = tcp;
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
        int code = TcpConnect::connect(tcp, paddr);
        if (code != 0)
        {
            printf("uv_tcp_connect failed code:%d\n", code);
            TcpClose::close(tcp);
            return false;
        }
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

        code = AsyncGetAddrInfo::getaddrinfo(tcp, addr.domain.domain, service, &hints);
        if (code != 0)
        {
            TcpClose::close(tcp);
            return false;
        }
    }
    else
    {
        TcpClose::close(tcp);
        return false;
    }

    return true;
}

void ProxyClient::AddTcp(Tcp *tcp)
{
    _tcp_connection_map[tcp->guid] = tcp;
    tcp->AddRef();
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
            TcpClose::close(iterator->second);
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

void ProxyServer::ReadAckMessage(RakNet::Packet *packet)
{
#ifndef DISABLE_ACK
    ProxyClient *client;
    unsigned char *data;
    size_t length;
    data = GetPacketData(packet);
    length = GetPacketLength(packet);

    if (!FindClient(packet->guid.g, client))
    {
        return;
    }

    uint32_t ack = *(uint32_t *)&data[1];

    for (auto iterator = client->_tcp_connection_map.begin(); iterator != client->_tcp_connection_map.end(); iterator++)
    {
        auto tcp = iterator->second;

        if (tcp->ack == ack)
        {
            if (tcp->reader)
            {
                tcp->reader->resume();
                break;
            }
        }
    }
#endif
}

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
    if (!reader.ReadAlignedBytes((unsigned char *)nonce, 8))
        return;

    unsigned char *encrypted_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
    size_t encrypted_length = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

    s20_crypt(password, S20_KEYLEN_256, nonce, 0, encrypted_data, encrypted_length);

    if (!reader.ReadAlignedBytes((unsigned char *)&identifier, 1) || !reader.ReadAlignedBytes((unsigned char *)&guid, 8))
    {
        return;
    }

    if (!FindClient(packet->guid.g, client))
    {
        return;
    }

    if (identifier == ID_C2S_TCP_CONNECT)
    {
        unsigned char remote_addrtype;
        socks5_addr addr;

        bool begin_connect = false;

        if (!reader.ReadAlignedBytes((unsigned char *)&remote_addrtype, 1))
        {
            return;
        }

        if (remote_addrtype == SOCKS5_ADDRTYPE_IPV4)
        {
            if (reader.ReadAlignedBytes((unsigned char *)&addr.v4.sin_addr, 4) && reader.ReadAlignedBytes((unsigned char *)&addr.v4.sin_port, 2))
            {
                begin_connect = true;
            }
            else
            {
                SendConnectResult(client, guid, SOCKS5_RESPONSE_ADDRTYPE_NOT_SUPPORTED, remote_addrtype, &addr);
            }
        }
        else if (remote_addrtype == SOCKS5_ADDRTYPE_IPV6)
        {
            if (reader.ReadAlignedBytes((unsigned char *)&addr.v6.sin6_addr, 16) && reader.ReadAlignedBytes((unsigned char *)&addr.v6.sin6_port, 2))
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

            if (reader.Read(domain) && reader.ReadAlignedBytes((unsigned char *)&addr.domain.port, 2))
            {
                strncpy(addr.domain.domain, domain.C_String(), 255);
                addr.domain.domain[255] = 0;
                begin_connect = true;
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
            Tcp *tcp = new Tcp(guid, client);
            if (tcp == NULL)
            {
                printf("create Tcp failed\n");
                exit(EXIT_FAILURE);
            }

            client->AddTcp(tcp);

            if (!client->InitTcp(tcp, remote_addrtype, addr))
            {
                client->CloseTcp(tcp);
            }

            tcp->Release();
        }
        return;
    }

    if (identifier == ID_A2A_TCP_STREAM)
    {
        Tcp *tcp = nullptr;
        if (client->FindTcp(guid, tcp))
        {
            uint32_t crc;
            reader.ReadAlignedBytes((unsigned char *)&crc, 4);

            unsigned char *stream_data = reader.GetData() + BITS_TO_BYTES(reader.GetReadOffset());
            size_t stream_len = BITS_TO_BYTES(reader.GetNumberOfUnreadBits());

            uint32_t crc2 = crc32(0, stream_data, stream_len);
            if (crc2 != crc)
            {
                printf("bad crc\n");
                return;
            }
            TcpWriter::write(tcp, stream_data, stream_len);
        }
        return;
    }

    if (identifier == ID_A2A_TCP_CLOSE)
    {
        Tcp *tcp;
        if (client->FindTcp(guid, tcp))
        {
            tcp->remote_close = true;
            TcpClose::close(tcp);
        }
        return;
    }
}

void ProxyServer::SendConnectResult(ProxyClient *client, uint64_t guid, unsigned char rep, unsigned char addrtype, socks5_addr *addr)
{
    RakNet::BitStream serializer;
    unsigned char id = ID_S2C_TCP_CONNECT;
    serializer.WriteAlignedBytes((unsigned char *)&id, 1);
    serializer.WriteAlignedBytes((unsigned char *)&guid, 8);
    serializer.WriteAlignedBytes((unsigned char *)&rep, 1);
    serializer.WriteAlignedBytes((unsigned char *)&addrtype, 1);

    if (addrtype == SOCKS5_ADDRTYPE_IPV4)
    {
        serializer.WriteAlignedBytes((unsigned char *)&addr->v4.sin_addr, 4);
        serializer.WriteAlignedBytes((unsigned char *)&addr->v4.sin_port, 2);
    }
    if (addrtype == SOCKS5_ADDRTYPE_IPV6)
    {
        serializer.WriteAlignedBytes((unsigned char *)&addr->v6.sin6_addr, 16);
        serializer.WriteAlignedBytes((unsigned char *)&addr->v6.sin6_port, 2);
    }
    if (addrtype == SOCKS5_ADDRTYPE_DOMAIN)
    {
        serializer.Write(addr->domain.domain);
        serializer.WriteAlignedBytes((unsigned char *)&addr->domain.port, 2);
    }

    Send(client, guid, serializer, RELIABLE_ORDERED, IMMEDIATE_PRIORITY);
}

void ProxyServer::SencClose(ProxyClient *client, uint64_t clientguid)
{
    RakNet::BitStream serializer;
    unsigned char id = ID_A2A_TCP_CLOSE;
    serializer.WriteAlignedBytes((unsigned char *)&id, 1);
    serializer.WriteAlignedBytes((unsigned char *)&clientguid, 8);

    Send(client, clientguid, serializer);
}

void ProxyServer::Send(ProxyClient *client, uint64_t guid, RakNet::BitStream &packet, PacketReliability reliability, PacketPriority priority)
{
    // RakNet::BitStream encrypted_packet;

    uint8_t nonce[8];
    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();

    size_t len = sizeof(struct packet_header) + packet.GetNumberOfBytesUsed();
    void *copydata = alloca(len);
    struct packet_header *header = (struct packet_header *)copydata;
    header->id = ID_USER_PACKET_ENUM;
    memcpy(header->nonce, nonce, 8);
    s20_crypt(password, S20_KEYLEN_256, nonce, 0, packet.GetData(), packet.GetNumberOfBytesUsed());
    memcpy(&header[1], packet.GetData(), packet.GetNumberOfBytesUsed());
    char orderingChannel = guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS
    rakPeer->Send((char *)copydata, len, priority, reliability, orderingChannel, RakNet::RakNetGUID(client->guid), false);
}

uint32_t ProxyServer::SendStreamData(ProxyClient *client, Tcp *tcp, void *data, size_t length, PacketReliability reliability, PacketPriority priority)
{
    uint8_t nonce[8];
    *(uint64_t *)&nonce = rakPeer->Get64BitUniqueRandomNumber();
    size_t len = sizeof(struct packet_header) + sizeof(struct stream_header) + length;
    void *copydata = alloca(len);

    struct packet_header *header = (struct packet_header *)copydata;
    header->id = ID_USER_PACKET_ENUM;
    memcpy(header->nonce, nonce, 8);

    struct stream_header *sheader = (struct stream_header *)&header[1];
    sheader->id = ID_A2A_TCP_STREAM;
    sheader->guid = tcp->guid;
    sheader->crc = crc32(0, data, (uint32_t)length);
    void *target = &sheader[1];
    memcpy(target, data, length);

    s20_crypt(password, S20_KEYLEN_256, nonce, 0, (unsigned char *)sheader, (uint32_t)length + sizeof(struct stream_header));

    char orderingChannel = tcp->guid % 32; //PacketPriority::NUMBER_OF_ORDERED_STREAMS
    return rakPeer->Send((char *)copydata, len, priority, reliability, orderingChannel, RakNet::RakNetGUID(client->guid), false);
}
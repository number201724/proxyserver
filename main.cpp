#include "defs.h"
#include "server.h"

RakNet::RakPeerInterface *rakPeer;

#define HOST "127.0.0.1"
#define PORT 27015

// Copied from Multiplayer.cpp
// If the first byte is ID_TIMESTAMP, then we want the 5th byte
// Otherwise we want the 1st byte
unsigned char GetPacketIdentifier(RakNet::Packet *p)
{
    if (p == 0)
        return 255;

    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return (unsigned char)p->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)];
    }
    else
        return (unsigned char)p->data[0];
}

unsigned char *GetPacketData(RakNet::Packet *p)
{
    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return &p->data[sizeof(RakNet::MessageID) + sizeof(RakNet::Time)];
    }
    else
        return &p->data[0];
}

size_t GetPacketLength(RakNet::Packet *p)
{
    if ((unsigned char)p->data[0] == ID_TIMESTAMP)
    {
        RakAssert(p->length > sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
        return p->length - (sizeof(RakNet::MessageID) + sizeof(RakNet::Time));
    }
    else
        return p->length;
}

uv_timer_t udp_timer;

static void udp_packet_update(uv_timer_t *timer)
{
    RakNet::Packet *p;
    unsigned char packetIdentifier;

    for (p = rakPeer->Receive(); p; rakPeer->DeallocatePacket(p), p = rakPeer->Receive())
    {
        packetIdentifier = GetPacketIdentifier(p);
        switch (packetIdentifier)
        {
        case ID_DISCONNECTION_NOTIFICATION:
            proxyServer->RemoveClient(p->guid.g);
            printf("ID_DISCONNECTION_NOTIFICATION from %s\n", p->systemAddress.ToString(true));
            break;
        case ID_NEW_INCOMING_CONNECTION:
            proxyServer->AddClient(p->guid.g);
            printf("ID_NEW_INCOMING_CONNECTION from %s with GUID %s\n", p->systemAddress.ToString(true), p->guid.ToString());
            break;
        case ID_INCOMPATIBLE_PROTOCOL_VERSION:
            printf("ID_INCOMPATIBLE_PROTOCOL_VERSION\n");
            break;
        case ID_CONNECTED_PING:
        case ID_UNCONNECTED_PING:
            printf("Ping from %s\n", p->systemAddress.ToString(true));
            break;
        case ID_CONNECTION_LOST:
            proxyServer->RemoveClient(p->guid.g);
            printf("ID_CONNECTION_LOST from %s\n", p->systemAddress.ToString(true));
            break;
        case ID_USER_PACKET_ENUM:
            proxyServer->ReadClientMessage(p);
            break;
        case ID_SND_RECEIPT_ACKED:
        case ID_SND_RECEIPT_LOSS:
            proxyServer->ReadAckMessage(p);
            break;
        default:
            break;
        }
    }
}


int main(int argc, char *argv[])
{
#ifndef  _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif // ! _WIN32


    rakPeer = RakNet::RakPeerInterface::GetInstance();
    rakPeer->SetTimeoutTime(10000, RakNet::UNASSIGNED_SYSTEM_ADDRESS);
    rakPeer->AllowConnectionResponseIPMigration(false);
    rakPeer->SetOccasionalPing(true);
    rakPeer->SetUnreliableTimeout(1000);

    RakNet::SocketDescriptor socketDescriptor[1];
    socketDescriptor[0].port = 27015;

    RakNet::StartupResult rs = rakPeer->Startup(500, socketDescriptor, 1);

    if (rs != RakNet::StartupResult::RAKNET_STARTED)
    {
        printf("rakPeer::Startup failed error:%d\n", rs);
        exit(EXIT_FAILURE);
    }

    proxyServer->SetupKey("WDNMDNMSL");
    rakPeer->SetMaximumIncomingConnections(500);

    uv_timer_init(uv_default_loop(), &udp_timer);
    uv_timer_start(&udp_timer, udp_packet_update, 10, 10);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    return 0;
}
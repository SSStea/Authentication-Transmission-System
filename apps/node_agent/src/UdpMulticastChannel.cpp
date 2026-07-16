#include "tesla/node_agent/UdpMulticastChannel.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <utility>

namespace tesla::node_agent
{
namespace
{
constexpr std::size_t MAX_UDP_DATAGRAM_SIZE = 65507;

void closeSocket(std::atomic<int>& nSocket) noexcept
{
    const int nDescriptor = nSocket.exchange(-1);
    if (nDescriptor >= 0)
    {
        shutdown(nDescriptor, SHUT_RDWR);
        close(nDescriptor);
    }
}
}

UdpMulticastChannel::UdpMulticastChannel(
    std::string strBindAddress,
    std::string strMulticastAddress,
    std::uint16_t u16MulticastPort,
    DatagramHandler fnDatagramHandler
)
    : m_strBindAddress(std::move(strBindAddress)),
      m_strMulticastAddress(std::move(strMulticastAddress)),
      m_u16MulticastPort(u16MulticastPort),
      m_fnDatagramHandler(std::move(fnDatagramHandler))
{
}

UdpMulticastChannel::~UdpMulticastChannel()
{
    stop();
}

void UdpMulticastChannel::start()
{
    bool bExpected = false;
    if (!m_bRunning.compare_exchange_strong(bExpected, true))
    {
        return;
    }

    const int nSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (nSocket < 0)
    {
        m_bRunning = false;
        throw std::runtime_error("Unable to create UDP multicast socket");
    }
    m_nSocket = nSocket;

    int nEnabled = 1;
    setsockopt(nSocket, SOL_SOCKET, SO_REUSEADDR, &nEnabled, sizeof(nEnabled));

    sockaddr_in adrBind{};
    adrBind.sin_family = AF_INET;
    adrBind.sin_port = htons(m_u16MulticastPort);
    adrBind.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(nSocket, reinterpret_cast<const sockaddr*>(&adrBind), sizeof(adrBind)) != 0)
    {
        const std::string strError = std::strerror(errno);
        stop();
        throw std::runtime_error("Unable to bind UDP multicast socket: " + strError);
    }

    ip_mreq reqMembership{};
    if (inet_pton(AF_INET, m_strMulticastAddress.c_str(), &reqMembership.imr_multiaddr) != 1
        || inet_pton(AF_INET, m_strBindAddress.c_str(), &reqMembership.imr_interface) != 1)
    {
        stop();
        throw std::invalid_argument("UDP multicast or bind address is not valid IPv4");
    }

    if (setsockopt(
            nSocket,
            IPPROTO_IP,
            IP_ADD_MEMBERSHIP,
            &reqMembership,
            sizeof(reqMembership)
        ) != 0)
    {
        const std::string strError = std::strerror(errno);
        stop();
        throw std::runtime_error("Unable to join UDP multicast group: " + strError);
    }

    in_addr adrInterface{};
    inet_pton(AF_INET, m_strBindAddress.c_str(), &adrInterface);
    unsigned char u8Ttl = 1;
    unsigned char u8Loop = 1;
    if (setsockopt(nSocket, IPPROTO_IP, IP_MULTICAST_IF, &adrInterface, sizeof(adrInterface)) != 0
        || setsockopt(nSocket, IPPROTO_IP, IP_MULTICAST_TTL, &u8Ttl, sizeof(u8Ttl)) != 0
        || setsockopt(nSocket, IPPROTO_IP, IP_MULTICAST_LOOP, &u8Loop, sizeof(u8Loop)) != 0)
    {
        const std::string strError = std::strerror(errno);
        stop();
        throw std::runtime_error("Unable to configure UDP multicast socket: " + strError);
    }

    try
    {
        m_thrReceiver = std::thread(&UdpMulticastChannel::receiveLoop, this);
    }
    catch (...)
    {
        stop();
        throw;
    }
}

void UdpMulticastChannel::stop() noexcept
{
    m_bRunning = false;
    closeSocket(m_nSocket);
    if (m_thrReceiver.joinable())
    {
        m_thrReceiver.join();
    }
}

bool UdpMulticastChannel::bIsRunning() const noexcept
{
    return m_bRunning.load();
}

bool UdpMulticastChannel::bSend(const protocol::ByteBuffer& vecDatagram) const noexcept
{
    if (vecDatagram.empty() || vecDatagram.size() > MAX_UDP_DATAGRAM_SIZE)
    {
        return false;
    }

    sockaddr_in adrTarget{};
    adrTarget.sin_family = AF_INET;
    adrTarget.sin_port = htons(m_u16MulticastPort);
    if (inet_pton(AF_INET, m_strMulticastAddress.c_str(), &adrTarget.sin_addr) != 1)
    {
        return false;
    }

    const int nSocket = m_nSocket.load();
    return nSocket >= 0
        && sendto(
            nSocket,
            vecDatagram.data(),
            vecDatagram.size(),
            MSG_NOSIGNAL,
            reinterpret_cast<const sockaddr*>(&adrTarget),
            sizeof(adrTarget)
        ) == static_cast<ssize_t>(vecDatagram.size());
}

void UdpMulticastChannel::receiveLoop()
{
    std::array<std::uint8_t, MAX_UDP_DATAGRAM_SIZE> arrBuffer{};

    while (m_bRunning.load())
    {
        pollfd pfdSocket{};
        pfdSocket.fd = m_nSocket.load();
        pfdSocket.events = POLLIN;
        const int nPollResult = poll(&pfdSocket, 1, 250);
        if (nPollResult == 0 || (nPollResult < 0 && errno == EINTR))
        {
            continue;
        }

        if (nPollResult < 0 || (pfdSocket.revents & POLLIN) == 0)
        {
            break;
        }

        sockaddr_in adrSource{};
        socklen_t nSourceLength = sizeof(adrSource);
        const ssize_t nReceived = recvfrom(
            m_nSocket.load(),
            arrBuffer.data(),
            arrBuffer.size(),
            0,
            reinterpret_cast<sockaddr*>(&adrSource),
            &nSourceLength
        );
        if (nReceived <= 0)
        {
            continue;
        }

        char arrSourceAddress[INET_ADDRSTRLEN]{};
        if (inet_ntop(
                AF_INET,
                &adrSource.sin_addr,
                arrSourceAddress,
                sizeof(arrSourceAddress)
            ) == nullptr)
        {
            continue;
        }

        // 每个Receiver始终监听，但明确忽略本节点自己发出的组播副本。
        if (m_strBindAddress == arrSourceAddress)
        {
            continue;
        }

        if (m_fnDatagramHandler)
        {
            m_fnDatagramHandler(
                arrSourceAddress,
                protocol::ByteBuffer(arrBuffer.begin(), arrBuffer.begin() + nReceived)
            );
        }
    }
}
}

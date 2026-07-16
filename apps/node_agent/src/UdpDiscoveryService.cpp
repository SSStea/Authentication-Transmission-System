#include "tesla/node_agent/UdpDiscoveryService.h"

#include "tesla/protocol/NodeDiscoveryJsonCodec.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>
#include <variant>

namespace tesla::node_agent
{
namespace
{
void closeSocket(std::atomic<int>& nSocket) noexcept
{
    const int nDescriptor = nSocket.exchange(-1);
    if (nDescriptor >= 0)
    {
        shutdown(nDescriptor, SHUT_RDWR);
        close(nDescriptor);
    }
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
}
}

UdpDiscoveryService::UdpDiscoveryService(
    std::string strBindAddress,
    std::uint16_t u16DiscoveryPort,
    std::string strBroadcastAddress,
    std::string strNodeName,
    std::uint16_t u16ManagementPort,
    std::chrono::milliseconds durHeartbeatInterval,
    RuntimeStateProvider fnStateProvider
)
    : m_strBindAddress(std::move(strBindAddress)),
      m_u16DiscoveryPort(u16DiscoveryPort),
      m_strBroadcastAddress(std::move(strBroadcastAddress)),
      m_strNodeName(std::move(strNodeName)),
      m_u16ManagementPort(u16ManagementPort),
      m_durHeartbeatInterval(durHeartbeatInterval),
      m_fnStateProvider(std::move(fnStateProvider))
{
    if (!m_fnStateProvider)
    {
        throw std::invalid_argument("UDP discovery service requires a state provider");
    }
}

UdpDiscoveryService::~UdpDiscoveryService()
{
    stop();
}

void UdpDiscoveryService::start()
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
        throw std::runtime_error("Unable to create UDP discovery socket");
    }
    m_nSocket = nSocket;

    int nEnabled = 1;
    setsockopt(nSocket, SOL_SOCKET, SO_REUSEADDR, &nEnabled, sizeof(nEnabled));
    if (setsockopt(nSocket, SOL_SOCKET, SO_BROADCAST, &nEnabled, sizeof(nEnabled)) != 0)
    {
        stop();
        throw std::runtime_error("Unable to enable UDP discovery broadcast");
    }

    if (setsockopt(nSocket, IPPROTO_IP, IP_PKTINFO, &nEnabled, sizeof(nEnabled)) != 0)
    {
        stop();
        throw std::runtime_error("Unable to enable UDP discovery interface selection");
    }

    sockaddr_in adrBind{};
    adrBind.sin_family = AF_INET;
    adrBind.sin_port = htons(m_u16DiscoveryPort);
    adrBind.sin_addr.s_addr = htonl(INADDR_ANY);

    in_addr adrSelectedInterface{};
    if (inet_pton(AF_INET, m_strBindAddress.c_str(), &adrSelectedInterface) != 1)
    {
        stop();
        throw std::invalid_argument("UDP discovery bind address is not valid IPv4");
    }

    // 广播目的地址不会投递给只绑定单播地址的Socket，因此接收端监听INADDR_ANY；
    // 发送时再通过IP_PKTINFO固定源地址，避免多网卡主机从错误接口响应扫描。
    if (bind(nSocket, reinterpret_cast<const sockaddr*>(&adrBind), sizeof(adrBind)) != 0)
    {
        const std::string strError = std::strerror(errno);
        stop();
        throw std::runtime_error("Unable to bind UDP discovery socket: " + strError);
    }

    try
    {
        m_thrWorker = std::thread(&UdpDiscoveryService::workerLoop, this);
    }
    catch (...)
    {
        stop();
        throw;
    }
}

void UdpDiscoveryService::stop() noexcept
{
    m_bRunning = false;
    closeSocket(m_nSocket);
    if (m_thrWorker.joinable())
    {
        m_thrWorker.join();
    }
}

bool UdpDiscoveryService::bIsRunning() const noexcept
{
    return m_bRunning.load();
}

void UdpDiscoveryService::workerLoop()
{
    auto tpNextHeartbeat = std::chrono::steady_clock::now();
    std::array<char, 8192> arrBuffer{};

    while (m_bRunning.load())
    {
        const auto durUntilHeartbeat = std::chrono::duration_cast<std::chrono::milliseconds>(
            tpNextHeartbeat - std::chrono::steady_clock::now()
        );
        const int nTimeoutMilliseconds = static_cast<int>(std::max<std::int64_t>(
            0,
            std::min<std::int64_t>(durUntilHeartbeat.count(), 250)
        ));

        pollfd pfdSocket{};
        pfdSocket.fd = m_nSocket.load();
        pfdSocket.events = POLLIN;
        const int nPollResult = poll(&pfdSocket, 1, nTimeoutMilliseconds);
        if (nPollResult > 0 && (pfdSocket.revents & POLLIN) != 0)
        {
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

            if (nReceived > 0)
            {
                char arrSourceAddress[INET_ADDRSTRLEN]{};
                if (inet_ntop(
                        AF_INET,
                        &adrSource.sin_addr,
                        arrSourceAddress,
                        sizeof(arrSourceAddress)
                    ) != nullptr)
                {
                    handleDatagram(
                        arrSourceAddress,
                        ntohs(adrSource.sin_port),
                        std::string(arrBuffer.data(), static_cast<std::size_t>(nReceived))
                    );
                }
            }
        }
        else if (nPollResult < 0 && errno != EINTR)
        {
            break;
        }

        if (std::chrono::steady_clock::now() >= tpNextHeartbeat)
        {
            bSendPresence(
                protocol::NodeDiscoveryMessageType::Heartbeat,
                "",
                m_strBroadcastAddress,
                m_u16DiscoveryPort
            );
            tpNextHeartbeat = std::chrono::steady_clock::now() + m_durHeartbeatInterval;
        }
    }
}

void UdpDiscoveryService::handleDatagram(
    const std::string& strSourceAddress,
    std::uint16_t u16SourcePort,
    const std::string& strJson
)
{
    const protocol::NodeDiscoveryDecodeResult resMessage =
        protocol::NodeDiscoveryJsonCodec::resDecode(strJson);
    if (!std::holds_alternative<protocol::NodeDiscoveryMessage>(resMessage))
    {
        return;
    }

    const protocol::NodeDiscoveryMessage& msgMessage =
        std::get<protocol::NodeDiscoveryMessage>(resMessage);
    if (msgMessage.typeMessage() != protocol::NodeDiscoveryMessageType::DiscoverRequest)
    {
        return;
    }

    const std::string& strRequestId = std::get<protocol::DiscoveryRequestDetails>(
        msgMessage.varDetails()
    ).strRequestId();
    bSendPresence(
        protocol::NodeDiscoveryMessageType::NodeAnnouncement,
        strRequestId,
        strSourceAddress,
        u16SourcePort
    );
}

bool UdpDiscoveryService::bSendPresence(
    protocol::NodeDiscoveryMessageType typeMessage,
    const std::string& strRequestId,
    const std::string& strTargetAddress,
    std::uint16_t u16TargetPort
) const noexcept
{
    try
    {
        const std::pair<bool, bool> prState = m_fnStateProvider();
        const protocol::NodeDiscoveryMessage msgPresence(
            protocol::NodePresenceDetails(
                typeMessage,
                strRequestId,
                m_strNodeName,
                protocol::NodeRole::Uav,
                m_u16ManagementPort,
                prState.first,
                prState.second,
                u64NowMilliseconds()
            )
        );
        const std::string strJson = protocol::NodeDiscoveryJsonCodec::strEncode(msgPresence);

        sockaddr_in adrTarget{};
        adrTarget.sin_family = AF_INET;
        adrTarget.sin_port = htons(u16TargetPort);
        if (inet_pton(AF_INET, strTargetAddress.c_str(), &adrTarget.sin_addr) != 1)
        {
            return false;
        }

        in_pktinfo infPacket{};
        if (inet_pton(AF_INET, m_strBindAddress.c_str(), &infPacket.ipi_spec_dst) != 1)
        {
            return false;
        }

        iovec iovPayload{};
        iovPayload.iov_base = const_cast<char*>(strJson.data());
        iovPayload.iov_len = strJson.size();

        std::array<char, CMSG_SPACE(sizeof(in_pktinfo))> arrControl{};
        msghdr hdrMessage{};
        hdrMessage.msg_name = &adrTarget;
        hdrMessage.msg_namelen = sizeof(adrTarget);
        hdrMessage.msg_iov = &iovPayload;
        hdrMessage.msg_iovlen = 1;
        hdrMessage.msg_control = arrControl.data();
        hdrMessage.msg_controllen = arrControl.size();

        cmsghdr* pControl = CMSG_FIRSTHDR(&hdrMessage);
        pControl->cmsg_level = IPPROTO_IP;
        pControl->cmsg_type = IP_PKTINFO;
        pControl->cmsg_len = CMSG_LEN(sizeof(in_pktinfo));
        std::memcpy(CMSG_DATA(pControl), &infPacket, sizeof(infPacket));

        const int nSocket = m_nSocket.load();
        return nSocket >= 0
            && sendmsg(nSocket, &hdrMessage, MSG_NOSIGNAL)
                == static_cast<ssize_t>(strJson.size());
    }
    catch (...)
    {
        return false;
    }
}
}

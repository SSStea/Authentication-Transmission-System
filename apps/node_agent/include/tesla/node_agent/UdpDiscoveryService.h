#pragma once

#include "tesla/protocol/NodeDiscoveryMessage.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>
#include <utility>

namespace tesla::node_agent
{
/** @brief 接收UDP发现请求、单播返回节点公告并周期广播心跳。 */
class UdpDiscoveryService final
{
public:
    using RuntimeStateProvider = std::function<std::pair<bool, bool>()>;

    UdpDiscoveryService(
        std::string strBindAddress,
        std::uint16_t u16DiscoveryPort,
        std::string strBroadcastAddress,
        std::string strNodeName,
        std::uint16_t u16ManagementPort,
        std::chrono::milliseconds durHeartbeatInterval,
        RuntimeStateProvider fnStateProvider
    );
    ~UdpDiscoveryService();

    UdpDiscoveryService(const UdpDiscoveryService&) = delete;
    UdpDiscoveryService& operator=(const UdpDiscoveryService&) = delete;

    void start();
    void stop() noexcept;
    bool bIsRunning() const noexcept;

private:
    void workerLoop();
    void handleDatagram(
        const std::string& strSourceAddress,
        std::uint16_t u16SourcePort,
        const std::string& strJson
    );
    bool bSendPresence(
        protocol::NodeDiscoveryMessageType typeMessage,
        const std::string& strRequestId,
        const std::string& strTargetAddress,
        std::uint16_t u16TargetPort
    ) const noexcept;

    std::string               m_strBindAddress;
    std::uint16_t             m_u16DiscoveryPort;
    std::string               m_strBroadcastAddress;
    std::string               m_strNodeName;
    std::uint16_t             m_u16ManagementPort;
    std::chrono::milliseconds m_durHeartbeatInterval;
    RuntimeStateProvider      m_fnStateProvider;
    std::atomic<bool>         m_bRunning{false};
    std::atomic<int>          m_nSocket{-1};
    std::thread               m_thrWorker;
};
}

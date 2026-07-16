#pragma once

#include "tesla/node_agent/NodeAgentConfig.h"
#include "tesla/node_agent/TcpManagementServer.h"
#include "tesla/node_agent/UdpDiscoveryService.h"
#include "tesla/node_agent/UdpMulticastChannel.h"

#include <atomic>
#include <cstddef>

namespace tesla::node_agent
{
/** @brief 组合NodeAgent阶段3的TCP管理、UDP发现和TESLA组播生命周期。 */
class NodeAgentService final
{
public:
    explicit NodeAgentService(
        NodeAgentConfig cfgConfig,
        UdpMulticastChannel::DatagramHandler fnDatagramHandler = {}
    );
    ~NodeAgentService();

    NodeAgentService(const NodeAgentService&) = delete;
    NodeAgentService& operator=(const NodeAgentService&) = delete;

    void start();
    void stop() noexcept;
    bool bIsRunning() const noexcept;
    bool bSendAuthenticationDatagram(const protocol::ByteBuffer& vecDatagram) const noexcept;
    std::size_t nReceivedDatagramCount() const noexcept;
    const NodeAgentConfig& cfgConfig() const noexcept;

private:
    NodeAgentConfig             m_cfgConfig;
    std::atomic<bool>           m_bRunning{false};
    std::atomic<bool>           m_bSenderRunning{false};
    std::atomic<bool>           m_bReceiverRunning{false};
    std::atomic<std::size_t>    m_nReceivedDatagramCount{0};
    UdpMulticastChannel::DatagramHandler m_fnExternalDatagramHandler;
    TcpManagementServer        m_srvManagement;
    UdpDiscoveryService        m_srvDiscovery;
    UdpMulticastChannel        m_chnMulticast;
};
}

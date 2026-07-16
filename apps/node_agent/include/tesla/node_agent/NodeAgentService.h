#pragma once

#include "tesla/node_agent/NodeAuthenticationConfigController.h"
#include "tesla/node_agent/NodeAgentConfig.h"
#include "tesla/node_agent/TcpManagementServer.h"
#include "tesla/node_agent/UdpDiscoveryService.h"
#include "tesla/node_agent/UdpMulticastChannel.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace tesla::node_agent
{
/** @brief 组合NodeAgent网络生命周期与阶段4认证配置状态。 */
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
    bool bHasSenderAuthenticationContext() const;
    std::optional<std::uint64_t> optSenderAuthenticationChainId() const;
    std::size_t nReceiverAuthenticationContextCount() const;
    core::ReceiverAuthenticationContextLookupResult resFindReceiverAuthenticationContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;
    const NodeAgentConfig& cfgConfig() const noexcept;

private:
    NodeAgentConfig             m_cfgConfig;
    std::atomic<bool>           m_bRunning{false};
    std::atomic<bool>           m_bSenderRunning{false};
    std::atomic<bool>           m_bReceiverRunning{false};
    std::atomic<std::size_t>    m_nReceivedDatagramCount{0};
    UdpMulticastChannel::DatagramHandler m_fnExternalDatagramHandler;
    NodeAuthenticationConfigController m_ctlAuthenticationConfig;
    TcpManagementServer        m_srvManagement;
    UdpDiscoveryService        m_srvDiscovery;
    UdpMulticastChannel        m_chnMulticast;
};
}

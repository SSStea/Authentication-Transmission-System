#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

namespace tesla::node_agent
{
/** @brief NodeAgent内部网络常量和已自动选定的本机接口配置。 */
class NodeAgentConfig final
{
public:
    NodeAgentConfig(
        std::string strNodeName,
        std::string strBindAddress,
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16ManagementPort = 38020,
        std::string strMulticastAddress = "239.10.10.10",
        std::uint16_t u16MulticastPort = 39020,
        std::string strBroadcastAddress = "255.255.255.255",
        std::chrono::milliseconds durHeartbeatInterval = std::chrono::milliseconds(1000)
    )
        : m_strNodeName(std::move(strNodeName)),
          m_strBindAddress(std::move(strBindAddress)),
          m_u16DiscoveryPort(u16DiscoveryPort),
          m_u16ManagementPort(u16ManagementPort),
          m_strMulticastAddress(std::move(strMulticastAddress)),
          m_u16MulticastPort(u16MulticastPort),
          m_strBroadcastAddress(std::move(strBroadcastAddress)),
          m_durHeartbeatInterval(durHeartbeatInterval)
    {
        if (m_strNodeName.empty() || m_strBindAddress.empty())
        {
            throw std::invalid_argument("Node name and bind address must not be empty");
        }

        if (m_u16DiscoveryPort == 0 || m_u16ManagementPort == 0 || m_u16MulticastPort == 0)
        {
            throw std::invalid_argument("NodeAgent network ports must not be zero");
        }

        if (m_strMulticastAddress.empty() || m_strBroadcastAddress.empty())
        {
            throw std::invalid_argument("NodeAgent multicast and broadcast addresses are required");
        }

        if (m_durHeartbeatInterval.count() <= 0)
        {
            throw std::invalid_argument("NodeAgent heartbeat interval must be positive");
        }
    }

    const std::string& strNodeName() const noexcept
    {
        return m_strNodeName;
    }

    const std::string& strBindAddress() const noexcept
    {
        return m_strBindAddress;
    }

    std::uint16_t u16DiscoveryPort() const noexcept
    {
        return m_u16DiscoveryPort;
    }

    std::uint16_t u16ManagementPort() const noexcept
    {
        return m_u16ManagementPort;
    }

    const std::string& strMulticastAddress() const noexcept
    {
        return m_strMulticastAddress;
    }

    std::uint16_t u16MulticastPort() const noexcept
    {
        return m_u16MulticastPort;
    }

    const std::string& strBroadcastAddress() const noexcept
    {
        return m_strBroadcastAddress;
    }

    std::chrono::milliseconds durHeartbeatInterval() const noexcept
    {
        return m_durHeartbeatInterval;
    }

private:
    std::string               m_strNodeName;
    std::string               m_strBindAddress;
    std::uint16_t             m_u16DiscoveryPort;
    std::uint16_t             m_u16ManagementPort;
    std::string               m_strMulticastAddress;
    std::uint16_t             m_u16MulticastPort;
    std::string               m_strBroadcastAddress;
    std::chrono::milliseconds m_durHeartbeatInterval;
};
}

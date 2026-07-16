#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace tesla::node_agent
{
/** @brief Linux UDP组播收发通道，只运输原始认证数据报，不解释算法上下文。 */
class UdpMulticastChannel final
{
public:
    using DatagramHandler = std::function<void(
        const std::string& strSourceAddress,
        const protocol::ByteBuffer& vecDatagram
    )>;

    UdpMulticastChannel(
        std::string strBindAddress,
        std::string strMulticastAddress,
        std::uint16_t u16MulticastPort,
        DatagramHandler fnDatagramHandler
    );
    ~UdpMulticastChannel();

    UdpMulticastChannel(const UdpMulticastChannel&) = delete;
    UdpMulticastChannel& operator=(const UdpMulticastChannel&) = delete;

    void start();
    void stop() noexcept;
    bool bIsRunning() const noexcept;
    bool bSend(const protocol::ByteBuffer& vecDatagram) const noexcept;

private:
    void receiveLoop();

    std::string        m_strBindAddress;
    std::string        m_strMulticastAddress;
    std::uint16_t      m_u16MulticastPort;
    DatagramHandler    m_fnDatagramHandler;
    std::atomic<bool>  m_bRunning{false};
    std::atomic<int>   m_nSocket{-1};
    std::thread        m_thrReceiver;
};
}

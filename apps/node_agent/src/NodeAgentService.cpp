#include "tesla/node_agent/NodeAgentService.h"

#include <stdexcept>
#include <utility>

namespace tesla::node_agent
{
NodeAgentService::NodeAgentService(
    NodeAgentConfig cfgConfig,
    UdpMulticastChannel::DatagramHandler fnDatagramHandler
)
    : m_cfgConfig(std::move(cfgConfig)),
      m_fnExternalDatagramHandler(std::move(fnDatagramHandler)),
      m_srvManagement(
          m_cfgConfig.strBindAddress(),
          m_cfgConfig.u16ManagementPort(),
          m_cfgConfig.strNodeName(),
          [this]()
          {
              return std::make_pair(
                  m_bSenderRunning.load(),
                  m_bReceiverRunning.load()
              );
          }
      ),
      m_srvDiscovery(
          m_cfgConfig.strBindAddress(),
          m_cfgConfig.u16DiscoveryPort(),
          m_cfgConfig.strBroadcastAddress(),
          m_cfgConfig.strNodeName(),
          m_cfgConfig.u16ManagementPort(),
          m_cfgConfig.durHeartbeatInterval(),
          [this]()
          {
              return std::make_pair(
                  m_bSenderRunning.load(),
                  m_bReceiverRunning.load()
              );
          }
      ),
      m_chnMulticast(
          m_cfgConfig.strBindAddress(),
          m_cfgConfig.strMulticastAddress(),
          m_cfgConfig.u16MulticastPort(),
          [this](
              const std::string& strSourceAddress,
              const protocol::ByteBuffer& vecDatagram
          )
          {
              ++m_nReceivedDatagramCount;
              if (m_fnExternalDatagramHandler)
              {
                  m_fnExternalDatagramHandler(strSourceAddress, vecDatagram);
              }
          }
      )
{
}

NodeAgentService::~NodeAgentService()
{
    stop();
}

void NodeAgentService::start()
{
    bool bExpected = false;
    if (!m_bRunning.compare_exchange_strong(bExpected, true))
    {
        return;
    }

    try
    {
        // Receiver先加入组播，再对外宣告在线，避免发现后短暂丢失首批报文。
        m_chnMulticast.start();
        m_bReceiverRunning = true;
        m_srvManagement.start();
        m_srvDiscovery.start();
    }
    catch (...)
    {
        stop();
        throw;
    }
}

void NodeAgentService::stop() noexcept
{
    m_bRunning = false;
    m_srvDiscovery.stop();
    m_srvManagement.stop();
    m_bSenderRunning = false;
    m_bReceiverRunning = false;
    m_chnMulticast.stop();
}

bool NodeAgentService::bIsRunning() const noexcept
{
    return m_bRunning.load();
}

bool NodeAgentService::bSendAuthenticationDatagram(
    const protocol::ByteBuffer& vecDatagram
) const noexcept
{
    return m_bRunning.load() && m_chnMulticast.bSend(vecDatagram);
}

std::size_t NodeAgentService::nReceivedDatagramCount() const noexcept
{
    return m_nReceivedDatagramCount.load();
}

const NodeAgentConfig& NodeAgentService::cfgConfig() const noexcept
{
    return m_cfgConfig;
}
}

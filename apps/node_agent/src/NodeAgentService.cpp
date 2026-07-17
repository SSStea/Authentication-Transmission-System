#include "tesla/node_agent/NodeAgentService.h"

#include "tesla/node_agent/SystemTimeSynchronization.h"

#include <chrono>
#include <stdexcept>
#include <utility>

namespace tesla::node_agent
{
namespace
{
std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}
}

NodeAgentService::NodeAgentService(
    NodeAgentConfig cfgConfig,
    UdpMulticastChannel::DatagramHandler fnDatagramHandler,
    core::AuthenticationNodeRuntime::TimeSynchronizationProvider
        fnTimeSynchronizationProvider
)
    : m_cfgConfig(std::move(cfgConfig)),
      m_fnExternalDatagramHandler(std::move(fnDatagramHandler)),
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
              m_runAuthentication.bHandleDatagram(
                  strSourceAddress,
                  vecDatagram,
                  u64NowMilliseconds()
              );

              if (m_fnExternalDatagramHandler)
              {
                  m_fnExternalDatagramHandler(strSourceAddress, vecDatagram);
              }
          }
      ),
      m_srvManagement(
          m_cfgConfig.strBindAddress(),
          m_cfgConfig.u16ManagementPort(),
          m_cfgConfig.strNodeName(),
          [this]()
          {
              return std::make_pair(
                  m_runAuthentication.bSenderRunning(),
                  m_bReceiverRunning.load()
              );
          },
          [this](
              protocol::TcpClientRole roleClient,
              const protocol::NodeControlMessage& msgMessage
          )
          {
              return m_runAuthentication.msgHandleControl(
                  roleClient,
                  msgMessage
              );
          }
      ),
      m_runAuthentication(
          m_cfgConfig.strNodeName(),
          [this](const protocol::ByteBuffer& vecDatagram)
          {
              return m_chnMulticast.bSend(vecDatagram);
          },
          [this](const protocol::NodeControlMessage& msgMessage)
          {
              m_srvManagement.broadcastControlMessage(msgMessage);
          },
          fnTimeSynchronizationProvider
              ? std::move(fnTimeSynchronizationProvider)
              : core::AuthenticationNodeRuntime::TimeSynchronizationProvider(
                  []()
                  {
                      return SystemTimeSynchronization::stsQuery();
                  }
              )
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
                  m_runAuthentication.bSenderRunning(),
                  m_bReceiverRunning.load()
              );
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
    m_runAuthentication.stop();
    m_srvDiscovery.stop();
    m_srvManagement.stop();
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

bool NodeAgentService::bHasSenderAuthenticationContext() const
{
    return m_runAuthentication.bHasSenderContext();
}

std::optional<std::uint64_t>
NodeAgentService::optSenderAuthenticationChainId() const
{
    return m_runAuthentication.optSenderChainId();
}

std::size_t NodeAgentService::nReceiverAuthenticationContextCount() const
{
    return m_runAuthentication.nReceiverContextCount();
}

core::ReceiverAuthenticationContextLookupResult
NodeAgentService::resFindReceiverAuthenticationContext(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    return m_runAuthentication.resFindReceiverContext(
        strSourceIpAddress,
        u64ChainId
    );
}

const NodeAgentConfig& NodeAgentService::cfgConfig() const noexcept
{
    return m_cfgConfig;
}
}

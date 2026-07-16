#include "tesla/protocol/NodeDiscoveryMessage.h"

#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
void validateIdentifier(const std::string& strValue, const char* pName)
{
    constexpr std::size_t MAX_IDENTIFIER_LENGTH = 256;
    if (strValue.empty() || strValue.size() > MAX_IDENTIFIER_LENGTH)
    {
        throw std::invalid_argument(std::string(pName) + " must contain 1 to 256 bytes");
    }
}
}

DiscoveryRequestDetails::DiscoveryRequestDetails(std::string strRequestId)
    : m_strRequestId(std::move(strRequestId))
{
    validateIdentifier(m_strRequestId, "Discovery request ID");
}

const std::string& DiscoveryRequestDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

NodePresenceDetails::NodePresenceDetails(
    NodeDiscoveryMessageType typeMessage,
    std::string strRequestId,
    std::string strNodeName,
    NodeRole roleNode,
    std::uint16_t u16ManagementPort,
    bool bSenderRunning,
    bool bReceiverRunning,
    std::uint64_t u64TimestampMilliseconds
)
    : m_typeMessage(typeMessage),
      m_strRequestId(std::move(strRequestId)),
      m_strNodeName(std::move(strNodeName)),
      m_roleNode(roleNode),
      m_u16ManagementPort(u16ManagementPort),
      m_bSenderRunning(bSenderRunning),
      m_bReceiverRunning(bReceiverRunning),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds)
{
    if (m_typeMessage != NodeDiscoveryMessageType::NodeAnnouncement
        && m_typeMessage != NodeDiscoveryMessageType::Heartbeat)
    {
        throw std::invalid_argument("Node presence type must be announcement or heartbeat");
    }

    // 心跳没有对应扫描请求时允许空requestId，主动扫描响应则原样回显请求ID。
    if (!m_strRequestId.empty())
    {
        validateIdentifier(m_strRequestId, "Discovery request ID");
    }

    validateIdentifier(m_strNodeName, "Node name");
    if (m_u16ManagementPort == 0)
    {
        throw std::invalid_argument("Management port must not be zero");
    }
}

NodeDiscoveryMessageType NodePresenceDetails::typeMessage() const noexcept
{
    return m_typeMessage;
}

const std::string& NodePresenceDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& NodePresenceDetails::strNodeName() const noexcept
{
    return m_strNodeName;
}

NodeRole NodePresenceDetails::roleNode() const noexcept
{
    return m_roleNode;
}

std::uint16_t NodePresenceDetails::u16ManagementPort() const noexcept
{
    return m_u16ManagementPort;
}

bool NodePresenceDetails::bSenderRunning() const noexcept
{
    return m_bSenderRunning;
}

bool NodePresenceDetails::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

std::uint64_t NodePresenceDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

NodeDiscoveryMessage::NodeDiscoveryMessage(NodeDiscoveryMessageDetails varDetails)
    : m_varDetails(std::move(varDetails))
{
}

NodeDiscoveryMessageType NodeDiscoveryMessage::typeMessage() const noexcept
{
    if (std::holds_alternative<DiscoveryRequestDetails>(m_varDetails))
    {
        return NodeDiscoveryMessageType::DiscoverRequest;
    }

    return std::get<NodePresenceDetails>(m_varDetails).typeMessage();
}

const NodeDiscoveryMessageDetails& NodeDiscoveryMessage::varDetails() const noexcept
{
    return m_varDetails;
}
}

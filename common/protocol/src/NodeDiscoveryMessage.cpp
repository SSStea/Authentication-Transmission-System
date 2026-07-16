#include "tesla/protocol/NodeDiscoveryMessage.h"

#include <nlohmann/json.hpp>

#include <exception>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

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

const char* pTypeName(NodeDiscoveryMessageType typeMessage)
{
    switch (typeMessage)
    {
    case NodeDiscoveryMessageType::DiscoverRequest:
        return "DISCOVER_REQUEST";
    case NodeDiscoveryMessageType::NodeAnnouncement:
        return "NODE_ANNOUNCEMENT";
    case NodeDiscoveryMessageType::Heartbeat:
        return "HEARTBEAT";
    }

    throw std::invalid_argument("Unknown discovery message type");
}

const char* pRoleName(NodeRole roleNode)
{
    switch (roleNode)
    {
    case NodeRole::PcBroadcast:
        return "PC_BROADCAST";
    case NodeRole::Uav:
        return "UAV";
    case NodeRole::Attacker:
        return "ATTACKER";
    }

    throw std::invalid_argument("Unknown node role");
}

NodeRole roleParse(const std::string& strRole)
{
    if (strRole == "PC_BROADCAST")
    {
        return NodeRole::PcBroadcast;
    }

    if (strRole == "UAV")
    {
        return NodeRole::Uav;
    }

    if (strRole == "ATTACKER")
    {
        return NodeRole::Attacker;
    }

    throw std::invalid_argument("Unknown node role");
}

ProtocolDecodeError errCreate(const std::string& strMessage)
{
    return ProtocolDecodeError(
        ProtocolDecodeErrorCode::InvalidDiscoveryMessage,
        strMessage
    );
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

std::string NodeDiscoveryJsonCodec::strEncode(const NodeDiscoveryMessage& msgMessage)
{
    nlohmann::json jsnMessage;
    jsnMessage["type"] = pTypeName(msgMessage.typeMessage());

    if (msgMessage.typeMessage() == NodeDiscoveryMessageType::DiscoverRequest)
    {
        jsnMessage["requestId"] = std::get<DiscoveryRequestDetails>(
            msgMessage.varDetails()
        ).strRequestId();
        return jsnMessage.dump();
    }

    const NodePresenceDetails& detPresence = std::get<NodePresenceDetails>(
        msgMessage.varDetails()
    );
    jsnMessage["requestId"] = detPresence.strRequestId();
    jsnMessage["nodeName"] = detPresence.strNodeName();
    jsnMessage["nodeRole"] = pRoleName(detPresence.roleNode());
    jsnMessage["managementPort"] = detPresence.u16ManagementPort();
    jsnMessage["senderRunning"] = detPresence.bSenderRunning();
    jsnMessage["receiverRunning"] = detPresence.bReceiverRunning();
    jsnMessage["timestampMs"] = detPresence.u64TimestampMilliseconds();
    return jsnMessage.dump();
}

NodeDiscoveryDecodeResult NodeDiscoveryJsonCodec::resDecode(const std::string& strJson)
{
    try
    {
        // 一个UDP数据报只能表示一个完整对象，不接受数组或跨数据报拼接的JSON。
        const nlohmann::json jsnMessage = nlohmann::json::parse(strJson);
        if (!jsnMessage.is_object())
        {
            return errCreate("Discovery datagram must contain one JSON object");
        }

        const std::string strType = jsnMessage.at("type").get<std::string>();
        if (strType == "DISCOVER_REQUEST")
        {
            return NodeDiscoveryMessage(DiscoveryRequestDetails(
                jsnMessage.at("requestId").get<std::string>()
            ));
        }

        NodeDiscoveryMessageType typeMessage;
        if (strType == "NODE_ANNOUNCEMENT")
        {
            typeMessage = NodeDiscoveryMessageType::NodeAnnouncement;
        }
        else if (strType == "HEARTBEAT")
        {
            typeMessage = NodeDiscoveryMessageType::Heartbeat;
        }
        else
        {
            return errCreate("Discovery datagram has an unsupported message type");
        }

        const std::uint64_t u64ManagementPort =
            jsnMessage.at("managementPort").get<std::uint64_t>();
        if (u64ManagementPort == 0 || u64ManagementPort > 65535U)
        {
            return errCreate("Discovery management port is outside the valid range");
        }

        return NodeDiscoveryMessage(NodePresenceDetails(
            typeMessage,
            jsnMessage.at("requestId").get<std::string>(),
            jsnMessage.at("nodeName").get<std::string>(),
            roleParse(jsnMessage.at("nodeRole").get<std::string>()),
            static_cast<std::uint16_t>(u64ManagementPort),
            jsnMessage.at("senderRunning").get<bool>(),
            jsnMessage.at("receiverRunning").get<bool>(),
            jsnMessage.at("timestampMs").get<std::uint64_t>()
        ));
    }
    catch (const std::exception& exError)
    {
        return errCreate(std::string("Invalid discovery JSON: ") + exError.what());
    }
}
}

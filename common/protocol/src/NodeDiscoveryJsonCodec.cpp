#include "tesla/protocol/NodeDiscoveryJsonCodec.h"

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <variant>

namespace tesla::protocol
{
namespace
{
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

        const std::uint64_t u64ManagementPort = jsnMessage.at("managementPort").get<std::uint64_t>();
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

#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <string>
#include <variant>

namespace tesla::protocol
{
enum class NodeRole
{
    PcBroadcast,
    Uav,
    Attacker
};

enum class NodeDiscoveryMessageType
{
    DiscoverRequest,
    NodeAnnouncement,
    Heartbeat
};

/** @brief 扫描端发出的发现请求，只携带用于关联响应的请求ID。 */
class DiscoveryRequestDetails final
{
public:
    explicit DiscoveryRequestDetails(std::string strRequestId);

    const std::string& strRequestId() const noexcept;

private:
    std::string m_strRequestId;
};

/** @brief 节点公告和心跳共同携带的在线状态快照。 */
class NodePresenceDetails final
{
public:
    NodePresenceDetails(
        NodeDiscoveryMessageType typeMessage,
        std::string strRequestId,
        std::string strNodeName,
        NodeRole roleNode,
        std::uint16_t u16ManagementPort,
        bool bSenderRunning,
        bool bReceiverRunning,
        std::uint64_t u64TimestampMilliseconds
    );

    NodeDiscoveryMessageType typeMessage() const noexcept;
    const std::string& strRequestId() const noexcept;
    const std::string& strNodeName() const noexcept;
    NodeRole roleNode() const noexcept;
    std::uint16_t u16ManagementPort() const noexcept;
    bool bSenderRunning() const noexcept;
    bool bReceiverRunning() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;

private:
    NodeDiscoveryMessageType m_typeMessage;
    std::string              m_strRequestId;
    std::string              m_strNodeName;
    NodeRole                 m_roleNode;
    std::uint16_t            m_u16ManagementPort;
    bool                     m_bSenderRunning;
    bool                     m_bReceiverRunning;
    std::uint64_t            m_u64TimestampMilliseconds;
};

using NodeDiscoveryMessageDetails = std::variant<
    DiscoveryRequestDetails,
    NodePresenceDetails
>;

/** @brief UDP发现JSON数据报的强类型逻辑消息。 */
class NodeDiscoveryMessage final
{
public:
    explicit NodeDiscoveryMessage(NodeDiscoveryMessageDetails varDetails);

    NodeDiscoveryMessageType typeMessage() const noexcept;
    const NodeDiscoveryMessageDetails& varDetails() const noexcept;

private:
    NodeDiscoveryMessageDetails m_varDetails;
};

using NodeDiscoveryDecodeResult = std::variant<
    NodeDiscoveryMessage,
    ProtocolDecodeError
>;

/** @brief 编解码一个完整UDP JSON发现数据报，不添加换行或长度前缀。 */
class NodeDiscoveryJsonCodec final
{
public:
    static std::string strEncode(const NodeDiscoveryMessage& msgMessage);
    static NodeDiscoveryDecodeResult resDecode(const std::string& strJson);

private:
    NodeDiscoveryJsonCodec() = delete;
};
}

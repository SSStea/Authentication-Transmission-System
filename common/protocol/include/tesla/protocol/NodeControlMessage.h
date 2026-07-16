#pragma once

#include "tesla/protocol/AuthenticationControl.h"

#include <cstdint>
#include <string>
#include <variant>

namespace tesla::protocol
{
enum class TcpClientRole
{
    Manager,
    Monitor
};

enum class NodeControlMessageType
{
    ClientHello,
    Ping,
    Pong,
    StatusRequest,
    StatusResponse,
    SenderAuthenticationConfig,
    ReceiverAuthenticationContexts,
    AuthenticationConfigAcknowledgement,
    ErrorResponse
};

/** @brief 每条NodeAgent TCP连接的首个控制消息，用于锁定权限角色。 */
class ClientHelloControlDetails final
{
public:
    explicit ClientHelloControlDetails(TcpClientRole roleClient);

    TcpClientRole roleClient() const noexcept;

private:
    TcpClientRole m_roleClient;
};

/** @brief PING、PONG和STATUS_REQUEST共享的关联请求详情。 */
class RequestControlDetails final
{
public:
    RequestControlDetails(NodeControlMessageType typeMessage, std::string strRequestId);

    NodeControlMessageType typeMessage() const noexcept;
    const std::string& strRequestId() const noexcept;

private:
    NodeControlMessageType m_typeMessage;
    std::string            m_strRequestId;
};

/** @brief NodeAgent向管理端返回的最小阶段3状态快照。 */
class StatusResponseControlDetails final
{
public:
    StatusResponseControlDetails(
        std::string strRequestId,
        std::string strNodeName,
        bool bSenderRunning,
        bool bReceiverRunning,
        std::uint64_t u64TimestampMilliseconds
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strNodeName() const noexcept;
    bool bSenderRunning() const noexcept;
    bool bReceiverRunning() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;

private:
    std::string   m_strRequestId;
    std::string   m_strNodeName;
    bool          m_bSenderRunning;
    bool          m_bReceiverRunning;
    std::uint64_t m_u64TimestampMilliseconds;
};

/** @brief 可回传给客户端的稳定错误码和可读说明。 */
class ErrorResponseControlDetails final
{
public:
    ErrorResponseControlDetails(
        std::string strRequestId,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string m_strRequestId;
    std::string m_strErrorCode;
    std::string m_strMessage;
};

using NodeControlMessageDetails = std::variant<
    ClientHelloControlDetails,
    RequestControlDetails,
    StatusResponseControlDetails,
    SenderAuthenticationConfigControlDetails,
    ReceiverAuthenticationContextsControlDetails,
    AuthenticationConfigAcknowledgementControlDetails,
    ErrorResponseControlDetails
>;

/** @brief TCP JSON控制帧的强类型消息，模式专用字段保存在variant详情中。 */
class NodeControlMessage final
{
public:
    explicit NodeControlMessage(NodeControlMessageDetails varDetails);

    NodeControlMessageType typeMessage() const noexcept;
    const NodeControlMessageDetails& varDetails() const noexcept;

private:
    NodeControlMessageDetails m_varDetails;
};
}

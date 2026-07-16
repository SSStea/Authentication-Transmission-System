#include "tesla/protocol/NodeControlMessage.h"

#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
// 在消息对象创建时统一限制控制面文本长度，网络服务无需重复做同类检查。
void validateText(const std::string& strValue, const char* pName, bool bAllowEmpty = false)
{
    constexpr std::size_t MAX_TEXT_LENGTH = 1024;
    if ((!bAllowEmpty && strValue.empty()) || strValue.size() > MAX_TEXT_LENGTH)
    {
        throw std::invalid_argument(std::string(pName) + " has an invalid length");
    }
}
}

ClientHelloControlDetails::ClientHelloControlDetails(TcpClientRole roleClient)
    : m_roleClient(roleClient)
{
}

TcpClientRole ClientHelloControlDetails::roleClient() const noexcept
{
    return m_roleClient;
}

RequestControlDetails::RequestControlDetails(
    NodeControlMessageType typeMessage,
    std::string strRequestId
)
    : m_typeMessage(typeMessage),
      m_strRequestId(std::move(strRequestId))
{
    if (m_typeMessage != NodeControlMessageType::Ping
        && m_typeMessage != NodeControlMessageType::Pong
        && m_typeMessage != NodeControlMessageType::StatusRequest)
    {
        throw std::invalid_argument("Request control details contain an unsupported type");
    }

    validateText(m_strRequestId, "Control request ID");
}

NodeControlMessageType RequestControlDetails::typeMessage() const noexcept
{
    return m_typeMessage;
}

const std::string& RequestControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

StatusResponseControlDetails::StatusResponseControlDetails(
    std::string strRequestId,
    std::string strNodeName,
    bool bSenderRunning,
    bool bReceiverRunning,
    std::uint64_t u64TimestampMilliseconds
)
    : m_strRequestId(std::move(strRequestId)),
      m_strNodeName(std::move(strNodeName)),
      m_bSenderRunning(bSenderRunning),
      m_bReceiverRunning(bReceiverRunning),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds)
{
    validateText(m_strRequestId, "Control request ID");
    validateText(m_strNodeName, "Node name");
}

const std::string& StatusResponseControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& StatusResponseControlDetails::strNodeName() const noexcept
{
    return m_strNodeName;
}

bool StatusResponseControlDetails::bSenderRunning() const noexcept
{
    return m_bSenderRunning;
}

bool StatusResponseControlDetails::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

std::uint64_t StatusResponseControlDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

ErrorResponseControlDetails::ErrorResponseControlDetails(
    std::string strRequestId,
    std::string strErrorCode,
    std::string strMessage
)
    : m_strRequestId(std::move(strRequestId)),
      m_strErrorCode(std::move(strErrorCode)),
      m_strMessage(std::move(strMessage))
{
    validateText(m_strRequestId, "Control request ID", true);
    validateText(m_strErrorCode, "Control error code");
    validateText(m_strMessage, "Control error message");
}

const std::string& ErrorResponseControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& ErrorResponseControlDetails::strErrorCode() const noexcept
{
    return m_strErrorCode;
}

const std::string& ErrorResponseControlDetails::strMessage() const noexcept
{
    return m_strMessage;
}

NodeControlMessage::NodeControlMessage(NodeControlMessageDetails varDetails)
    : m_varDetails(std::move(varDetails))
{
}

NodeControlMessageType NodeControlMessage::typeMessage() const noexcept
{
    if (std::holds_alternative<ClientHelloControlDetails>(m_varDetails))
    {
        return NodeControlMessageType::ClientHello;
    }

    if (std::holds_alternative<RequestControlDetails>(m_varDetails))
    {
        return std::get<RequestControlDetails>(m_varDetails).typeMessage();
    }

    if (std::holds_alternative<StatusResponseControlDetails>(m_varDetails))
    {
        return NodeControlMessageType::StatusResponse;
    }

    return NodeControlMessageType::ErrorResponse;
}

const NodeControlMessageDetails& NodeControlMessage::varDetails() const noexcept
{
    return m_varDetails;
}
}

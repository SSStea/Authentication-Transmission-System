#include "tesla/protocol/AttackControl.h"

#include <nlohmann/json.hpp>

#include <exception>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
const char* pTypeName(AttackControlMessageType typeMessage)
{
    switch (typeMessage)
    {
    case AttackControlMessageType::ClientHello:
        return "ATTACK_CLIENT_HELLO";
    case AttackControlMessageType::Ping:
        return "ATTACK_PING";
    case AttackControlMessageType::Pong:
        return "ATTACK_PONG";
    case AttackControlMessageType::StatusRequest:
        return "ATTACK_STATUS_REQUEST";
    case AttackControlMessageType::StatusResponse:
        return "ATTACK_STATUS_RESPONSE";
    case AttackControlMessageType::ErrorResponse:
        return "ATTACK_ERROR";
    }

    throw std::invalid_argument("Unknown attack control message type");
}

ProtocolDecodeError errCreate(const std::string& strMessage)
{
    return ProtocolDecodeError(
        ProtocolDecodeErrorCode::InvalidControlMessage,
        strMessage
    );
}
}

AttackClientHelloDetails::AttackClientHelloDetails(std::string strClientName)
    : m_strClientName(std::move(strClientName))
{
    if (m_strClientName.empty())
    {
        throw std::invalid_argument("Attack control client name must not be empty");
    }
}

const std::string& AttackClientHelloDetails::strClientName() const noexcept
{
    return m_strClientName;
}

AttackRequestControlDetails::AttackRequestControlDetails(
    AttackControlMessageType typeMessage,
    std::string strRequestId
)
    : m_typeMessage(typeMessage),
      m_strRequestId(std::move(strRequestId))
{
    if (m_typeMessage != AttackControlMessageType::Ping
        && m_typeMessage != AttackControlMessageType::Pong
        && m_typeMessage != AttackControlMessageType::StatusRequest)
    {
        throw std::invalid_argument("Attack request details require a request message type");
    }

    if (m_strRequestId.empty())
    {
        throw std::invalid_argument("Attack control request ID must not be empty");
    }
}

AttackControlMessageType AttackRequestControlDetails::typeMessage() const noexcept
{
    return m_typeMessage;
}

const std::string& AttackRequestControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

AttackStatusControlDetails::AttackStatusControlDetails(
    std::string strRequestId,
    std::string strNodeName,
    bool bMulticastListening,
    bool bAttackRunning,
    std::uint64_t u64TimestampMilliseconds
)
    : m_strRequestId(std::move(strRequestId)),
      m_strNodeName(std::move(strNodeName)),
      m_bMulticastListening(bMulticastListening),
      m_bAttackRunning(bAttackRunning),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds)
{
    if (m_strRequestId.empty() || m_strNodeName.empty())
    {
        throw std::invalid_argument(
            "Attack status requires non-empty request and node names"
        );
    }
}

const std::string& AttackStatusControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& AttackStatusControlDetails::strNodeName() const noexcept
{
    return m_strNodeName;
}

bool AttackStatusControlDetails::bMulticastListening() const noexcept
{
    return m_bMulticastListening;
}

bool AttackStatusControlDetails::bAttackRunning() const noexcept
{
    return m_bAttackRunning;
}

std::uint64_t AttackStatusControlDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

AttackErrorControlDetails::AttackErrorControlDetails(
    std::string strRequestId,
    std::string strErrorCode,
    std::string strMessage
)
    : m_strRequestId(std::move(strRequestId)),
      m_strErrorCode(std::move(strErrorCode)),
      m_strMessage(std::move(strMessage))
{
    if (m_strErrorCode.empty() || m_strMessage.empty())
    {
        throw std::invalid_argument(
            "Attack control error code and message must not be empty"
        );
    }
}

const std::string& AttackErrorControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& AttackErrorControlDetails::strErrorCode() const noexcept
{
    return m_strErrorCode;
}

const std::string& AttackErrorControlDetails::strMessage() const noexcept
{
    return m_strMessage;
}

AttackControlMessage::AttackControlMessage(AttackControlMessageDetails varDetails)
    : m_varDetails(std::move(varDetails))
{
}

AttackControlMessageType AttackControlMessage::typeMessage() const noexcept
{
    if (std::holds_alternative<AttackClientHelloDetails>(m_varDetails))
    {
        return AttackControlMessageType::ClientHello;
    }

    if (std::holds_alternative<AttackRequestControlDetails>(m_varDetails))
    {
        return std::get<AttackRequestControlDetails>(m_varDetails).typeMessage();
    }

    if (std::holds_alternative<AttackStatusControlDetails>(m_varDetails))
    {
        return AttackControlMessageType::StatusResponse;
    }

    return AttackControlMessageType::ErrorResponse;
}

const AttackControlMessageDetails& AttackControlMessage::varDetails() const noexcept
{
    return m_varDetails;
}

std::string AttackControlJsonCodec::strEncode(const AttackControlMessage& msgMessage)
{
    nlohmann::json jsnMessage;
    jsnMessage["type"] = pTypeName(msgMessage.typeMessage());

    if (msgMessage.typeMessage() == AttackControlMessageType::ClientHello)
    {
        jsnMessage["clientName"] = std::get<AttackClientHelloDetails>(
            msgMessage.varDetails()
        ).strClientName();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::Ping
        || msgMessage.typeMessage() == AttackControlMessageType::Pong
        || msgMessage.typeMessage() == AttackControlMessageType::StatusRequest)
    {
        jsnMessage["requestId"] = std::get<AttackRequestControlDetails>(
            msgMessage.varDetails()
        ).strRequestId();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::StatusResponse)
    {
        const AttackStatusControlDetails& detStatus =
            std::get<AttackStatusControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detStatus.strRequestId();
        jsnMessage["nodeName"] = detStatus.strNodeName();
        jsnMessage["multicastListening"] = detStatus.bMulticastListening();
        jsnMessage["attackRunning"] = detStatus.bAttackRunning();
        jsnMessage["timestampMs"] = detStatus.u64TimestampMilliseconds();
    }
    else
    {
        const AttackErrorControlDetails& detError =
            std::get<AttackErrorControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detError.strRequestId();
        jsnMessage["errorCode"] = detError.strErrorCode();
        jsnMessage["message"] = detError.strMessage();
    }

    return jsnMessage.dump();
}

AttackControlDecodeResult AttackControlJsonCodec::resDecode(
    const std::string& strJson
)
{
    try
    {
        const nlohmann::json jsnMessage = nlohmann::json::parse(strJson);
        if (!jsnMessage.is_object())
        {
            return errCreate("Attack control frame must contain one JSON object");
        }

        const std::string strType = jsnMessage.at("type").get<std::string>();
        if (strType == "ATTACK_CLIENT_HELLO")
        {
            return AttackControlMessage(AttackClientHelloDetails(
                jsnMessage.at("clientName").get<std::string>()
            ));
        }

        if (strType == "ATTACK_PING"
            || strType == "ATTACK_PONG"
            || strType == "ATTACK_STATUS_REQUEST")
        {
            AttackControlMessageType typeMessage =
                AttackControlMessageType::StatusRequest;
            if (strType == "ATTACK_PING")
            {
                typeMessage = AttackControlMessageType::Ping;
            }
            else if (strType == "ATTACK_PONG")
            {
                typeMessage = AttackControlMessageType::Pong;
            }

            return AttackControlMessage(AttackRequestControlDetails(
                typeMessage,
                jsnMessage.at("requestId").get<std::string>()
            ));
        }

        if (strType == "ATTACK_STATUS_RESPONSE")
        {
            return AttackControlMessage(AttackStatusControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("nodeName").get<std::string>(),
                jsnMessage.at("multicastListening").get<bool>(),
                jsnMessage.at("attackRunning").get<bool>(),
                jsnMessage.at("timestampMs").get<std::uint64_t>()
            ));
        }

        if (strType == "ATTACK_ERROR")
        {
            return AttackControlMessage(AttackErrorControlDetails(
                jsnMessage.value("requestId", std::string()),
                jsnMessage.at("errorCode").get<std::string>(),
                jsnMessage.at("message").get<std::string>()
            ));
        }

        return errCreate("Attack control frame has an unsupported message type");
    }
    catch (const std::exception& exError)
    {
        return errCreate(std::string("Invalid attack control JSON: ") + exError.what());
    }
}
}

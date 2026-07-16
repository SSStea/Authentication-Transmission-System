#include "tesla/protocol/NodeControlJsonCodec.h"

#include <nlohmann/json.hpp>

#include <exception>
#include <stdexcept>
#include <string>

namespace tesla::protocol
{
namespace
{
const char* pTypeName(NodeControlMessageType typeMessage)
{
    switch (typeMessage)
    {
    case NodeControlMessageType::ClientHello:
        return "CLIENT_HELLO";
    case NodeControlMessageType::Ping:
        return "PING";
    case NodeControlMessageType::Pong:
        return "PONG";
    case NodeControlMessageType::StatusRequest:
        return "STATUS_REQUEST";
    case NodeControlMessageType::StatusResponse:
        return "STATUS_RESPONSE";
    case NodeControlMessageType::ErrorResponse:
        return "ERROR";
    }

    throw std::invalid_argument("Unknown node control message type");
}

const char* pRoleName(TcpClientRole roleClient)
{
    return roleClient == TcpClientRole::Manager ? "MANAGER" : "MONITOR";
}

TcpClientRole roleParse(const std::string& strRole)
{
    if (strRole == "MANAGER")
    {
        return TcpClientRole::Manager;
    }

    if (strRole == "MONITOR")
    {
        return TcpClientRole::Monitor;
    }

    throw std::invalid_argument("Unknown TCP client role");
}

ProtocolDecodeError errCreate(const std::string& strMessage)
{
    return ProtocolDecodeError(
        ProtocolDecodeErrorCode::InvalidControlMessage,
        strMessage
    );
}
}

std::string NodeControlJsonCodec::strEncode(const NodeControlMessage& msgMessage)
{
    nlohmann::json jsnMessage;
    jsnMessage["type"] = pTypeName(msgMessage.typeMessage());

    if (msgMessage.typeMessage() == NodeControlMessageType::ClientHello)
    {
        jsnMessage["role"] = pRoleName(std::get<ClientHelloControlDetails>(
            msgMessage.varDetails()
        ).roleClient());
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::Ping
        || msgMessage.typeMessage() == NodeControlMessageType::Pong
        || msgMessage.typeMessage() == NodeControlMessageType::StatusRequest)
    {
        jsnMessage["requestId"] = std::get<RequestControlDetails>(
            msgMessage.varDetails()
        ).strRequestId();
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::StatusResponse)
    {
        const StatusResponseControlDetails& detStatus =
            std::get<StatusResponseControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detStatus.strRequestId();
        jsnMessage["nodeName"] = detStatus.strNodeName();
        jsnMessage["senderRunning"] = detStatus.bSenderRunning();
        jsnMessage["receiverRunning"] = detStatus.bReceiverRunning();
        jsnMessage["timestampMs"] = detStatus.u64TimestampMilliseconds();
    }
    else
    {
        const ErrorResponseControlDetails& detError =
            std::get<ErrorResponseControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detError.strRequestId();
        jsnMessage["errorCode"] = detError.strErrorCode();
        jsnMessage["message"] = detError.strMessage();
    }

    return jsnMessage.dump();
}

NodeControlDecodeResult NodeControlJsonCodec::resDecode(const std::string& strJson)
{
    try
    {
        // JSON库负责语法和UTF-8解析，本Codec继续校验消息类型及每个必需字段的类型。
        const nlohmann::json jsnMessage = nlohmann::json::parse(strJson);
        if (!jsnMessage.is_object())
        {
            return errCreate("Control frame must contain one JSON object");
        }

        const std::string strType = jsnMessage.at("type").get<std::string>();
        if (strType == "CLIENT_HELLO")
        {
            return NodeControlMessage(ClientHelloControlDetails(
                roleParse(jsnMessage.at("role").get<std::string>())
            ));
        }

        if (strType == "PING" || strType == "PONG" || strType == "STATUS_REQUEST")
        {
            NodeControlMessageType typeMessage = NodeControlMessageType::StatusRequest;
            if (strType == "PING")
            {
                typeMessage = NodeControlMessageType::Ping;
            }
            else if (strType == "PONG")
            {
                typeMessage = NodeControlMessageType::Pong;
            }

            return NodeControlMessage(RequestControlDetails(
                typeMessage,
                jsnMessage.at("requestId").get<std::string>()
            ));
        }

        if (strType == "STATUS_RESPONSE")
        {
            return NodeControlMessage(StatusResponseControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("nodeName").get<std::string>(),
                jsnMessage.at("senderRunning").get<bool>(),
                jsnMessage.at("receiverRunning").get<bool>(),
                jsnMessage.at("timestampMs").get<std::uint64_t>()
            ));
        }

        if (strType == "ERROR")
        {
            return NodeControlMessage(ErrorResponseControlDetails(
                jsnMessage.value("requestId", std::string()),
                jsnMessage.at("errorCode").get<std::string>(),
                jsnMessage.at("message").get<std::string>()
            ));
        }

        return errCreate("Control frame has an unsupported message type");
    }
    catch (const std::exception& exError)
    {
        return errCreate(std::string("Invalid control JSON: ") + exError.what());
    }
}
}

#include "tesla/protocol/NodeControlJsonCodec.h"

#include <nlohmann/json.hpp>

#include <exception>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

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
    case NodeControlMessageType::SenderAuthenticationConfig:
        return "SENDER_AUTH_CONFIG";
    case NodeControlMessageType::ReceiverAuthenticationContexts:
        return "RECEIVER_AUTH_CONTEXTS";
    case NodeControlMessageType::AuthenticationConfigAcknowledgement:
        return "AUTH_CONFIG_ACK";
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

const char* pAlgorithmName(AuthenticationCryptoAlgorithm algAlgorithm)
{
    switch (algAlgorithm)
    {
    case AuthenticationCryptoAlgorithm::Sha256:
        return "SHA256";
    case AuthenticationCryptoAlgorithm::Sm3:
        return "SM3";
    case AuthenticationCryptoAlgorithm::Sha3_256:
        return "SHA3_256";
    }

    throw std::invalid_argument("Unknown authentication crypto algorithm");
}

AuthenticationCryptoAlgorithm algParse(const std::string& strAlgorithm)
{
    if (strAlgorithm == "SHA256")
    {
        return AuthenticationCryptoAlgorithm::Sha256;
    }

    if (strAlgorithm == "SM3")
    {
        return AuthenticationCryptoAlgorithm::Sm3;
    }

    if (strAlgorithm == "SHA3_256")
    {
        return AuthenticationCryptoAlgorithm::Sha3_256;
    }

    throw std::invalid_argument("Unknown authentication crypto algorithm");
}

const char* pAuthenticationModeName(UdpAuthenticationMode modeAuthentication)
{
    return modeAuthentication == UdpAuthenticationMode::Native
        ? "NATIVE"
        : "IMPROVED";
}

UdpAuthenticationMode modeAuthenticationParse(const std::string& strMode)
{
    if (strMode == "NATIVE")
    {
        return UdpAuthenticationMode::Native;
    }

    if (strMode == "IMPROVED")
    {
        return UdpAuthenticationMode::Improved;
    }

    throw std::invalid_argument("Unknown TESLA authentication mode");
}

const char* pConfigTargetName(AuthenticationConfigTarget targetConfig)
{
    return targetConfig == AuthenticationConfigTarget::Sender
        ? "SENDER"
        : "RECEIVER";
}

AuthenticationConfigTarget targetConfigParse(const std::string& strTarget)
{
    if (strTarget == "SENDER")
    {
        return AuthenticationConfigTarget::Sender;
    }

    if (strTarget == "RECEIVER")
    {
        return AuthenticationConfigTarget::Receiver;
    }

    throw std::invalid_argument("Unknown authentication configuration target");
}

nlohmann::json jsnEncodeRoundParameters(
    const AuthenticationRoundControlParameters& prmParameters
)
{
    nlohmann::json jsnParameters{
        {"cryptoAlgorithm", pAlgorithmName(prmParameters.algCryptoAlgorithm())},
        {"authMode", pAuthenticationModeName(prmParameters.modeAuthentication())},
        {"totalPacketCount", prmParameters.u32TotalPacketCount()},
        {"packetsPerInterval", prmParameters.u32PacketsPerInterval()},
        {"disclosureDelay", prmParameters.u32DisclosureDelay()},
        {"intervalMs", prmParameters.u32IntervalMilliseconds()},
        {"startTimestampMs", prmParameters.u64StartTimestampMilliseconds()},
        {"chainLength", prmParameters.u32ChainLength()}
    };

    if (prmParameters.optImprovedParameters().has_value())
    {
        const ImprovedTeslaControlParameters& prmImproved =
            prmParameters.optImprovedParameters().value();
        jsnParameters["improvedTesla"] = {
            {"groupSize", prmImproved.u32GroupSize()},
            {"detectionThreshold", prmImproved.u32DetectionThreshold()}
        };
    }

    return jsnParameters;
}

AuthenticationRoundControlParameters prmDecodeRoundParameters(
    const nlohmann::json& jsnParameters
)
{
    const UdpAuthenticationMode modeAuthentication = modeAuthenticationParse(
        jsnParameters.at("authMode").get<std::string>()
    );
    std::optional<ImprovedTeslaControlParameters> optImprovedParameters;

    if (modeAuthentication == UdpAuthenticationMode::Improved)
    {
        const nlohmann::json& jsnImproved = jsnParameters.at("improvedTesla");
        optImprovedParameters.emplace(
            jsnImproved.at("groupSize").get<std::uint32_t>(),
            jsnImproved.at("detectionThreshold").get<std::uint32_t>()
        );
    }
    else if (jsnParameters.contains("improvedTesla"))
    {
        throw std::invalid_argument(
            "Native TESLA control must not contain improvedTesla"
        );
    }

    return AuthenticationRoundControlParameters(
        algParse(jsnParameters.at("cryptoAlgorithm").get<std::string>()),
        modeAuthentication,
        jsnParameters.at("totalPacketCount").get<std::uint32_t>(),
        jsnParameters.at("packetsPerInterval").get<std::uint32_t>(),
        jsnParameters.at("disclosureDelay").get<std::uint32_t>(),
        jsnParameters.at("intervalMs").get<std::uint32_t>(),
        jsnParameters.at("startTimestampMs").get<std::uint64_t>(),
        jsnParameters.at("chainLength").get<std::uint32_t>(),
        std::move(optImprovedParameters)
    );
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
    else if (msgMessage.typeMessage() == NodeControlMessageType::SenderAuthenticationConfig)
    {
        const SenderAuthenticationConfigControlDetails& detConfig =
            std::get<SenderAuthenticationConfigControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["requestId"] = detConfig.strRequestId();
        jsnMessage["senderId"] = detConfig.strSenderId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detConfig.u64ChainId()
        );
        jsnMessage["chainSeed"] = AuthenticationControlValueCodec::strEncodeBlock(
            detConfig.arrChainSeed()
        );
        jsnMessage["commitmentKey"] = AuthenticationControlValueCodec::strEncodeBlock(
            detConfig.arrCommitmentKey()
        );
        jsnMessage["round"] = jsnEncodeRoundParameters(detConfig.prmRoundParameters());
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::ReceiverAuthenticationContexts)
    {
        const ReceiverAuthenticationContextsControlDetails& detConfig =
            std::get<ReceiverAuthenticationContextsControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["requestId"] = detConfig.strRequestId();
        jsnMessage["contexts"] = nlohmann::json::array();

        for (const ReceiverAuthenticationContextControlDetails& detContext
            : detConfig.vecContexts())
        {
            jsnMessage["contexts"].push_back({
                {"senderId", detContext.strSenderId()},
                {"senderIp", detContext.strSenderIpAddress()},
                {
                    "chainId",
                    AuthenticationControlValueCodec::strEncodeChainId(
                        detContext.u64ChainId()
                    )
                },
                {
                    "commitmentKey",
                    AuthenticationControlValueCodec::strEncodeBlock(
                        detContext.arrCommitmentKey()
                    )
                },
                {"round", jsnEncodeRoundParameters(detContext.prmRoundParameters())}
            });
        }
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::AuthenticationConfigAcknowledgement)
    {
        const AuthenticationConfigAcknowledgementControlDetails& detAcknowledgement =
            std::get<AuthenticationConfigAcknowledgementControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["requestId"] = detAcknowledgement.strRequestId();
        jsnMessage["target"] = pConfigTargetName(detAcknowledgement.targetConfig());
        jsnMessage["accepted"] = detAcknowledgement.bAccepted();
        jsnMessage["errorCode"] = detAcknowledgement.strErrorCode();
        jsnMessage["message"] = detAcknowledgement.strMessage();
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

        if (strType == "SENDER_AUTH_CONFIG")
        {
            return NodeControlMessage(SenderAuthenticationConfigControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("senderId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                AuthenticationControlValueCodec::arrDecodeBlock(
                    jsnMessage.at("chainSeed").get<std::string>()
                ),
                AuthenticationControlValueCodec::arrDecodeBlock(
                    jsnMessage.at("commitmentKey").get<std::string>()
                ),
                prmDecodeRoundParameters(jsnMessage.at("round"))
            ));
        }

        if (strType == "RECEIVER_AUTH_CONTEXTS")
        {
            const nlohmann::json& jsnContexts = jsnMessage.at("contexts");
            if (!jsnContexts.is_array())
            {
                throw std::invalid_argument(
                    "Receiver authentication contexts must be a JSON array"
                );
            }

            std::vector<ReceiverAuthenticationContextControlDetails> vecContexts;
            vecContexts.reserve(jsnContexts.size());
            for (const nlohmann::json& jsnContext : jsnContexts)
            {
                // Receiver配置出现种子字段通常意味着CA分发目标写错，必须显式拒绝而非静默忽略。
                if (jsnContext.contains("chainSeed"))
                {
                    throw std::invalid_argument(
                        "Receiver authentication context must not contain a chain seed"
                    );
                }

                vecContexts.emplace_back(
                    jsnContext.at("senderId").get<std::string>(),
                    jsnContext.at("senderIp").get<std::string>(),
                    AuthenticationControlValueCodec::u64DecodeChainId(
                        jsnContext.at("chainId").get<std::string>()
                    ),
                    AuthenticationControlValueCodec::arrDecodeBlock(
                        jsnContext.at("commitmentKey").get<std::string>()
                    ),
                    prmDecodeRoundParameters(jsnContext.at("round"))
                );
            }

            return NodeControlMessage(ReceiverAuthenticationContextsControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                std::move(vecContexts)
            ));
        }

        if (strType == "AUTH_CONFIG_ACK")
        {
            return NodeControlMessage(
                AuthenticationConfigAcknowledgementControlDetails(
                    jsnMessage.at("requestId").get<std::string>(),
                    targetConfigParse(jsnMessage.at("target").get<std::string>()),
                    jsnMessage.at("accepted").get<bool>(),
                    jsnMessage.at("errorCode").get<std::string>(),
                    jsnMessage.at("message").get<std::string>()
                )
            );
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

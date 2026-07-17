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
    case NodeControlMessageType::TextPayloadConfig:
        return "TEXT_PAYLOAD";
    case NodeControlMessageType::FileUploadBegin:
        return "FILE_UPLOAD_BEGIN";
    case NodeControlMessageType::FileUploadEnd:
        return "FILE_UPLOAD_END";
    case NodeControlMessageType::AuthenticationConfigAcknowledgement:
        return "AUTH_CONFIG_ACK";
    case NodeControlMessageType::RoundStart:
        return "ROUND_START";
    case NodeControlMessageType::RoundPause:
        return "ROUND_PAUSE";
    case NodeControlMessageType::RoundResume:
        return "ROUND_RESUME";
    case NodeControlMessageType::RoundStop:
        return "ROUND_STOP";
    case NodeControlMessageType::RoundCommandAcknowledgement:
        return "ROUND_COMMAND_ACK";
    case NodeControlMessageType::RoundResult:
        return "ROUND_RESULT";
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
    switch (targetConfig)
    {
    case AuthenticationConfigTarget::Sender:
        return "SENDER";
    case AuthenticationConfigTarget::Receiver:
        return "RECEIVER";
    case AuthenticationConfigTarget::TextPayload:
        return "TEXT_PAYLOAD";
    case AuthenticationConfigTarget::FilePayload:
        return "FILE_PAYLOAD";
    }

    throw std::invalid_argument("Unknown authentication configuration target");
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

    if (strTarget == "TEXT_PAYLOAD")
    {
        return AuthenticationConfigTarget::TextPayload;
    }

    if (strTarget == "FILE_PAYLOAD")
    {
        return AuthenticationConfigTarget::FilePayload;
    }

    throw std::invalid_argument("Unknown authentication configuration target");
}

const char* pPayloadModeName(AuthenticationPayloadMode modePayload)
{
    return modePayload == AuthenticationPayloadMode::Text ? "TEXT" : "FILE";
}

AuthenticationPayloadMode modePayloadParse(const std::string& strMode)
{
    if (strMode == "TEXT")
    {
        return AuthenticationPayloadMode::Text;
    }

    if (strMode == "FILE")
    {
        return AuthenticationPayloadMode::File;
    }

    throw std::invalid_argument("Unknown authentication payload mode");
}

const char* pRoundCommandName(AuthenticationRoundCommand cmdCommand)
{
    switch (cmdCommand)
    {
    case AuthenticationRoundCommand::Start:
        return "START";
    case AuthenticationRoundCommand::Pause:
        return "PAUSE";
    case AuthenticationRoundCommand::Resume:
        return "RESUME";
    case AuthenticationRoundCommand::Stop:
        return "STOP";
    }

    throw std::invalid_argument("Unknown authentication round command");
}

AuthenticationRoundCommand cmdRoundParse(const std::string& strCommand)
{
    if (strCommand == "START")
    {
        return AuthenticationRoundCommand::Start;
    }

    if (strCommand == "PAUSE")
    {
        return AuthenticationRoundCommand::Pause;
    }

    if (strCommand == "RESUME")
    {
        return AuthenticationRoundCommand::Resume;
    }

    if (strCommand == "STOP")
    {
        return AuthenticationRoundCommand::Stop;
    }

    throw std::invalid_argument("Unknown authentication round command");
}

AuthenticationRoundCommand cmdRoundFromType(const std::string& strType)
{
    if (strType == "ROUND_START")
    {
        return AuthenticationRoundCommand::Start;
    }

    if (strType == "ROUND_PAUSE")
    {
        return AuthenticationRoundCommand::Pause;
    }

    if (strType == "ROUND_RESUME")
    {
        return AuthenticationRoundCommand::Resume;
    }

    if (strType == "ROUND_STOP")
    {
        return AuthenticationRoundCommand::Stop;
    }

    throw std::invalid_argument("Unknown authentication round command type");
}

const char* pResultRoleName(AuthenticationRoundResultRole roleResult)
{
    return roleResult == AuthenticationRoundResultRole::Sender
        ? "SENDER"
        : "RECEIVER";
}

AuthenticationRoundResultRole roleResultParse(const std::string& strRole)
{
    if (strRole == "SENDER")
    {
        return AuthenticationRoundResultRole::Sender;
    }

    if (strRole == "RECEIVER")
    {
        return AuthenticationRoundResultRole::Receiver;
    }

    throw std::invalid_argument("Unknown authentication result role");
}

const char* pResultStatusName(AuthenticationRoundResultStatus statusResult)
{
    switch (statusResult)
    {
    case AuthenticationRoundResultStatus::Completed:
        return "COMPLETED";
    case AuthenticationRoundResultStatus::AuthenticationFailed:
        return "AUTHENTICATION_FAILED";
    case AuthenticationRoundResultStatus::VerificationTimeout:
        return "VERIFICATION_TIMEOUT";
    case AuthenticationRoundResultStatus::InvalidSchedulingOverrun:
        return "INVALID_SCHEDULING_OVERRUN";
    case AuthenticationRoundResultStatus::Stopped:
        return "STOPPED";
    case AuthenticationRoundResultStatus::ProtocolIncomplete:
        return "PROTOCOL_INCOMPLETE";
    case AuthenticationRoundResultStatus::TimeUnsynchronized:
        return "TIME_UNSYNCHRONIZED";
    }

    throw std::invalid_argument("Unknown authentication round result status");
}

AuthenticationRoundResultStatus statusResultParse(const std::string& strStatus)
{
    if (strStatus == "COMPLETED")
    {
        return AuthenticationRoundResultStatus::Completed;
    }

    if (strStatus == "AUTHENTICATION_FAILED")
    {
        return AuthenticationRoundResultStatus::AuthenticationFailed;
    }

    if (strStatus == "VERIFICATION_TIMEOUT")
    {
        return AuthenticationRoundResultStatus::VerificationTimeout;
    }

    if (strStatus == "INVALID_SCHEDULING_OVERRUN")
    {
        return AuthenticationRoundResultStatus::InvalidSchedulingOverrun;
    }

    if (strStatus == "STOPPED")
    {
        return AuthenticationRoundResultStatus::Stopped;
    }

    if (strStatus == "PROTOCOL_INCOMPLETE")
    {
        return AuthenticationRoundResultStatus::ProtocolIncomplete;
    }

    if (strStatus == "TIME_UNSYNCHRONIZED")
    {
        return AuthenticationRoundResultStatus::TimeUnsynchronized;
    }

    throw std::invalid_argument("Unknown authentication round result status");
}

nlohmann::json jsnEncodeReceiverPayload(
    const ReceiverPayloadControlDetails& varPayloadDetails
)
{
    if (std::holds_alternative<TextReceiverPayloadControlDetails>(
            varPayloadDetails
        ))
    {
        return {
            {"type", "TEXT"},
            {
                "repeatCount",
                std::get<TextReceiverPayloadControlDetails>(varPayloadDetails)
                    .u32RepeatCount()
            }
        };
    }

    return {
        {"type", "FILE"},
        {
            "originalByteCount",
            std::get<FileReceiverPayloadControlDetails>(varPayloadDetails)
                .u64OriginalByteCount()
        }
    };
}

ReceiverPayloadControlDetails varDecodeReceiverPayload(
    const nlohmann::json& jsnPayload
)
{
    const std::string strType = jsnPayload.at("type").get<std::string>();
    if (strType == "TEXT")
    {
        return TextReceiverPayloadControlDetails(
            jsnPayload.at("repeatCount").get<std::uint32_t>()
        );
    }

    if (strType == "FILE")
    {
        if (jsnPayload.contains("originalSha256"))
        {
            throw std::invalid_argument(
                "Receiver file payload must not contain the original SHA-256"
            );
        }

        return FileReceiverPayloadControlDetails(
            jsnPayload.at("originalByteCount").get<std::uint64_t>()
        );
    }

    throw std::invalid_argument("Unknown Receiver payload detail type");
}

nlohmann::json jsnEncodeResultDetails(
    const AuthenticationRoundResultDetails& varResultDetails
)
{
    if (std::holds_alternative<TextAuthenticationRoundResultDetails>(
            varResultDetails
        ))
    {
        return {
            {"type", "TEXT"},
            {
                "recoveredText",
                std::get<TextAuthenticationRoundResultDetails>(varResultDetails)
                    .strRecoveredText()
            }
        };
    }

    if (std::holds_alternative<FileSenderAuthenticationRoundResultDetails>(
            varResultDetails
        ))
    {
        return {
            {"type", "FILE_SENDER"},
            {
                "originalByteCount",
                std::get<FileSenderAuthenticationRoundResultDetails>(
                    varResultDetails
                ).u64OriginalByteCount()
            }
        };
    }

    const FileReceiverAuthenticationRoundResultDetails& detFile = std::get<
        FileReceiverAuthenticationRoundResultDetails
    >(varResultDetails);
    nlohmann::json jsnResult{
        {"type", "FILE_RECEIVER"},
        {"originalByteCount", detFile.u64OriginalByteCount()},
        {"recoveredByteCount", detFile.u64RecoveredByteCount()}
    };
    if (detFile.optRecoveredSha256().has_value())
    {
        jsnResult["recoveredSha256"] =
            AuthenticationControlValueCodec::strEncodeBlock(
                detFile.optRecoveredSha256().value()
            );
    }
    return jsnResult;
}

AuthenticationRoundResultDetails varDecodeResultDetails(
    const nlohmann::json& jsnDetails
)
{
    const std::string strType = jsnDetails.at("type").get<std::string>();
    if (strType == "TEXT")
    {
        return TextAuthenticationRoundResultDetails(
            jsnDetails.value("recoveredText", std::string())
        );
    }

    if (strType == "FILE_SENDER")
    {
        return FileSenderAuthenticationRoundResultDetails(
            jsnDetails.at("originalByteCount").get<std::uint64_t>()
        );
    }

    if (strType == "FILE_RECEIVER")
    {
        std::optional<BinaryBlock> optRecoveredSha256;
        if (jsnDetails.contains("recoveredSha256"))
        {
            optRecoveredSha256 = AuthenticationControlValueCodec::arrDecodeBlock(
                jsnDetails.at("recoveredSha256").get<std::string>()
            );
        }
        return FileReceiverAuthenticationRoundResultDetails(
            jsnDetails.at("originalByteCount").get<std::uint64_t>(),
            jsnDetails.at("recoveredByteCount").get<std::uint64_t>(),
            std::move(optRecoveredSha256)
        );
    }

    throw std::invalid_argument("Unknown authentication result detail type");
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
        {"chainLength", prmParameters.u32ChainLength()},
        {"payloadMode", pPayloadModeName(prmParameters.modePayload())}
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
        std::move(optImprovedParameters),
        jsnParameters.contains("payloadMode")
            ? modePayloadParse(jsnParameters.at("payloadMode").get<std::string>())
            : AuthenticationPayloadMode::Text
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
                {"round", jsnEncodeRoundParameters(detContext.prmRoundParameters())},
                {"payloadDetails", jsnEncodeReceiverPayload(
                    detContext.varPayloadDetails()
                )}
            });
        }
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::TextPayloadConfig)
    {
        const TextPayloadControlDetails& detPayload =
            std::get<TextPayloadControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detPayload.strRequestId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detPayload.u64ChainId()
        );
        jsnMessage["text"] = detPayload.strUtf8Text();
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::FileUploadBegin)
    {
        const FileUploadBeginControlDetails& detUpload =
            std::get<FileUploadBeginControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detUpload.strRequestId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detUpload.u64ChainId()
        );
        jsnMessage["originalByteCount"] = detUpload.u64OriginalByteCount();
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::FileUploadEnd)
    {
        const FileUploadEndControlDetails& detUpload =
            std::get<FileUploadEndControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detUpload.strRequestId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detUpload.u64ChainId()
        );
        jsnMessage["chunkCount"] = detUpload.u32ChunkCount();
        jsnMessage["transferredByteCount"] =
            detUpload.u64TransferredByteCount();
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
    else if (msgMessage.typeMessage() == NodeControlMessageType::RoundStart
        || msgMessage.typeMessage() == NodeControlMessageType::RoundPause
        || msgMessage.typeMessage() == NodeControlMessageType::RoundResume
        || msgMessage.typeMessage() == NodeControlMessageType::RoundStop)
    {
        const AuthenticationRoundCommandControlDetails& detCommand =
            std::get<AuthenticationRoundCommandControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["requestId"] = detCommand.strRequestId();
        jsnMessage["roundId"] = detCommand.strRoundId();

        if (detCommand.cmdCommand() != AuthenticationRoundCommand::Stop)
        {
            jsnMessage["executionTimestampMs"] =
                detCommand.u64ExecutionTimestampMilliseconds();
            jsnMessage["logicalIntervalIndex"] =
                detCommand.u32LogicalIntervalIndex();
        }
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::RoundCommandAcknowledgement)
    {
        const AuthenticationRoundAcknowledgementControlDetails& detAcknowledgement =
            std::get<AuthenticationRoundAcknowledgementControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["requestId"] = detAcknowledgement.strRequestId();
        jsnMessage["roundId"] = detAcknowledgement.strRoundId();
        jsnMessage["command"] = pRoundCommandName(detAcknowledgement.cmdCommand());
        jsnMessage["accepted"] = detAcknowledgement.bAccepted();
        jsnMessage["errorCode"] = detAcknowledgement.strErrorCode();
        jsnMessage["message"] = detAcknowledgement.strMessage();
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::RoundResult)
    {
        const AuthenticationRoundResultControlDetails& detResult =
            std::get<AuthenticationRoundResultControlDetails>(
                msgMessage.varDetails()
            );
        jsnMessage["roundId"] = detResult.strRoundId();
        jsnMessage["senderId"] = detResult.strSenderId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detResult.u64ChainId()
        );
        jsnMessage["role"] = pResultRoleName(detResult.roleResult());
        jsnMessage["status"] = pResultStatusName(detResult.statusResult());
        jsnMessage["expectedPacketCount"] = detResult.u32ExpectedPacketCount();
        jsnMessage["receivedPacketCount"] = detResult.u32ReceivedPacketCount();
        jsnMessage["authenticatedPacketCount"] =
            detResult.u32AuthenticatedPacketCount();
        jsnMessage["failedPacketCount"] = detResult.u32FailedPacketCount();
        jsnMessage["missingPacketCount"] = detResult.u32MissingPacketCount();
        jsnMessage["payloadDetails"] = jsnEncodeResultDetails(
            detResult.varResultDetails()
        );
        jsnMessage["message"] = detResult.strMessage();
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
                    prmDecodeRoundParameters(jsnContext.at("round")),
                    varDecodeReceiverPayload(jsnContext.at("payloadDetails"))
                );
            }

            return NodeControlMessage(ReceiverAuthenticationContextsControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                std::move(vecContexts)
            ));
        }

        if (strType == "TEXT_PAYLOAD")
        {
            return NodeControlMessage(TextPayloadControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                jsnMessage.at("text").get<std::string>()
            ));
        }

        if (strType == "FILE_UPLOAD_BEGIN")
        {
            return NodeControlMessage(FileUploadBeginControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                jsnMessage.at("originalByteCount").get<std::uint64_t>()
            ));
        }

        if (strType == "FILE_UPLOAD_END")
        {
            return NodeControlMessage(FileUploadEndControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                jsnMessage.at("chunkCount").get<std::uint32_t>(),
                jsnMessage.at("transferredByteCount").get<std::uint64_t>()
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

        if (strType == "ROUND_START"
            || strType == "ROUND_PAUSE"
            || strType == "ROUND_RESUME"
            || strType == "ROUND_STOP")
        {
            const AuthenticationRoundCommand cmdCommand = cmdRoundFromType(strType);
            return NodeControlMessage(AuthenticationRoundCommandControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("roundId").get<std::string>(),
                cmdCommand,
                cmdCommand == AuthenticationRoundCommand::Stop
                    ? 0
                    : jsnMessage.at("executionTimestampMs").get<std::uint64_t>(),
                cmdCommand == AuthenticationRoundCommand::Stop
                    ? 0
                    : jsnMessage.at("logicalIntervalIndex").get<std::uint32_t>()
            ));
        }

        if (strType == "ROUND_COMMAND_ACK")
        {
            return NodeControlMessage(
                AuthenticationRoundAcknowledgementControlDetails(
                    jsnMessage.at("requestId").get<std::string>(),
                    jsnMessage.at("roundId").get<std::string>(),
                    cmdRoundParse(jsnMessage.at("command").get<std::string>()),
                    jsnMessage.at("accepted").get<bool>(),
                    jsnMessage.at("errorCode").get<std::string>(),
                    jsnMessage.at("message").get<std::string>()
                )
            );
        }

        if (strType == "ROUND_RESULT")
        {
            return NodeControlMessage(AuthenticationRoundResultControlDetails(
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.at("senderId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                roleResultParse(jsnMessage.at("role").get<std::string>()),
                statusResultParse(jsnMessage.at("status").get<std::string>()),
                jsnMessage.at("expectedPacketCount").get<std::uint32_t>(),
                jsnMessage.at("receivedPacketCount").get<std::uint32_t>(),
                jsnMessage.at("authenticatedPacketCount").get<std::uint32_t>(),
                jsnMessage.at("failedPacketCount").get<std::uint32_t>(),
                jsnMessage.at("missingPacketCount").get<std::uint32_t>(),
                varDecodeResultDetails(jsnMessage.at("payloadDetails")),
                jsnMessage.at("message").get<std::string>()
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

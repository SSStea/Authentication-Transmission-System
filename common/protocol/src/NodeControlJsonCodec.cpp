#include "tesla/protocol/NodeControlJsonCodec.h"

#include <nlohmann/json.hpp>

#include <cctype>
#include <exception>
#include <limits>
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
    case NodeControlMessageType::PacketObservationEvent:
        return "PACKET_OBSERVATION_EVENT";
    case NodeControlMessageType::PacketFailureEvent:
        return "PACKET_FAILURE_EVENT";
    case NodeControlMessageType::ImprovedGroupObservationEvent:
        return "IMPROVED_GROUP_OBSERVATION_EVENT";
    case NodeControlMessageType::DosSummaryEvent:
        return "DOS_SUMMARY_EVENT";
    case NodeControlMessageType::AbnormalEventSnapshotRequest:
        return "ABNORMAL_EVENT_SNAPSHOT_REQUEST";
    case NodeControlMessageType::AbnormalEventSnapshot:
        return "ABNORMAL_EVENT_SNAPSHOT";
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

const char* pObservationDirectionName(PacketObservationDirection dirDirection)
{
    return dirDirection == PacketObservationDirection::Tx ? "TX" : "RX";
}

PacketObservationDirection dirObservationParse(const std::string& strDirection)
{
    if (strDirection == "TX")
    {
        return PacketObservationDirection::Tx;
    }

    if (strDirection == "RX")
    {
        return PacketObservationDirection::Rx;
    }

    throw std::invalid_argument("Unknown packet observation direction");
}

const char* pSourceTypeName(PacketSourceType typeSource)
{
    switch (typeSource)
    {
    case PacketSourceType::NormalSender:
        return "NORMAL_SENDER";
    case PacketSourceType::AttackInjection:
        return "ATTACK_INJECTION";
    case PacketSourceType::UnknownSource:
        return "UNKNOWN_SOURCE";
    }

    throw std::invalid_argument("Unknown packet source type");
}

PacketSourceType typeSourceParse(const std::string& strSource)
{
    if (strSource == "NORMAL_SENDER")
    {
        return PacketSourceType::NormalSender;
    }

    if (strSource == "ATTACK_INJECTION")
    {
        return PacketSourceType::AttackInjection;
    }

    if (strSource == "UNKNOWN_SOURCE")
    {
        return PacketSourceType::UnknownSource;
    }

    throw std::invalid_argument("Unknown packet source type");
}

const char* pPacketStatusName(PacketAuthenticationStatus statusAuthentication)
{
    switch (statusAuthentication)
    {
    case PacketAuthenticationStatus::Generated:
        return "GENERATED";
    case PacketAuthenticationStatus::Pending:
        return "PENDING";
    case PacketAuthenticationStatus::Passed:
        return "PASS";
    case PacketAuthenticationStatus::Failed:
        return "FAIL";
    }

    throw std::invalid_argument("Unknown packet authentication status");
}

PacketAuthenticationStatus statusPacketParse(const std::string& strStatus)
{
    if (strStatus == "GENERATED")
    {
        return PacketAuthenticationStatus::Generated;
    }

    if (strStatus == "PENDING")
    {
        return PacketAuthenticationStatus::Pending;
    }

    if (strStatus == "PASS")
    {
        return PacketAuthenticationStatus::Passed;
    }

    if (strStatus == "FAIL")
    {
        return PacketAuthenticationStatus::Failed;
    }

    throw std::invalid_argument("Unknown packet authentication status");
}

const char* pFailureTypeName(AuthenticationFailureType typeFailure)
{
    switch (typeFailure)
    {
    case AuthenticationFailureType::MacFailed:
        return "MAC_FAILED";
    case AuthenticationFailureType::TamperedVariant:
        return "TAMPERED_VARIANT";
    case AuthenticationFailureType::FastGroupFailed:
        return "FAST_GROUP_FAILED";
    case AuthenticationFailureType::GroupTauFailed:
        return "GROUP_TAU_FAILED";
    case AuthenticationFailureType::DetectionThresholdExceeded:
        return "DETECTION_THRESHOLD_EXCEEDED";
    case AuthenticationFailureType::ReplayDuplicate:
        return "REPLAY_DUPLICATE";
    case AuthenticationFailureType::ReplayLate:
        return "REPLAY_LATE";
    case AuthenticationFailureType::ReplayExpiredChain:
        return "REPLAY_EXPIRED_CHAIN";
    case AuthenticationFailureType::MissingPacket:
        return "MISSING_PACKET";
    case AuthenticationFailureType::IncompleteGroupTags:
        return "INCOMPLETE_GROUP_TAGS";
    case AuthenticationFailureType::UnverifiableMissingBaseline:
        return "UNVERIFIABLE_MISSING_BASELINE";
    case AuthenticationFailureType::UnknownContext:
        return "UNKNOWN_CONTEXT";
    case AuthenticationFailureType::ProtocolError:
        return "PROTOCOL_ERROR";
    case AuthenticationFailureType::InvalidSchedulingOverrun:
        return "INVALID_SCHEDULING_OVERRUN";
    case AuthenticationFailureType::AbnormalRecordLimitReached:
        return "ABNORMAL_RECORD_LIMIT_REACHED";
    }

    throw std::invalid_argument("Unknown authentication failure type");
}

AuthenticationFailureType typeFailureParse(const std::string& strFailure)
{
    static const std::vector<std::pair<std::string, AuthenticationFailureType>>
        vecMappings{
            {"MAC_FAILED", AuthenticationFailureType::MacFailed},
            {"TAMPERED_VARIANT", AuthenticationFailureType::TamperedVariant},
            {"FAST_GROUP_FAILED", AuthenticationFailureType::FastGroupFailed},
            {"GROUP_TAU_FAILED", AuthenticationFailureType::GroupTauFailed},
            {"DETECTION_THRESHOLD_EXCEEDED", AuthenticationFailureType::DetectionThresholdExceeded},
            {"REPLAY_DUPLICATE", AuthenticationFailureType::ReplayDuplicate},
            {"REPLAY_LATE", AuthenticationFailureType::ReplayLate},
            {"REPLAY_EXPIRED_CHAIN", AuthenticationFailureType::ReplayExpiredChain},
            {"MISSING_PACKET", AuthenticationFailureType::MissingPacket},
            {"INCOMPLETE_GROUP_TAGS", AuthenticationFailureType::IncompleteGroupTags},
            {"UNVERIFIABLE_MISSING_BASELINE", AuthenticationFailureType::UnverifiableMissingBaseline},
            {"UNKNOWN_CONTEXT", AuthenticationFailureType::UnknownContext},
            {"PROTOCOL_ERROR", AuthenticationFailureType::ProtocolError},
            {"INVALID_SCHEDULING_OVERRUN", AuthenticationFailureType::InvalidSchedulingOverrun},
            {"ABNORMAL_RECORD_LIMIT_REACHED", AuthenticationFailureType::AbnormalRecordLimitReached}
        };

    for (const auto& prMapping : vecMappings)
    {
        if (prMapping.first == strFailure)
        {
            return prMapping.second;
        }
    }

    throw std::invalid_argument("Unknown authentication failure type");
}

const char* pSeverityName(ObservationSeverity sevSeverity)
{
    switch (sevSeverity)
    {
    case ObservationSeverity::Information:
        return "INFO";
    case ObservationSeverity::Warning:
        return "WARNING";
    case ObservationSeverity::Error:
        return "ERROR";
    }

    throw std::invalid_argument("Unknown observation severity");
}

ObservationSeverity sevParse(const std::string& strSeverity)
{
    if (strSeverity == "INFO")
    {
        return ObservationSeverity::Information;
    }

    if (strSeverity == "WARNING")
    {
        return ObservationSeverity::Warning;
    }

    if (strSeverity == "ERROR")
    {
        return ObservationSeverity::Error;
    }

    throw std::invalid_argument("Unknown observation severity");
}

const char* pGroupPathName(GroupVerificationPath pathVerification)
{
    switch (pathVerification)
    {
    case GroupVerificationPath::FastGroupPass:
        return "FAST_GROUP_PASS";
    case GroupVerificationPath::KsRsFallback:
        return "KS_RS_FALLBACK";
    case GroupVerificationPath::IncompleteGroupTags:
        return "INCOMPLETE_GROUP_TAGS";
    }

    throw std::invalid_argument("Unknown group verification path");
}

GroupVerificationPath pathGroupParse(const std::string& strPath)
{
    if (strPath == "FAST_GROUP_PASS")
    {
        return GroupVerificationPath::FastGroupPass;
    }

    if (strPath == "KS_RS_FALLBACK")
    {
        return GroupVerificationPath::KsRsFallback;
    }

    if (strPath == "INCOMPLETE_GROUP_TAGS")
    {
        return GroupVerificationPath::IncompleteGroupTags;
    }

    throw std::invalid_argument("Unknown group verification path");
}

std::string strEncodeBytes(const ByteBuffer& vecBytes)
{
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::string strHex;
    strHex.resize(vecBytes.size() * 2U);

    for (std::size_t nIndex = 0; nIndex < vecBytes.size(); ++nIndex)
    {
        strHex[nIndex * 2U] = HEX_DIGITS[(vecBytes[nIndex] >> 4U) & 0x0FU];
        strHex[nIndex * 2U + 1U] = HEX_DIGITS[vecBytes[nIndex] & 0x0FU];
    }

    return strHex;
}

std::uint8_t u8DecodeHex(char chValue)
{
    if (chValue >= '0' && chValue <= '9')
    {
        return static_cast<std::uint8_t>(chValue - '0');
    }

    const char chLower = static_cast<char>(std::tolower(
        static_cast<unsigned char>(chValue)
    ));
    if (chLower >= 'a' && chLower <= 'f')
    {
        return static_cast<std::uint8_t>(chLower - 'a' + 10);
    }

    throw std::invalid_argument("Hex text contains an invalid character");
}

ByteBuffer vecDecodeBytes(const std::string& strHex)
{
    constexpr std::size_t MAX_MONITOR_BYTE_COUNT = 65535;
    if (strHex.empty()
        || (strHex.size() % 2U) != 0
        || strHex.size() / 2U > MAX_MONITOR_BYTE_COUNT)
    {
        throw std::invalid_argument("Monitor byte field has an invalid length");
    }

    ByteBuffer vecBytes(strHex.size() / 2U);
    for (std::size_t nIndex = 0; nIndex < vecBytes.size(); ++nIndex)
    {
        vecBytes[nIndex] = static_cast<std::uint8_t>(
            (u8DecodeHex(strHex[nIndex * 2U]) << 4U)
            | u8DecodeHex(strHex[nIndex * 2U + 1U])
        );
    }

    return vecBytes;
}

nlohmann::json jsnEncodePacketPayload(
    const PacketPayloadObservationDetails& varPayload
)
{
    if (const auto* pDisclosure = std::get_if<
            DisclosurePacketObservationDetails
        >(&varPayload))
    {
        return {
            {"type", "DISCLOSE"},
            {"disclosedKey", AuthenticationControlValueCodec::strEncodeBlock(
                pDisclosure->arrDisclosedKey()
            )}
        };
    }

    const DataPacketObservationDetails& detData = std::get<
        DataPacketObservationDetails
    >(varPayload);
    nlohmann::json jsnPayload{
        {"type", "DATA"},
        {"message", AuthenticationControlValueCodec::strEncodeBlock(
            detData.arrMessage()
        )}
    };
    if (detData.optDisclosedKey().has_value())
    {
        jsnPayload["disclosedKey"] =
            AuthenticationControlValueCodec::strEncodeBlock(
                detData.optDisclosedKey().value()
            );
    }

    if (const auto* pNative = std::get_if<NativePacketObservationDetails>(
            &detData.varModeDetails()
        ))
    {
        jsnPayload["modeDetails"] = {
            {"type", "NATIVE"},
            {"packetMac", AuthenticationControlValueCodec::strEncodeBlock(
                pNative->arrPacketMac()
            )}
        };
    }
    else
    {
        const ImprovedPacketObservationDetails& detImproved = std::get<
            ImprovedPacketObservationDetails
        >(detData.varModeDetails());
        nlohmann::json jsnTau = nlohmann::json::array();
        for (const BinaryBlock& arrTau : detImproved.vecSamdTau())
        {
            jsnTau.push_back(
                AuthenticationControlValueCodec::strEncodeBlock(arrTau)
            );
        }
        jsnPayload["modeDetails"] = {
            {"type", "IMPROVED"},
            {"samdTau", std::move(jsnTau)}
        };
        if (detImproved.optFastGroupTag().has_value())
        {
            jsnPayload["modeDetails"]["fastGroupTag"] =
                AuthenticationControlValueCodec::strEncodeBlock(
                    detImproved.optFastGroupTag().value()
                );
        }
    }

    return jsnPayload;
}

PacketPayloadObservationDetails varDecodePacketPayload(
    const nlohmann::json& jsnPayload
)
{
    const std::string strType = jsnPayload.at("type").get<std::string>();
    if (strType == "DISCLOSE")
    {
        return DisclosurePacketObservationDetails(
            AuthenticationControlValueCodec::arrDecodeBlock(
                jsnPayload.at("disclosedKey").get<std::string>()
            )
        );
    }

    if (strType != "DATA")
    {
        throw std::invalid_argument("Unknown observed packet payload type");
    }

    std::optional<BinaryBlock> optDisclosedKey;
    if (jsnPayload.contains("disclosedKey"))
    {
        optDisclosedKey = AuthenticationControlValueCodec::arrDecodeBlock(
            jsnPayload.at("disclosedKey").get<std::string>()
        );
    }

    const nlohmann::json& jsnMode = jsnPayload.at("modeDetails");
    PacketModeObservationDetails varMode = NativePacketObservationDetails(
        BinaryBlock{}
    );
    const std::string strMode = jsnMode.at("type").get<std::string>();
    if (strMode == "NATIVE")
    {
        varMode = NativePacketObservationDetails(
            AuthenticationControlValueCodec::arrDecodeBlock(
                jsnMode.at("packetMac").get<std::string>()
            )
        );
    }
    else if (strMode == "IMPROVED")
    {
        std::vector<BinaryBlock> vecTau;
        for (const nlohmann::json& jsnTau : jsnMode.at("samdTau"))
        {
            vecTau.push_back(AuthenticationControlValueCodec::arrDecodeBlock(
                jsnTau.get<std::string>()
            ));
        }
        std::optional<BinaryBlock> optFastGroupTag;
        if (jsnMode.contains("fastGroupTag"))
        {
            optFastGroupTag = AuthenticationControlValueCodec::arrDecodeBlock(
                jsnMode.at("fastGroupTag").get<std::string>()
            );
        }
        varMode = ImprovedPacketObservationDetails(
            std::move(vecTau),
            std::move(optFastGroupTag)
        );
    }
    else
    {
        throw std::invalid_argument("Unknown observed packet mode details");
    }

    return DataPacketObservationDetails(
        AuthenticationControlValueCodec::arrDecodeBlock(
            jsnPayload.at("message").get<std::string>()
        ),
        std::move(optDisclosedKey),
        std::move(varMode)
    );
}

// 实时事件和重连快照共用同一份报文JSON映射，避免两条协议路径逐渐产生字段差异。
nlohmann::json jsnEncodeObservedPacket(
    const PacketObservationControlDetails& detPacket
)
{
    return {
        {"eventId", detPacket.u64EventId()},
        {"timestampMs", detPacket.u64TimestampMilliseconds()},
        {"roundId", detPacket.strRoundId()},
        {"senderId", detPacket.strSenderId()},
        {"senderIp", detPacket.strSenderIp()},
        {"actualSourceIp", detPacket.strActualSourceIp()},
        {"peer", detPacket.strPeer()},
        {"direction", pObservationDirectionName(detPacket.dirDirection())},
        {"sourceType", pSourceTypeName(detPacket.typeSource())},
        {"chainId", AuthenticationControlValueCodec::strEncodeChainId(
            detPacket.u64ChainId()
        )},
        {"intervalIndex", detPacket.u32IntervalIndex()},
        {"packetIndex", detPacket.u32PacketIndex()},
        {"packetsPerInterval", detPacket.u32PacketsPerInterval()},
        {"disclosureDelay", detPacket.u32DisclosureDelay()},
        {"cryptoAlgorithm", pAlgorithmName(detPacket.algCryptoAlgorithm())},
        {"authMode", pAuthenticationModeName(
            detPacket.modeAuthentication()
        )},
        {"status", pPacketStatusName(detPacket.statusAuthentication())},
        {"candidateHash", detPacket.strCandidateHash()},
        {"duplicateCount", detPacket.u32DuplicateCount()},
        {"reason", detPacket.strReason()},
        {"payloadDetails", jsnEncodePacketPayload(
            detPacket.varPayloadDetails()
        )},
        {"rawDatagram", strEncodeBytes(detPacket.vecRawDatagram())}
    };
}

PacketObservationControlDetails detDecodeObservedPacket(
    const nlohmann::json& jsnPacket
)
{
    return PacketObservationControlDetails(
        jsnPacket.at("eventId").get<std::uint64_t>(),
        jsnPacket.at("timestampMs").get<std::uint64_t>(),
        jsnPacket.at("roundId").get<std::string>(),
        jsnPacket.at("senderId").get<std::string>(),
        jsnPacket.value("senderIp", std::string()),
        jsnPacket.value("actualSourceIp", std::string()),
        jsnPacket.at("peer").get<std::string>(),
        dirObservationParse(jsnPacket.at("direction").get<std::string>()),
        typeSourceParse(jsnPacket.at("sourceType").get<std::string>()),
        AuthenticationControlValueCodec::u64DecodeChainId(
            jsnPacket.at("chainId").get<std::string>()
        ),
        jsnPacket.at("intervalIndex").get<std::uint32_t>(),
        jsnPacket.at("packetIndex").get<std::uint32_t>(),
        jsnPacket.at("packetsPerInterval").get<std::uint32_t>(),
        jsnPacket.at("disclosureDelay").get<std::uint32_t>(),
        algParse(jsnPacket.at("cryptoAlgorithm").get<std::string>()),
        modeAuthenticationParse(jsnPacket.at("authMode").get<std::string>()),
        statusPacketParse(jsnPacket.at("status").get<std::string>()),
        jsnPacket.at("candidateHash").get<std::string>(),
        jsnPacket.at("duplicateCount").get<std::uint32_t>(),
        jsnPacket.value("reason", std::string()),
        varDecodePacketPayload(jsnPacket.at("payloadDetails")),
        vecDecodeBytes(jsnPacket.at("rawDatagram").get<std::string>())
    );
}

nlohmann::json jsnEncodeFailure(const PacketFailureControlDetails& detFailure)
{
    nlohmann::json jsnFailure{
        {"eventId", detFailure.u64EventId()},
        {"packetEventId", detFailure.u64PacketEventId()},
        {"timestampMs", detFailure.u64TimestampMilliseconds()},
        {"severity", pSeverityName(detFailure.sevSeverity())},
        {"failureType", pFailureTypeName(detFailure.typeFailure())},
        {"roundId", detFailure.strRoundId()},
        {"senderId", detFailure.strSenderId()},
        {"senderIp", detFailure.strSenderIp()},
        {"actualSourceIp", detFailure.strActualSourceIp()},
        {"chainId", AuthenticationControlValueCodec::strEncodeChainId(
            detFailure.u64ChainId()
        )},
        {"intervalIndex", detFailure.u32IntervalIndex()},
        {"packetIndex", detFailure.u32PacketIndex()},
        {"candidateHash", detFailure.strCandidateHash()},
        {"reason", detFailure.strReason()},
        {"receivedTagDigest", detFailure.strReceivedTagDigest()},
        {"calculatedTagDigest", detFailure.strCalculatedTagDigest()},
        {"locatedPacketIndexes", detFailure.vecLocatedPacketIndexes()},
        {"duplicateCount", detFailure.u32DuplicateCount()}
    };
    if (detFailure.optGroupIndex().has_value())
    {
        jsnFailure["groupIndex"] = detFailure.optGroupIndex().value();
    }
    return jsnFailure;
}

PacketFailureControlDetails detDecodeFailure(const nlohmann::json& jsnFailure)
{
    std::optional<std::uint32_t> optGroupIndex;
    if (jsnFailure.contains("groupIndex"))
    {
        optGroupIndex = jsnFailure.at("groupIndex").get<std::uint32_t>();
    }

    return PacketFailureControlDetails(
        jsnFailure.at("eventId").get<std::uint64_t>(),
        jsnFailure.value("packetEventId", static_cast<std::uint64_t>(0)),
        jsnFailure.at("timestampMs").get<std::uint64_t>(),
        sevParse(jsnFailure.at("severity").get<std::string>()),
        typeFailureParse(jsnFailure.at("failureType").get<std::string>()),
        jsnFailure.value("roundId", std::string()),
        jsnFailure.value("senderId", std::string()),
        jsnFailure.value("senderIp", std::string()),
        jsnFailure.value("actualSourceIp", std::string()),
        AuthenticationControlValueCodec::u64DecodeChainId(
            jsnFailure.value("chainId", std::string("0000000000000000"))
        ),
        jsnFailure.value("intervalIndex", static_cast<std::uint32_t>(0)),
        jsnFailure.value("packetIndex", static_cast<std::uint32_t>(0)),
        std::move(optGroupIndex),
        jsnFailure.value("candidateHash", std::string()),
        jsnFailure.at("reason").get<std::string>(),
        jsnFailure.value("receivedTagDigest", std::string()),
        jsnFailure.value("calculatedTagDigest", std::string()),
        jsnFailure.value(
            "locatedPacketIndexes",
            std::vector<std::uint32_t>()
        ),
        jsnFailure.value("duplicateCount", static_cast<std::uint32_t>(1))
    );
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
        || msgMessage.typeMessage() == NodeControlMessageType::StatusRequest
        || msgMessage.typeMessage()
            == NodeControlMessageType::AbnormalEventSnapshotRequest)
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
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::PacketObservationEvent)
    {
        const PacketObservationControlDetails& detPacket = std::get<
            PacketObservationControlDetails
        >(msgMessage.varDetails());
        jsnMessage.update(jsnEncodeObservedPacket(detPacket));
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::PacketFailureEvent)
    {
        const PacketFailureControlDetails& detFailure = std::get<
            PacketFailureControlDetails
        >(msgMessage.varDetails());
        jsnMessage.update(jsnEncodeFailure(detFailure));
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::ImprovedGroupObservationEvent)
    {
        const ImprovedGroupObservationControlDetails& detGroup = std::get<
            ImprovedGroupObservationControlDetails
        >(msgMessage.varDetails());
        jsnMessage["eventId"] = detGroup.u64EventId();
        jsnMessage["timestampMs"] = detGroup.u64TimestampMilliseconds();
        jsnMessage["roundId"] = detGroup.strRoundId();
        jsnMessage["senderId"] = detGroup.strSenderId();
        jsnMessage["chainId"] = AuthenticationControlValueCodec::strEncodeChainId(
            detGroup.u64ChainId()
        );
        jsnMessage["groupIndex"] = detGroup.u32GroupIndex();
        jsnMessage["firstPacketIndex"] = detGroup.u32FirstPacketIndex();
        jsnMessage["lastPacketIndex"] = detGroup.u32LastPacketIndex();
        jsnMessage["detectionThreshold"] = detGroup.u32DetectionThreshold();
        jsnMessage["verificationPath"] = pGroupPathName(
            detGroup.pathVerification()
        );
        jsnMessage["fastGroupTagMatched"] = detGroup.bFastGroupTagMatched();
        jsnMessage["detectionThresholdExceeded"] =
            detGroup.bDetectionThresholdExceeded();
        jsnMessage["locatedPacketIndexes"] =
            detGroup.vecLocatedPacketIndexes();
        jsnMessage["locationSteps"] = nlohmann::json::array();
        for (const MatrixLocationStepControlDetails& detStep
            : detGroup.vecLocationSteps())
        {
            jsnMessage["locationSteps"].push_back({
                {"stepIndex", detStep.u32StepIndex()},
                {"operation", detStep.strOperation()},
                {"newGoodPacketIndexes", detStep.vecNewGoodPacketIndexes()},
                {"remainingCandidateIndexes", detStep.vecRemainingCandidateIndexes()}
            });
        }
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::DosSummaryEvent)
    {
        const DosSummaryControlDetails& detSummary = std::get<
            DosSummaryControlDetails
        >(msgMessage.varDetails());
        jsnMessage["timestampMs"] = detSummary.u64TimestampMilliseconds();
        jsnMessage["windowMs"] = detSummary.u32WindowMilliseconds();
        jsnMessage["invalidPacketCount"] = detSummary.u64InvalidPacketCount();
        jsnMessage["rateLimitedDropCount"] =
            detSummary.u64RateLimitedDropCount();
        jsnMessage["legitimatePacketCount"] =
            detSummary.u64LegitimatePacketCount();
        jsnMessage["receiveQueueOverflowCount"] =
            detSummary.u64ReceiveQueueOverflowCount();
    }
    else if (msgMessage.typeMessage()
        == NodeControlMessageType::AbnormalEventSnapshot)
    {
        const AbnormalEventSnapshotControlDetails& detSnapshot = std::get<
            AbnormalEventSnapshotControlDetails
        >(msgMessage.varDetails());
        jsnMessage["requestId"] = detSnapshot.strRequestId();
        jsnMessage["sequence"] = detSnapshot.u32Sequence();
        jsnMessage["finalBatch"] = detSnapshot.bFinalBatch();
        jsnMessage["packetEvents"] = nlohmann::json::array();
        for (const PacketObservationControlDetails& detPacket
            : detSnapshot.vecPacketEvents())
        {
            jsnMessage["packetEvents"].push_back(
                jsnEncodeObservedPacket(detPacket)
            );
        }
        jsnMessage["failureEvents"] = nlohmann::json::array();
        for (const PacketFailureControlDetails& detFailure
            : detSnapshot.vecFailureEvents())
        {
            jsnMessage["failureEvents"].push_back(jsnEncodeFailure(detFailure));
        }
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

        if (strType == "PING"
            || strType == "PONG"
            || strType == "STATUS_REQUEST"
            || strType == "ABNORMAL_EVENT_SNAPSHOT_REQUEST")
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
            else if (strType == "ABNORMAL_EVENT_SNAPSHOT_REQUEST")
            {
                typeMessage = NodeControlMessageType::AbnormalEventSnapshotRequest;
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

        if (strType == "PACKET_OBSERVATION_EVENT")
        {
            return NodeControlMessage(detDecodeObservedPacket(jsnMessage));
        }

        if (strType == "PACKET_FAILURE_EVENT")
        {
            return NodeControlMessage(detDecodeFailure(jsnMessage));
        }

        if (strType == "IMPROVED_GROUP_OBSERVATION_EVENT")
        {
            std::vector<MatrixLocationStepControlDetails> vecSteps;
            for (const nlohmann::json& jsnStep
                : jsnMessage.at("locationSteps"))
            {
                vecSteps.emplace_back(
                    jsnStep.at("stepIndex").get<std::uint32_t>(),
                    jsnStep.at("operation").get<std::string>(),
                    jsnStep.value(
                        "newGoodPacketIndexes",
                        std::vector<std::uint32_t>()
                    ),
                    jsnStep.value(
                        "remainingCandidateIndexes",
                        std::vector<std::uint32_t>()
                    )
                );
            }

            return NodeControlMessage(ImprovedGroupObservationControlDetails(
                jsnMessage.at("eventId").get<std::uint64_t>(),
                jsnMessage.at("timestampMs").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.at("senderId").get<std::string>(),
                AuthenticationControlValueCodec::u64DecodeChainId(
                    jsnMessage.at("chainId").get<std::string>()
                ),
                jsnMessage.at("groupIndex").get<std::uint32_t>(),
                jsnMessage.at("firstPacketIndex").get<std::uint32_t>(),
                jsnMessage.at("lastPacketIndex").get<std::uint32_t>(),
                jsnMessage.at("detectionThreshold").get<std::uint32_t>(),
                pathGroupParse(
                    jsnMessage.at("verificationPath").get<std::string>()
                ),
                jsnMessage.at("fastGroupTagMatched").get<bool>(),
                jsnMessage.at("detectionThresholdExceeded").get<bool>(),
                jsnMessage.value(
                    "locatedPacketIndexes",
                    std::vector<std::uint32_t>()
                ),
                std::move(vecSteps)
            ));
        }

        if (strType == "DOS_SUMMARY_EVENT")
        {
            return NodeControlMessage(DosSummaryControlDetails(
                jsnMessage.at("timestampMs").get<std::uint64_t>(),
                jsnMessage.at("windowMs").get<std::uint32_t>(),
                jsnMessage.at("invalidPacketCount").get<std::uint64_t>(),
                jsnMessage.at("rateLimitedDropCount").get<std::uint64_t>(),
                jsnMessage.at("legitimatePacketCount").get<std::uint64_t>(),
                jsnMessage.at("receiveQueueOverflowCount").get<std::uint64_t>()
            ));
        }

        if (strType == "ABNORMAL_EVENT_SNAPSHOT")
        {
            std::vector<PacketObservationControlDetails> vecPackets;
            std::vector<PacketFailureControlDetails> vecFailures;
            const nlohmann::json& jsnPackets = jsnMessage.at("packetEvents");
            const nlohmann::json& jsnFailures = jsnMessage.at("failureEvents");
            if (!jsnPackets.is_array()
                || jsnPackets.size() > 64
                || !jsnFailures.is_array()
                || jsnFailures.size() > 64)
            {
                throw std::invalid_argument(
                    "Abnormal event snapshot batch is invalid"
                );
            }

            vecPackets.reserve(jsnPackets.size());
            for (const nlohmann::json& jsnPacket : jsnPackets)
            {
                vecPackets.push_back(detDecodeObservedPacket(jsnPacket));
            }
            vecFailures.reserve(jsnFailures.size());
            for (const nlohmann::json& jsnFailure : jsnFailures)
            {
                vecFailures.push_back(detDecodeFailure(jsnFailure));
            }

            return NodeControlMessage(AbnormalEventSnapshotControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("sequence").get<std::uint32_t>(),
                jsnMessage.at("finalBatch").get<bool>(),
                std::move(vecPackets),
                std::move(vecFailures)
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

#include "tesla/protocol/AttackControl.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <exception>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
constexpr std::uint32_t MAX_DOS_RATE_PPS = 20000;
constexpr std::uint32_t MAX_DOS_DURATION_MILLISECONDS = 60000;
constexpr std::uint32_t MAX_DOS_PACKET_BYTES = 1472;
constexpr std::uint32_t MAX_ATTACK_REPEAT_COUNT = 1000;

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
    case AttackControlMessageType::RoundContext:
        return "ATTACK_ROUND_CONTEXT";
    case AttackControlMessageType::Plan:
        return "ATTACK_PLAN";
    case AttackControlMessageType::PlanAccepted:
        return "ATTACK_PLAN_ACCEPTED";
    case AttackControlMessageType::Ready:
        return "ATTACK_READY";
    case AttackControlMessageType::RoundStart:
        return "ROUND_START";
    case AttackControlMessageType::Stop:
        return "ATTACK_STOP";
    case AttackControlMessageType::EmergencyStop:
        return "ATTACK_EMERGENCY_STOP";
    case AttackControlMessageType::ExecutionStatus:
        return "ATTACK_STATUS";
    case AttackControlMessageType::ErrorResponse:
        return "ATTACK_ERROR";
    }

    throw std::invalid_argument("Unknown attack control message type");
}

const char* pAttackTypeName(AttackType typeAttack)
{
    switch (typeAttack)
    {
    case AttackType::Tamper:
        return "TAMPER";
    case AttackType::Replay:
        return "REPLAY";
    case AttackType::Dos:
        return "DOS";
    }

    throw std::invalid_argument("Unknown attack type");
}

const char* pExecutionStateName(AttackExecutionState stateExecution)
{
    switch (stateExecution)
    {
    case AttackExecutionState::Idle:
        return "IDLE";
    case AttackExecutionState::ContextReady:
        return "CONTEXT_READY";
    case AttackExecutionState::PlanPending:
        return "PLAN_PENDING";
    case AttackExecutionState::Ready:
        return "READY";
    case AttackExecutionState::Scheduled:
        return "SCHEDULED";
    case AttackExecutionState::Running:
        return "RUNNING";
    case AttackExecutionState::Completed:
        return "COMPLETED";
    case AttackExecutionState::Stopped:
        return "STOPPED";
    case AttackExecutionState::Failed:
        return "FAILED";
    }

    throw std::invalid_argument("Unknown attack execution state");
}

AttackExecutionState stateParse(const std::string& strState)
{
    if (strState == "IDLE")
    {
        return AttackExecutionState::Idle;
    }
    if (strState == "CONTEXT_READY")
    {
        return AttackExecutionState::ContextReady;
    }
    if (strState == "PLAN_PENDING")
    {
        return AttackExecutionState::PlanPending;
    }
    if (strState == "READY")
    {
        return AttackExecutionState::Ready;
    }
    if (strState == "SCHEDULED")
    {
        return AttackExecutionState::Scheduled;
    }
    if (strState == "RUNNING")
    {
        return AttackExecutionState::Running;
    }
    if (strState == "COMPLETED")
    {
        return AttackExecutionState::Completed;
    }
    if (strState == "STOPPED")
    {
        return AttackExecutionState::Stopped;
    }
    if (strState == "FAILED")
    {
        return AttackExecutionState::Failed;
    }

    throw std::invalid_argument("Unsupported attack execution state");
}

const char* pModeName(UdpAuthenticationMode modeAuthentication)
{
    return modeAuthentication == UdpAuthenticationMode::Native
        ? "NATIVE"
        : "IMPROVED";
}

UdpAuthenticationMode modeParse(const std::string& strMode)
{
    if (strMode == "NATIVE")
    {
        return UdpAuthenticationMode::Native;
    }
    if (strMode == "IMPROVED")
    {
        return UdpAuthenticationMode::Improved;
    }

    throw std::invalid_argument("Unsupported attack context authentication mode");
}

const char* pCryptoAlgorithmName(AuthenticationCryptoAlgorithm algCryptoAlgorithm)
{
    switch (algCryptoAlgorithm)
    {
    case AuthenticationCryptoAlgorithm::Sha256:
        return "SHA-256";
    case AuthenticationCryptoAlgorithm::Sm3:
        return "SM3";
    case AuthenticationCryptoAlgorithm::Sha3_256:
        return "SHA3-256";
    }

    throw std::invalid_argument("Unsupported attack context crypto algorithm");
}

AuthenticationCryptoAlgorithm algCryptoParse(const std::string& strAlgorithm)
{
    if (strAlgorithm == "SHA-256")
    {
        return AuthenticationCryptoAlgorithm::Sha256;
    }
    if (strAlgorithm == "SM3")
    {
        return AuthenticationCryptoAlgorithm::Sm3;
    }
    if (strAlgorithm == "SHA3-256")
    {
        return AuthenticationCryptoAlgorithm::Sha3_256;
    }

    throw std::invalid_argument("Unsupported attack context crypto algorithm");
}

ProtocolDecodeError errCreate(const std::string& strMessage)
{
    return ProtocolDecodeError(
        ProtocolDecodeErrorCode::InvalidControlMessage,
        strMessage
    );
}

void validatePacketIndexes(const std::vector<std::uint32_t>& vecPacketIndexes)
{
    if (vecPacketIndexes.empty())
    {
        throw std::invalid_argument("Attack plan requires packet indexes");
    }

    if (std::any_of(
            vecPacketIndexes.begin(),
            vecPacketIndexes.end(),
            [](std::uint32_t u32PacketIndex)
            {
                return u32PacketIndex == 0;
            }
        ))
    {
        throw std::invalid_argument("Attack packet indexes must be positive");
    }

    std::vector<std::uint32_t> vecSorted = vecPacketIndexes;
    std::sort(vecSorted.begin(), vecSorted.end());
    if (std::adjacent_find(vecSorted.begin(), vecSorted.end()) != vecSorted.end())
    {
        throw std::invalid_argument("Attack packet indexes must be unique");
    }
}

nlohmann::json jsnEncodePlanDetails(const AttackPlanDetails& varDetails)
{
    nlohmann::json jsnDetails;
    if (const auto* pTamper = std::get_if<TamperAttackPlanDetails>(&varDetails))
    {
        jsnDetails["attackType"] = pAttackTypeName(AttackType::Tamper);
        jsnDetails["packetIndexes"] = pTamper->vecPacketIndexes();
        jsnDetails["messageByteOffset"] = pTamper->u8MessageByteOffset();
        jsnDetails["xorMask"] = pTamper->u8XorMask();
        jsnDetails["repeatCount"] = pTamper->u32RepeatCount();
    }
    else if (const auto* pReplay = std::get_if<ReplayAttackPlanDetails>(
                 &varDetails
             ))
    {
        jsnDetails["attackType"] = pAttackTypeName(AttackType::Replay);
        jsnDetails["packetIndexes"] = pReplay->vecPacketIndexes();
        jsnDetails["replayDelayMs"] =
            pReplay->u32ReplayDelayMilliseconds();
        jsnDetails["repeatCount"] = pReplay->u32RepeatCount();
        jsnDetails["repeatGapMs"] = pReplay->u32RepeatGapMilliseconds();
    }
    else
    {
        const DosAttackPlanDetails& detDos =
            std::get<DosAttackPlanDetails>(varDetails);
        jsnDetails["attackType"] = pAttackTypeName(AttackType::Dos);
        jsnDetails["targetMulticast"] = "TESLA_INTERNAL_MULTICAST";
        jsnDetails["ratePps"] = detDos.u32RatePacketsPerSecond();
        jsnDetails["durationMs"] = detDos.u32DurationMilliseconds();
        jsnDetails["packetBytes"] = detDos.u32PacketBytes();
    }

    return jsnDetails;
}

AttackPlanDetails varDecodePlanDetails(const nlohmann::json& jsnMessage)
{
    const std::string strAttackType =
        jsnMessage.at("attackType").get<std::string>();
    if (strAttackType == "TAMPER")
    {
        return TamperAttackPlanDetails(
            jsnMessage.at("packetIndexes").get<std::vector<std::uint32_t>>(),
            jsnMessage.at("messageByteOffset").get<std::uint8_t>(),
            jsnMessage.at("xorMask").get<std::uint8_t>(),
            jsnMessage.at("repeatCount").get<std::uint32_t>()
        );
    }
    if (strAttackType == "REPLAY")
    {
        return ReplayAttackPlanDetails(
            jsnMessage.at("packetIndexes").get<std::vector<std::uint32_t>>(),
            jsnMessage.at("replayDelayMs").get<std::uint32_t>(),
            jsnMessage.at("repeatCount").get<std::uint32_t>(),
            jsnMessage.at("repeatGapMs").get<std::uint32_t>()
        );
    }
    if (strAttackType == "DOS"
        && jsnMessage.at("targetMulticast").get<std::string>()
            == "TESLA_INTERNAL_MULTICAST")
    {
        return DosAttackPlanDetails(
            jsnMessage.at("ratePps").get<std::uint32_t>(),
            jsnMessage.at("durationMs").get<std::uint32_t>(),
            jsnMessage.at("packetBytes").get<std::uint32_t>()
        );
    }

    throw std::invalid_argument("Unsupported attack plan type or target");
}

nlohmann::json jsnEncodeExecutionDetails(
    const AttackExecutionStatusDetails& varDetails
)
{
    nlohmann::json jsnDetails;
    if (const auto* pTamper = std::get_if<TamperAttackStatusDetails>(
            &varDetails
        ))
    {
        jsnDetails["attackType"] = "TAMPER";
        jsnDetails["capturedPackets"] = pTamper->u64CapturedPacketCount();
        jsnDetails["injectedPackets"] = pTamper->u64InjectedPacketCount();
        jsnDetails["lastInjectionDelayUs"] =
            pTamper->u64LastInjectionDelayMicroseconds();
    }
    else if (const auto* pReplay = std::get_if<ReplayAttackStatusDetails>(
                 &varDetails
             ))
    {
        jsnDetails["attackType"] = "REPLAY";
        jsnDetails["capturedPackets"] = pReplay->u64CapturedPacketCount();
        jsnDetails["replayedPackets"] = pReplay->u64ReplayedPacketCount();
    }
    else
    {
        const DosAttackStatusDetails& detDos =
            std::get<DosAttackStatusDetails>(varDetails);
        jsnDetails["attackType"] = "DOS";
        jsnDetails["sentPackets"] = detDos.u64SentPacketCount();
        jsnDetails["sentBytes"] = detDos.u64SentByteCount();
        jsnDetails["actualPps"] = detDos.dActualPacketsPerSecond();
    }

    return jsnDetails;
}

AttackExecutionStatusDetails varDecodeExecutionDetails(
    const nlohmann::json& jsnMessage
)
{
    const std::string strAttackType =
        jsnMessage.at("attackType").get<std::string>();
    if (strAttackType == "TAMPER")
    {
        return TamperAttackStatusDetails(
            jsnMessage.at("capturedPackets").get<std::uint64_t>(),
            jsnMessage.at("injectedPackets").get<std::uint64_t>(),
            jsnMessage.at("lastInjectionDelayUs").get<std::uint64_t>()
        );
    }
    if (strAttackType == "REPLAY")
    {
        return ReplayAttackStatusDetails(
            jsnMessage.at("capturedPackets").get<std::uint64_t>(),
            jsnMessage.at("replayedPackets").get<std::uint64_t>()
        );
    }
    if (strAttackType == "DOS")
    {
        return DosAttackStatusDetails(
            jsnMessage.at("sentPackets").get<std::uint64_t>(),
            jsnMessage.at("sentBytes").get<std::uint64_t>(),
            jsnMessage.at("actualPps").get<double>()
        );
    }

    throw std::invalid_argument("Unsupported attack execution status type");
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
    AttackExecutionState stateExecution,
    std::uint64_t u64TimestampMilliseconds
)
    : m_strRequestId(std::move(strRequestId)),
      m_strNodeName(std::move(strNodeName)),
      m_bMulticastListening(bMulticastListening),
      m_stateExecution(stateExecution),
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

AttackExecutionState AttackStatusControlDetails::stateExecution() const noexcept
{
    return m_stateExecution;
}

bool AttackStatusControlDetails::bAttackRunning() const noexcept
{
    return m_stateExecution == AttackExecutionState::Scheduled
        || m_stateExecution == AttackExecutionState::Running;
}

std::uint64_t AttackStatusControlDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

AttackRoundContextControlDetails::AttackRoundContextControlDetails(
    std::string strRequestId,
    std::string strRoundId,
    std::string strTargetSenderId,
    std::string strTargetSenderIp,
    std::uint64_t u64ChainId,
    AuthenticationCryptoAlgorithm algCryptoAlgorithm,
    UdpAuthenticationMode modeAuthentication,
    std::uint32_t u32DataPacketCount,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32IntervalMilliseconds,
    std::uint32_t u32DisclosureDelay,
    std::uint64_t u64StartTimestampMilliseconds,
    std::uint32_t u32GroupSize,
    std::uint32_t u32DetectionThreshold,
    std::size_t nTauCount
)
    : m_strRequestId(std::move(strRequestId)),
      m_strRoundId(std::move(strRoundId)),
      m_strTargetSenderId(std::move(strTargetSenderId)),
      m_strTargetSenderIp(std::move(strTargetSenderIp)),
      m_u64ChainId(u64ChainId),
      m_algCryptoAlgorithm(algCryptoAlgorithm),
      m_modeAuthentication(modeAuthentication),
      m_u32DataPacketCount(u32DataPacketCount),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32IntervalMilliseconds(u32IntervalMilliseconds),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u64StartTimestampMilliseconds(u64StartTimestampMilliseconds),
      m_u32GroupSize(u32GroupSize),
      m_u32DetectionThreshold(u32DetectionThreshold),
      m_nTauCount(nTauCount)
{
    if (m_strRequestId.empty()
        || m_strRoundId.empty()
        || m_strTargetSenderId.empty()
        || m_strTargetSenderIp.empty()
        || m_u64ChainId == 0
        || m_u32DataPacketCount == 0
        || m_u32PacketsPerInterval == 0
        || m_u32IntervalMilliseconds == 0
        || m_u32DisclosureDelay == 0)
    {
        throw std::invalid_argument("Attack round context has missing identity fields");
    }
    if (m_modeAuthentication == UdpAuthenticationMode::Native)
    {
        if (m_u32GroupSize != 0
            || m_u32DetectionThreshold != 0
            || m_nTauCount != 0)
        {
            throw std::invalid_argument("Native attack context must not contain group parameters");
        }
    }
    else if (m_u32GroupSize == 0
        || m_u32DetectionThreshold == 0
        || m_u32DetectionThreshold > m_u32GroupSize
        || m_nTauCount == 0)
    {
        throw std::invalid_argument("Improved attack context group parameters are invalid");
    }
}

const std::string& AttackRoundContextControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& AttackRoundContextControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

const std::string& AttackRoundContextControlDetails::strTargetSenderId() const noexcept
{
    return m_strTargetSenderId;
}

const std::string& AttackRoundContextControlDetails::strTargetSenderIp() const noexcept
{
    return m_strTargetSenderIp;
}

std::uint64_t AttackRoundContextControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

AuthenticationCryptoAlgorithm
AttackRoundContextControlDetails::algCryptoAlgorithm() const noexcept
{
    return m_algCryptoAlgorithm;
}

UdpAuthenticationMode AttackRoundContextControlDetails::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

std::uint32_t AttackRoundContextControlDetails::u32DataPacketCount() const noexcept
{
    return m_u32DataPacketCount;
}

std::uint32_t AttackRoundContextControlDetails::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t
AttackRoundContextControlDetails::u32IntervalMilliseconds() const noexcept
{
    return m_u32IntervalMilliseconds;
}

std::uint32_t AttackRoundContextControlDetails::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint64_t
AttackRoundContextControlDetails::u64StartTimestampMilliseconds() const noexcept
{
    return m_u64StartTimestampMilliseconds;
}

std::uint32_t AttackRoundContextControlDetails::u32GroupSize() const noexcept
{
    return m_u32GroupSize;
}

std::uint32_t AttackRoundContextControlDetails::u32DetectionThreshold() const noexcept
{
    return m_u32DetectionThreshold;
}

std::size_t AttackRoundContextControlDetails::nTauCount() const noexcept
{
    return m_nTauCount;
}

TamperAttackPlanDetails::TamperAttackPlanDetails(
    std::vector<std::uint32_t> vecPacketIndexes,
    std::uint8_t u8MessageByteOffset,
    std::uint8_t u8XorMask,
    std::uint32_t u32RepeatCount
)
    : m_vecPacketIndexes(std::move(vecPacketIndexes)),
      m_u8MessageByteOffset(u8MessageByteOffset),
      m_u8XorMask(u8XorMask),
      m_u32RepeatCount(u32RepeatCount)
{
    validatePacketIndexes(m_vecPacketIndexes);
    if (m_u8MessageByteOffset >= 32U
        || m_u8XorMask == 0
        || m_u32RepeatCount == 0
        || m_u32RepeatCount > MAX_ATTACK_REPEAT_COUNT)
    {
        throw std::invalid_argument("Tamper attack parameters are outside safe limits");
    }
}

const std::vector<std::uint32_t>& TamperAttackPlanDetails::vecPacketIndexes() const noexcept
{
    return m_vecPacketIndexes;
}

std::uint8_t TamperAttackPlanDetails::u8MessageByteOffset() const noexcept
{
    return m_u8MessageByteOffset;
}

std::uint8_t TamperAttackPlanDetails::u8XorMask() const noexcept
{
    return m_u8XorMask;
}

std::uint32_t TamperAttackPlanDetails::u32RepeatCount() const noexcept
{
    return m_u32RepeatCount;
}

ReplayAttackPlanDetails::ReplayAttackPlanDetails(
    std::vector<std::uint32_t> vecPacketIndexes,
    std::uint32_t u32ReplayDelayMilliseconds,
    std::uint32_t u32RepeatCount,
    std::uint32_t u32RepeatGapMilliseconds
)
    : m_vecPacketIndexes(std::move(vecPacketIndexes)),
      m_u32ReplayDelayMilliseconds(u32ReplayDelayMilliseconds),
      m_u32RepeatCount(u32RepeatCount),
      m_u32RepeatGapMilliseconds(u32RepeatGapMilliseconds)
{
    validatePacketIndexes(m_vecPacketIndexes);
    if (m_u32ReplayDelayMilliseconds == 0
        || m_u32RepeatCount == 0
        || m_u32RepeatCount > MAX_ATTACK_REPEAT_COUNT
        || (m_u32RepeatCount > 1 && m_u32RepeatGapMilliseconds == 0))
    {
        throw std::invalid_argument("Replay attack parameters are invalid");
    }
}

const std::vector<std::uint32_t>& ReplayAttackPlanDetails::vecPacketIndexes() const noexcept
{
    return m_vecPacketIndexes;
}

std::uint32_t ReplayAttackPlanDetails::u32ReplayDelayMilliseconds() const noexcept
{
    return m_u32ReplayDelayMilliseconds;
}

std::uint32_t ReplayAttackPlanDetails::u32RepeatCount() const noexcept
{
    return m_u32RepeatCount;
}

std::uint32_t ReplayAttackPlanDetails::u32RepeatGapMilliseconds() const noexcept
{
    return m_u32RepeatGapMilliseconds;
}

DosAttackPlanDetails::DosAttackPlanDetails(
    std::uint32_t u32RatePacketsPerSecond,
    std::uint32_t u32DurationMilliseconds,
    std::uint32_t u32PacketBytes
)
    : m_u32RatePacketsPerSecond(u32RatePacketsPerSecond),
      m_u32DurationMilliseconds(u32DurationMilliseconds),
      m_u32PacketBytes(u32PacketBytes)
{
    if (m_u32RatePacketsPerSecond == 0
        || m_u32RatePacketsPerSecond > MAX_DOS_RATE_PPS
        || m_u32DurationMilliseconds == 0
        || m_u32DurationMilliseconds > MAX_DOS_DURATION_MILLISECONDS
        || m_u32PacketBytes == 0
        || m_u32PacketBytes > MAX_DOS_PACKET_BYTES)
    {
        throw std::invalid_argument("DoS parameters exceed internal safe limits");
    }
}

std::uint32_t DosAttackPlanDetails::u32RatePacketsPerSecond() const noexcept
{
    return m_u32RatePacketsPerSecond;
}

std::uint32_t DosAttackPlanDetails::u32DurationMilliseconds() const noexcept
{
    return m_u32DurationMilliseconds;
}

std::uint32_t DosAttackPlanDetails::u32PacketBytes() const noexcept
{
    return m_u32PacketBytes;
}

AttackPlanControlDetails::AttackPlanControlDetails(
    std::uint64_t u64AttackId,
    std::string strRoundId,
    std::string strTargetSenderId,
    std::uint64_t u64ChainId,
    AttackPlanDetails varPlanDetails
)
    : m_u64AttackId(u64AttackId),
      m_strRoundId(std::move(strRoundId)),
      m_strTargetSenderId(std::move(strTargetSenderId)),
      m_u64ChainId(u64ChainId),
      m_varPlanDetails(std::move(varPlanDetails))
{
    if (m_u64AttackId == 0 || m_strRoundId.empty())
    {
        throw std::invalid_argument("Attack plan identity is invalid");
    }
    if (typeAttack() != AttackType::Dos
        && (m_strTargetSenderId.empty() || m_u64ChainId == 0))
    {
        throw std::invalid_argument("Capture attack requires target sender and chain");
    }
}

std::uint64_t AttackPlanControlDetails::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

const std::string& AttackPlanControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

const std::string& AttackPlanControlDetails::strTargetSenderId() const noexcept
{
    return m_strTargetSenderId;
}

std::uint64_t AttackPlanControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

AttackType AttackPlanControlDetails::typeAttack() const noexcept
{
    if (std::holds_alternative<TamperAttackPlanDetails>(m_varPlanDetails))
    {
        return AttackType::Tamper;
    }
    if (std::holds_alternative<ReplayAttackPlanDetails>(m_varPlanDetails))
    {
        return AttackType::Replay;
    }
    return AttackType::Dos;
}

const AttackPlanDetails& AttackPlanControlDetails::varPlanDetails() const noexcept
{
    return m_varPlanDetails;
}

AttackPlanAcceptedControlDetails::AttackPlanAcceptedControlDetails(
    std::uint64_t u64AttackId,
    std::string strRoundId,
    bool bAccepted,
    std::string strErrorCode,
    std::string strMessage
)
    : m_u64AttackId(u64AttackId),
      m_strRoundId(std::move(strRoundId)),
      m_bAccepted(bAccepted),
      m_strErrorCode(std::move(strErrorCode)),
      m_strMessage(std::move(strMessage))
{
    if (m_u64AttackId == 0 || m_strRoundId.empty() || m_strMessage.empty())
    {
        throw std::invalid_argument("Attack plan acknowledgement is incomplete");
    }
    if (m_bAccepted && !m_strErrorCode.empty())
    {
        throw std::invalid_argument("Accepted attack plan must not contain an error code");
    }
    if (!m_bAccepted && m_strErrorCode.empty())
    {
        throw std::invalid_argument("Rejected attack plan requires an error code");
    }
}

std::uint64_t AttackPlanAcceptedControlDetails::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

const std::string& AttackPlanAcceptedControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

bool AttackPlanAcceptedControlDetails::bAccepted() const noexcept
{
    return m_bAccepted;
}

const std::string& AttackPlanAcceptedControlDetails::strErrorCode() const noexcept
{
    return m_strErrorCode;
}

const std::string& AttackPlanAcceptedControlDetails::strMessage() const noexcept
{
    return m_strMessage;
}

AttackReadyControlDetails::AttackReadyControlDetails(
    std::uint64_t u64AttackId,
    std::string strRoundId,
    std::uint64_t u64TimestampMilliseconds
)
    : m_u64AttackId(u64AttackId),
      m_strRoundId(std::move(strRoundId)),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds)
{
    if (m_u64AttackId == 0
        || m_strRoundId.empty()
        || m_u64TimestampMilliseconds == 0)
    {
        throw std::invalid_argument("Attack ready acknowledgement is incomplete");
    }
}

std::uint64_t AttackReadyControlDetails::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

const std::string& AttackReadyControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

std::uint64_t AttackReadyControlDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

AttackRoundCommandControlDetails::AttackRoundCommandControlDetails(
    AttackControlMessageType typeMessage,
    std::uint64_t u64AttackId,
    std::string strRoundId,
    std::uint64_t u64ExecutionTimestampMilliseconds
)
    : m_typeMessage(typeMessage),
      m_u64AttackId(u64AttackId),
      m_strRoundId(std::move(strRoundId)),
      m_u64ExecutionTimestampMilliseconds(u64ExecutionTimestampMilliseconds)
{
    if (m_typeMessage != AttackControlMessageType::RoundStart
        && m_typeMessage != AttackControlMessageType::Stop
        && m_typeMessage != AttackControlMessageType::EmergencyStop)
    {
        throw std::invalid_argument("Attack command has an invalid message type");
    }
    if (m_u64AttackId == 0 || m_strRoundId.empty())
    {
        throw std::invalid_argument("Attack command identity is invalid");
    }
    if (m_typeMessage == AttackControlMessageType::RoundStart
        && m_u64ExecutionTimestampMilliseconds == 0)
    {
        throw std::invalid_argument("Attack start requires an execution timestamp");
    }
}

AttackControlMessageType AttackRoundCommandControlDetails::typeMessage() const noexcept
{
    return m_typeMessage;
}

std::uint64_t AttackRoundCommandControlDetails::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

const std::string& AttackRoundCommandControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

std::uint64_t AttackRoundCommandControlDetails::u64ExecutionTimestampMilliseconds() const noexcept
{
    return m_u64ExecutionTimestampMilliseconds;
}

TamperAttackStatusDetails::TamperAttackStatusDetails(
    std::uint64_t u64CapturedPacketCount,
    std::uint64_t u64InjectedPacketCount,
    std::uint64_t u64LastInjectionDelayMicroseconds
)
    : m_u64CapturedPacketCount(u64CapturedPacketCount),
      m_u64InjectedPacketCount(u64InjectedPacketCount),
      m_u64LastInjectionDelayMicroseconds(u64LastInjectionDelayMicroseconds)
{
}

std::uint64_t TamperAttackStatusDetails::u64CapturedPacketCount() const noexcept
{
    return m_u64CapturedPacketCount;
}

std::uint64_t TamperAttackStatusDetails::u64InjectedPacketCount() const noexcept
{
    return m_u64InjectedPacketCount;
}

std::uint64_t TamperAttackStatusDetails::u64LastInjectionDelayMicroseconds() const noexcept
{
    return m_u64LastInjectionDelayMicroseconds;
}

ReplayAttackStatusDetails::ReplayAttackStatusDetails(
    std::uint64_t u64CapturedPacketCount,
    std::uint64_t u64ReplayedPacketCount
)
    : m_u64CapturedPacketCount(u64CapturedPacketCount),
      m_u64ReplayedPacketCount(u64ReplayedPacketCount)
{
}

std::uint64_t ReplayAttackStatusDetails::u64CapturedPacketCount() const noexcept
{
    return m_u64CapturedPacketCount;
}

std::uint64_t ReplayAttackStatusDetails::u64ReplayedPacketCount() const noexcept
{
    return m_u64ReplayedPacketCount;
}

DosAttackStatusDetails::DosAttackStatusDetails(
    std::uint64_t u64SentPacketCount,
    std::uint64_t u64SentByteCount,
    double dActualPacketsPerSecond
)
    : m_u64SentPacketCount(u64SentPacketCount),
      m_u64SentByteCount(u64SentByteCount),
      m_dActualPacketsPerSecond(dActualPacketsPerSecond)
{
    if (!std::isfinite(m_dActualPacketsPerSecond)
        || m_dActualPacketsPerSecond < 0.0)
    {
        throw std::invalid_argument("DoS actual PPS must be finite and non-negative");
    }
}

std::uint64_t DosAttackStatusDetails::u64SentPacketCount() const noexcept
{
    return m_u64SentPacketCount;
}

std::uint64_t DosAttackStatusDetails::u64SentByteCount() const noexcept
{
    return m_u64SentByteCount;
}

double DosAttackStatusDetails::dActualPacketsPerSecond() const noexcept
{
    return m_dActualPacketsPerSecond;
}

AttackExecutionStatusControlDetails::AttackExecutionStatusControlDetails(
    std::uint64_t u64AttackId,
    std::string strRoundId,
    AttackExecutionState stateExecution,
    AttackExecutionStatusDetails varStatusDetails,
    std::uint64_t u64SendErrorCount,
    std::uint64_t u64TimestampMilliseconds,
    std::string strMessage
)
    : m_u64AttackId(u64AttackId),
      m_strRoundId(std::move(strRoundId)),
      m_stateExecution(stateExecution),
      m_varStatusDetails(std::move(varStatusDetails)),
      m_u64SendErrorCount(u64SendErrorCount),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strMessage(std::move(strMessage))
{
    if (m_u64AttackId == 0
        || m_strRoundId.empty()
        || m_u64TimestampMilliseconds == 0
        || m_strMessage.empty())
    {
        throw std::invalid_argument("Attack execution status is incomplete");
    }
}

std::uint64_t AttackExecutionStatusControlDetails::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

const std::string& AttackExecutionStatusControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

AttackExecutionState AttackExecutionStatusControlDetails::stateExecution() const noexcept
{
    return m_stateExecution;
}

AttackType AttackExecutionStatusControlDetails::typeAttack() const noexcept
{
    if (std::holds_alternative<TamperAttackStatusDetails>(m_varStatusDetails))
    {
        return AttackType::Tamper;
    }
    if (std::holds_alternative<ReplayAttackStatusDetails>(m_varStatusDetails))
    {
        return AttackType::Replay;
    }
    return AttackType::Dos;
}

const AttackExecutionStatusDetails& AttackExecutionStatusControlDetails::varStatusDetails() const noexcept
{
    return m_varStatusDetails;
}

std::uint64_t AttackExecutionStatusControlDetails::u64SendErrorCount() const noexcept
{
    return m_u64SendErrorCount;
}

std::uint64_t AttackExecutionStatusControlDetails::u64TimestampMilliseconds() const noexcept
{
    return m_u64TimestampMilliseconds;
}

const std::string& AttackExecutionStatusControlDetails::strMessage() const noexcept
{
    return m_strMessage;
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
    if (std::holds_alternative<AttackRoundContextControlDetails>(m_varDetails))
    {
        return AttackControlMessageType::RoundContext;
    }
    if (std::holds_alternative<AttackPlanControlDetails>(m_varDetails))
    {
        return AttackControlMessageType::Plan;
    }
    if (std::holds_alternative<AttackPlanAcceptedControlDetails>(m_varDetails))
    {
        return AttackControlMessageType::PlanAccepted;
    }
    if (std::holds_alternative<AttackReadyControlDetails>(m_varDetails))
    {
        return AttackControlMessageType::Ready;
    }
    if (std::holds_alternative<AttackRoundCommandControlDetails>(m_varDetails))
    {
        return std::get<AttackRoundCommandControlDetails>(m_varDetails)
            .typeMessage();
    }
    if (std::holds_alternative<AttackExecutionStatusControlDetails>(
            m_varDetails
        ))
    {
        return AttackControlMessageType::ExecutionStatus;
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
        jsnMessage["executionState"] = pExecutionStateName(
            detStatus.stateExecution()
        );
        jsnMessage["timestampMs"] = detStatus.u64TimestampMilliseconds();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::RoundContext)
    {
        const AttackRoundContextControlDetails& detContext =
            std::get<AttackRoundContextControlDetails>(msgMessage.varDetails());
        jsnMessage["requestId"] = detContext.strRequestId();
        jsnMessage["roundId"] = detContext.strRoundId();
        jsnMessage["targetSenderId"] = detContext.strTargetSenderId();
        jsnMessage["targetSenderIp"] = detContext.strTargetSenderIp();
        jsnMessage["chainId"] = detContext.u64ChainId();
        jsnMessage["cryptoAlgorithm"] = pCryptoAlgorithmName(
            detContext.algCryptoAlgorithm()
        );
        jsnMessage["authenticationMode"] = pModeName(
            detContext.modeAuthentication()
        );
        jsnMessage["dataPacketCount"] = detContext.u32DataPacketCount();
        jsnMessage["packetsPerInterval"] =
            detContext.u32PacketsPerInterval();
        jsnMessage["intervalMs"] = detContext.u32IntervalMilliseconds();
        jsnMessage["disclosureDelay"] = detContext.u32DisclosureDelay();
        jsnMessage["startTimestampMs"] =
            detContext.u64StartTimestampMilliseconds();
        jsnMessage["groupSize"] = detContext.u32GroupSize();
        jsnMessage["detectionThreshold"] =
            detContext.u32DetectionThreshold();
        jsnMessage["tauCount"] = detContext.nTauCount();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::Plan)
    {
        const AttackPlanControlDetails& detPlan =
            std::get<AttackPlanControlDetails>(msgMessage.varDetails());
        jsnMessage["attackId"] = detPlan.u64AttackId();
        jsnMessage["roundId"] = detPlan.strRoundId();
        jsnMessage["targetSenderId"] = detPlan.strTargetSenderId();
        jsnMessage["chainId"] = detPlan.u64ChainId();
        jsnMessage.update(jsnEncodePlanDetails(detPlan.varPlanDetails()));
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::PlanAccepted)
    {
        const AttackPlanAcceptedControlDetails& detAccepted =
            std::get<AttackPlanAcceptedControlDetails>(msgMessage.varDetails());
        jsnMessage["attackId"] = detAccepted.u64AttackId();
        jsnMessage["roundId"] = detAccepted.strRoundId();
        jsnMessage["accepted"] = detAccepted.bAccepted();
        jsnMessage["errorCode"] = detAccepted.strErrorCode();
        jsnMessage["message"] = detAccepted.strMessage();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::Ready)
    {
        const AttackReadyControlDetails& detReady =
            std::get<AttackReadyControlDetails>(msgMessage.varDetails());
        jsnMessage["attackId"] = detReady.u64AttackId();
        jsnMessage["roundId"] = detReady.strRoundId();
        jsnMessage["timestampMs"] = detReady.u64TimestampMilliseconds();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::RoundStart
        || msgMessage.typeMessage() == AttackControlMessageType::Stop
        || msgMessage.typeMessage() == AttackControlMessageType::EmergencyStop)
    {
        const AttackRoundCommandControlDetails& detCommand =
            std::get<AttackRoundCommandControlDetails>(msgMessage.varDetails());
        jsnMessage["attackId"] = detCommand.u64AttackId();
        jsnMessage["roundId"] = detCommand.strRoundId();
        jsnMessage["executionTimestampMs"] =
            detCommand.u64ExecutionTimestampMilliseconds();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::ExecutionStatus)
    {
        const AttackExecutionStatusControlDetails& detStatus = std::get<
            AttackExecutionStatusControlDetails
        >(msgMessage.varDetails());
        jsnMessage["attackId"] = detStatus.u64AttackId();
        jsnMessage["roundId"] = detStatus.strRoundId();
        jsnMessage["executionState"] = pExecutionStateName(
            detStatus.stateExecution()
        );
        jsnMessage["sendErrors"] = detStatus.u64SendErrorCount();
        jsnMessage["timestampMs"] = detStatus.u64TimestampMilliseconds();
        jsnMessage["message"] = detStatus.strMessage();
        jsnMessage.update(jsnEncodeExecutionDetails(
            detStatus.varStatusDetails()
        ));
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
                stateParse(jsnMessage.at("executionState").get<std::string>()),
                jsnMessage.at("timestampMs").get<std::uint64_t>()
            ));
        }
        if (strType == "ATTACK_ROUND_CONTEXT")
        {
            return AttackControlMessage(AttackRoundContextControlDetails(
                jsnMessage.at("requestId").get<std::string>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.at("targetSenderId").get<std::string>(),
                jsnMessage.at("targetSenderIp").get<std::string>(),
                jsnMessage.at("chainId").get<std::uint64_t>(),
                algCryptoParse(jsnMessage.at("cryptoAlgorithm").get<std::string>()),
                modeParse(jsnMessage.at("authenticationMode").get<std::string>()),
                jsnMessage.at("dataPacketCount").get<std::uint32_t>(),
                jsnMessage.at("packetsPerInterval").get<std::uint32_t>(),
                jsnMessage.at("intervalMs").get<std::uint32_t>(),
                jsnMessage.at("disclosureDelay").get<std::uint32_t>(),
                jsnMessage.at("startTimestampMs").get<std::uint64_t>(),
                jsnMessage.at("groupSize").get<std::uint32_t>(),
                jsnMessage.at("detectionThreshold").get<std::uint32_t>(),
                jsnMessage.at("tauCount").get<std::size_t>()
            ));
        }
        if (strType == "ATTACK_PLAN")
        {
            return AttackControlMessage(AttackPlanControlDetails(
                jsnMessage.at("attackId").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.value("targetSenderId", std::string()),
                jsnMessage.value("chainId", std::uint64_t(0)),
                varDecodePlanDetails(jsnMessage)
            ));
        }
        if (strType == "ATTACK_PLAN_ACCEPTED")
        {
            return AttackControlMessage(AttackPlanAcceptedControlDetails(
                jsnMessage.at("attackId").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.at("accepted").get<bool>(),
                jsnMessage.value("errorCode", std::string()),
                jsnMessage.at("message").get<std::string>()
            ));
        }
        if (strType == "ATTACK_READY")
        {
            return AttackControlMessage(AttackReadyControlDetails(
                jsnMessage.at("attackId").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.at("timestampMs").get<std::uint64_t>()
            ));
        }
        if (strType == "ROUND_START"
            || strType == "ATTACK_STOP"
            || strType == "ATTACK_EMERGENCY_STOP")
        {
            AttackControlMessageType typeMessage =
                AttackControlMessageType::RoundStart;
            if (strType == "ATTACK_STOP")
            {
                typeMessage = AttackControlMessageType::Stop;
            }
            else if (strType == "ATTACK_EMERGENCY_STOP")
            {
                typeMessage = AttackControlMessageType::EmergencyStop;
            }

            return AttackControlMessage(AttackRoundCommandControlDetails(
                typeMessage,
                jsnMessage.at("attackId").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                jsnMessage.value("executionTimestampMs", std::uint64_t(0))
            ));
        }
        if (strType == "ATTACK_STATUS")
        {
            return AttackControlMessage(AttackExecutionStatusControlDetails(
                jsnMessage.at("attackId").get<std::uint64_t>(),
                jsnMessage.at("roundId").get<std::string>(),
                stateParse(jsnMessage.at("executionState").get<std::string>()),
                varDecodeExecutionDetails(jsnMessage),
                jsnMessage.at("sendErrors").get<std::uint64_t>(),
                jsnMessage.at("timestampMs").get<std::uint64_t>(),
                jsnMessage.at("message").get<std::string>()
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

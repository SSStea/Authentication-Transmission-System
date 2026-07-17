#include "tesla/protocol/ExperimentControl.h"

#include <cmath>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
void validateText(const std::string& strValue, const char* pName)
{
    if (strValue.empty() || strValue.size() > 1024U)
    {
        throw std::invalid_argument(std::string(pName) + " has an invalid length");
    }
}
}

PacketLossFaultDetails::PacketLossFaultDetails(
    double dLossRatePercent,
    std::uint64_t u64RandomSeed,
    std::uint32_t u32ProtectedGroupSize
)
    : m_dLossRatePercent(dLossRatePercent),
      m_u64RandomSeed(u64RandomSeed),
      m_u32ProtectedGroupSize(u32ProtectedGroupSize)
{
    if (!std::isfinite(m_dLossRatePercent)
        || m_dLossRatePercent < 0.0
        || m_dLossRatePercent > 100.0
        || m_u64RandomSeed == 0
        || m_u32ProtectedGroupSize == 0)
    {
        throw std::invalid_argument("Packet loss fault parameters are invalid");
    }
}

double PacketLossFaultDetails::dLossRatePercent() const noexcept
{
    return m_dLossRatePercent;
}

std::uint64_t PacketLossFaultDetails::u64RandomSeed() const noexcept
{
    return m_u64RandomSeed;
}

std::uint32_t PacketLossFaultDetails::u32ProtectedGroupSize() const noexcept
{
    return m_u32ProtectedGroupSize;
}

LogicalDisconnectFaultDetails::LogicalDisconnectFaultDetails(
    std::uint32_t u32StartPacketIndex,
    std::uint32_t u32DurationMilliseconds,
    std::uint32_t u32ProtectedGroupSize
)
    : m_u32StartPacketIndex(u32StartPacketIndex),
      m_u32DurationMilliseconds(u32DurationMilliseconds),
      m_u32ProtectedGroupSize(u32ProtectedGroupSize)
{
    if (m_u32StartPacketIndex == 0
        || m_u32DurationMilliseconds == 0
        || m_u32ProtectedGroupSize == 0)
    {
        throw std::invalid_argument("Logical disconnect parameters are invalid");
    }
}

std::uint32_t LogicalDisconnectFaultDetails::u32StartPacketIndex() const noexcept
{
    return m_u32StartPacketIndex;
}

std::uint32_t LogicalDisconnectFaultDetails::u32DurationMilliseconds() const noexcept
{
    return m_u32DurationMilliseconds;
}

std::uint32_t LogicalDisconnectFaultDetails::u32ProtectedGroupSize() const noexcept
{
    return m_u32ProtectedGroupSize;
}

FixedDelayFaultDetails::FixedDelayFaultDetails(
    std::uint32_t u32DelayMilliseconds
)
    : m_u32DelayMilliseconds(u32DelayMilliseconds)
{
    if (m_u32DelayMilliseconds > 10000U)
    {
        throw std::invalid_argument("Fixed delay exceeds the internal safe limit");
    }
}

std::uint32_t FixedDelayFaultDetails::u32DelayMilliseconds() const noexcept
{
    return m_u32DelayMilliseconds;
}

FaultInjectionControlDetails::FaultInjectionControlDetails(
    std::string strRequestId,
    std::string strRoundId,
    std::string strTargetSenderId,
    std::uint64_t u64ChainId,
    AuthenticationFaultDetails varFaultDetails
)
    : m_strRequestId(std::move(strRequestId)),
      m_strRoundId(std::move(strRoundId)),
      m_strTargetSenderId(std::move(strTargetSenderId)),
      m_u64ChainId(u64ChainId),
      m_varFaultDetails(std::move(varFaultDetails))
{
    validateText(m_strRequestId, "Fault request ID");
    validateText(m_strRoundId, "Fault round ID");
    validateText(m_strTargetSenderId, "Fault target sender ID");
    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Fault target chain ID must be positive");
    }
}

const std::string& FaultInjectionControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& FaultInjectionControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

const std::string& FaultInjectionControlDetails::strTargetSenderId() const noexcept
{
    return m_strTargetSenderId;
}

std::uint64_t FaultInjectionControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const AuthenticationFaultDetails& FaultInjectionControlDetails::varFaultDetails() const noexcept
{
    return m_varFaultDetails;
}

AttackSourceMappingControlDetails::AttackSourceMappingControlDetails(
    std::string strRequestId,
    std::string strRoundId,
    AttackSourceMappingAction actAction,
    std::string strTargetSenderId,
    std::string strTargetSenderIp,
    std::string strAttackSourceIp,
    std::uint64_t u64ChainId,
    std::uint64_t u64ExpiresAtMilliseconds
)
    : m_strRequestId(std::move(strRequestId)),
      m_strRoundId(std::move(strRoundId)),
      m_actAction(actAction),
      m_strTargetSenderId(std::move(strTargetSenderId)),
      m_strTargetSenderIp(std::move(strTargetSenderIp)),
      m_strAttackSourceIp(std::move(strAttackSourceIp)),
      m_u64ChainId(u64ChainId),
      m_u64ExpiresAtMilliseconds(u64ExpiresAtMilliseconds)
{
    validateText(m_strRequestId, "Attack source mapping request ID");
    validateText(m_strRoundId, "Attack source mapping round ID");
    validateText(m_strTargetSenderId, "Attack source mapping sender ID");
    validateText(m_strTargetSenderIp, "Attack source mapping sender IP");
    validateText(m_strAttackSourceIp, "Attack source mapping attacker IP");
    if (m_strTargetSenderIp == m_strAttackSourceIp || m_u64ChainId == 0)
    {
        throw std::invalid_argument("Attack source mapping identity is invalid");
    }
    if (m_actAction == AttackSourceMappingAction::Install
        && m_u64ExpiresAtMilliseconds == 0)
    {
        throw std::invalid_argument("Installed attack source mapping requires expiry");
    }
}

const std::string& AttackSourceMappingControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& AttackSourceMappingControlDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

AttackSourceMappingAction AttackSourceMappingControlDetails::actAction() const noexcept
{
    return m_actAction;
}

const std::string& AttackSourceMappingControlDetails::strTargetSenderId() const noexcept
{
    return m_strTargetSenderId;
}

const std::string& AttackSourceMappingControlDetails::strTargetSenderIp() const noexcept
{
    return m_strTargetSenderIp;
}

const std::string& AttackSourceMappingControlDetails::strAttackSourceIp() const noexcept
{
    return m_strAttackSourceIp;
}

std::uint64_t AttackSourceMappingControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint64_t AttackSourceMappingControlDetails::u64ExpiresAtMilliseconds() const noexcept
{
    return m_u64ExpiresAtMilliseconds;
}

ExperimentControlAcknowledgementDetails::ExperimentControlAcknowledgementDetails(
    std::string strRequestId,
    std::string strRoundId,
    bool bAccepted,
    std::string strErrorCode,
    std::string strMessage
)
    : m_strRequestId(std::move(strRequestId)),
      m_strRoundId(std::move(strRoundId)),
      m_bAccepted(bAccepted),
      m_strErrorCode(std::move(strErrorCode)),
      m_strMessage(std::move(strMessage))
{
    validateText(m_strRequestId, "Experiment acknowledgement request ID");
    validateText(m_strRoundId, "Experiment acknowledgement round ID");
    validateText(m_strMessage, "Experiment acknowledgement message");
    if ((m_bAccepted && !m_strErrorCode.empty())
        || (!m_bAccepted && m_strErrorCode.empty()))
    {
        throw std::invalid_argument("Experiment acknowledgement result is inconsistent");
    }
}

const std::string& ExperimentControlAcknowledgementDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string& ExperimentControlAcknowledgementDetails::strRoundId() const noexcept
{
    return m_strRoundId;
}

bool ExperimentControlAcknowledgementDetails::bAccepted() const noexcept
{
    return m_bAccepted;
}

const std::string& ExperimentControlAcknowledgementDetails::strErrorCode() const noexcept
{
    return m_strErrorCode;
}

const std::string& ExperimentControlAcknowledgementDetails::strMessage() const noexcept
{
    return m_strMessage;
}
}

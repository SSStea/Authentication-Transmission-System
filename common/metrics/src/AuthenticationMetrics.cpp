#include "tesla/metrics/AuthenticationMetrics.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tesla::metrics
{
namespace
{
void validateIdentity(
    const std::string& strRoundId,
    const std::string& strSenderId,
    std::uint32_t u32PacketCount
)
{
    if (strRoundId.empty() || strSenderId.empty() || u32PacketCount == 0)
    {
        throw std::invalid_argument("Authentication metric identity is invalid");
    }
}
}

HardwarePerformanceCounters::HardwarePerformanceCounters(
    HardwareCounterStatus statusCounters,
    std::uint64_t u64CpuCycles,
    std::uint64_t u64CacheReferences,
    std::uint64_t u64CacheMisses
)
    : m_statusCounters(statusCounters),
      m_u64CpuCycles(u64CpuCycles),
      m_u64CacheReferences(u64CacheReferences),
      m_u64CacheMisses(u64CacheMisses)
{
}

HardwareCounterStatus HardwarePerformanceCounters::statusCounters() const noexcept
{
    return m_statusCounters;
}

std::uint64_t HardwarePerformanceCounters::u64CpuCycles() const noexcept
{
    return m_u64CpuCycles;
}

std::uint64_t HardwarePerformanceCounters::u64CacheReferences() const noexcept
{
    return m_u64CacheReferences;
}

std::uint64_t HardwarePerformanceCounters::u64CacheMisses() const noexcept
{
    return m_u64CacheMisses;
}

double HardwarePerformanceCounters::dCacheHitRate() const noexcept
{
    if (m_statusCounters != HardwareCounterStatus::Supported
        || m_u64CacheReferences == 0)
    {
        return 0.0;
    }

    const double dMissRate = static_cast<double>(m_u64CacheMisses)
        / static_cast<double>(m_u64CacheReferences);
    return std::clamp(1.0 - dMissRate, 0.0, 1.0);
}

PerformanceMeasurement::PerformanceMeasurement(
    std::uint64_t u64DurationNanoseconds,
    HardwarePerformanceCounters ctrHardware
)
    : m_u64DurationNanoseconds(u64DurationNanoseconds),
      m_ctrHardware(std::move(ctrHardware))
{
}

std::uint64_t PerformanceMeasurement::u64DurationNanoseconds() const noexcept
{
    return m_u64DurationNanoseconds;
}

const HardwarePerformanceCounters& PerformanceMeasurement::ctrHardware() const noexcept
{
    return m_ctrHardware;
}

NativeVerificationMetricDetails::NativeVerificationMetricDetails(
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex
)
    : m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex)
{
    if (m_u32IntervalIndex == 0 || m_u32PacketIndex == 0)
    {
        throw std::invalid_argument("Native verification metric index is invalid");
    }
}

std::uint32_t NativeVerificationMetricDetails::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

std::uint32_t NativeVerificationMetricDetails::u32PacketIndex() const noexcept
{
    return m_u32PacketIndex;
}

ImprovedVerificationMetricDetails::ImprovedVerificationMetricDetails(
    std::uint32_t u32GroupIndex,
    std::uint32_t u32FirstPacketIndex,
    std::uint32_t u32LastPacketIndex,
    VerificationMetricPath pathVerification
)
    : m_u32GroupIndex(u32GroupIndex),
      m_u32FirstPacketIndex(u32FirstPacketIndex),
      m_u32LastPacketIndex(u32LastPacketIndex),
      m_pathVerification(pathVerification)
{
    if (m_u32GroupIndex == 0
        || m_u32FirstPacketIndex == 0
        || m_u32LastPacketIndex < m_u32FirstPacketIndex
        || m_pathVerification == VerificationMetricPath::NativePacketVerify)
    {
        throw std::invalid_argument("Improved verification metric details are invalid");
    }
}

std::uint32_t ImprovedVerificationMetricDetails::u32GroupIndex() const noexcept
{
    return m_u32GroupIndex;
}

std::uint32_t ImprovedVerificationMetricDetails::u32FirstPacketIndex() const noexcept
{
    return m_u32FirstPacketIndex;
}

std::uint32_t ImprovedVerificationMetricDetails::u32LastPacketIndex() const noexcept
{
    return m_u32LastPacketIndex;
}

VerificationMetricPath ImprovedVerificationMetricDetails::pathVerification() const noexcept
{
    return m_pathVerification;
}

VerificationMetricSample::VerificationMetricSample(
    std::uint64_t u64EventId,
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32PacketCount,
    PerformanceMeasurement mstPerformance,
    VerificationMetricDetails varDetails
)
    : m_u64EventId(u64EventId),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32PacketCount(u32PacketCount),
      m_mstPerformance(std::move(mstPerformance)),
      m_varDetails(std::move(varDetails))
{
    validateIdentity(m_strRoundId, m_strSenderId, m_u32PacketCount);
    if (m_u64EventId == 0 || m_u64TimestampMilliseconds == 0)
    {
        throw std::invalid_argument("Verification metric event identity is invalid");
    }
}

std::uint64_t VerificationMetricSample::u64EventId() const noexcept { return m_u64EventId; }
std::uint64_t VerificationMetricSample::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& VerificationMetricSample::strRoundId() const noexcept { return m_strRoundId; }
const std::string& VerificationMetricSample::strSenderId() const noexcept { return m_strSenderId; }
std::uint64_t VerificationMetricSample::u64ChainId() const noexcept { return m_u64ChainId; }
std::uint32_t VerificationMetricSample::u32PacketCount() const noexcept { return m_u32PacketCount; }
const PerformanceMeasurement& VerificationMetricSample::mstPerformance() const noexcept { return m_mstPerformance; }
const VerificationMetricDetails& VerificationMetricSample::varDetails() const noexcept { return m_varDetails; }

AuthenticationMetricMode VerificationMetricSample::modeAuthentication() const noexcept
{
    return std::holds_alternative<NativeVerificationMetricDetails>(m_varDetails)
        ? AuthenticationMetricMode::Native
        : AuthenticationMetricMode::Improved;
}

VerificationMetricPath VerificationMetricSample::pathVerification() const noexcept
{
    const auto* pImproved = std::get_if<ImprovedVerificationMetricDetails>(
        &m_varDetails
    );
    return pImproved == nullptr
        ? VerificationMetricPath::NativePacketVerify
        : pImproved->pathVerification();
}

double VerificationMetricSample::dAveragePacketVerifyTimeMicroseconds() const noexcept
{
    return static_cast<double>(m_mstPerformance.u64DurationNanoseconds())
        / 1000.0 / static_cast<double>(m_u32PacketCount);
}

NativeRoundMetricDetails::NativeRoundMetricDetails(
    std::uint32_t u32VerifiedPacketCount
)
    : m_u32VerifiedPacketCount(u32VerifiedPacketCount)
{
}

std::uint32_t NativeRoundMetricDetails::u32VerifiedPacketCount() const noexcept
{
    return m_u32VerifiedPacketCount;
}

ImprovedRoundMetricDetails::ImprovedRoundMetricDetails(
    std::uint32_t u32FastGroupCount,
    std::uint32_t u32FallbackGroupCount,
    std::uint32_t u32IncompleteGroupCount
)
    : m_u32FastGroupCount(u32FastGroupCount),
      m_u32FallbackGroupCount(u32FallbackGroupCount),
      m_u32IncompleteGroupCount(u32IncompleteGroupCount)
{
}

std::uint32_t ImprovedRoundMetricDetails::u32FastGroupCount() const noexcept { return m_u32FastGroupCount; }
std::uint32_t ImprovedRoundMetricDetails::u32FallbackGroupCount() const noexcept { return m_u32FallbackGroupCount; }
std::uint32_t ImprovedRoundMetricDetails::u32IncompleteGroupCount() const noexcept { return m_u32IncompleteGroupCount; }

EstimatedEnergyMetricSummary::EstimatedEnergyMetricSummary(
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32PacketCount,
    std::uint64_t u64VerifyTimeNanoseconds,
    std::uint64_t u64ReceivedAuthBytes,
    double dEstimatedEnergyMicroJoule,
    bool bNormalComparisonEligible,
    AuthenticationRoundMetricDetails varDetails
)
    : m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32PacketCount(u32PacketCount),
      m_u64VerifyTimeNanoseconds(u64VerifyTimeNanoseconds),
      m_u64ReceivedAuthBytes(u64ReceivedAuthBytes),
      m_dEstimatedEnergyMicroJoule(dEstimatedEnergyMicroJoule),
      m_bNormalComparisonEligible(bNormalComparisonEligible),
      m_varDetails(std::move(varDetails))
{
    validateIdentity(m_strRoundId, m_strSenderId, m_u32PacketCount);
    if (m_u64TimestampMilliseconds == 0 || m_dEstimatedEnergyMicroJoule < 0.0)
    {
        throw std::invalid_argument("Estimated energy metric summary is invalid");
    }
}

std::uint64_t EstimatedEnergyMetricSummary::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& EstimatedEnergyMetricSummary::strRoundId() const noexcept { return m_strRoundId; }
const std::string& EstimatedEnergyMetricSummary::strSenderId() const noexcept { return m_strSenderId; }
std::uint64_t EstimatedEnergyMetricSummary::u64ChainId() const noexcept { return m_u64ChainId; }
std::uint32_t EstimatedEnergyMetricSummary::u32PacketCount() const noexcept { return m_u32PacketCount; }
std::uint64_t EstimatedEnergyMetricSummary::u64VerifyTimeNanoseconds() const noexcept { return m_u64VerifyTimeNanoseconds; }
std::uint64_t EstimatedEnergyMetricSummary::u64ReceivedAuthBytes() const noexcept { return m_u64ReceivedAuthBytes; }
double EstimatedEnergyMetricSummary::dEstimatedEnergyMicroJoule() const noexcept { return m_dEstimatedEnergyMicroJoule; }
double EstimatedEnergyMetricSummary::dEstimatedEnergyMilliJoule() const noexcept { return m_dEstimatedEnergyMicroJoule / 1000.0; }
double EstimatedEnergyMetricSummary::dAveragePacketEnergyMicroJoule() const noexcept { return m_dEstimatedEnergyMicroJoule / static_cast<double>(m_u32PacketCount); }
bool EstimatedEnergyMetricSummary::bNormalComparisonEligible() const noexcept { return m_bNormalComparisonEligible; }
AuthenticationMetricMode EstimatedEnergyMetricSummary::modeAuthentication() const noexcept
{
    return std::holds_alternative<NativeRoundMetricDetails>(m_varDetails)
        ? AuthenticationMetricMode::Native
        : AuthenticationMetricMode::Improved;
}
const AuthenticationRoundMetricDetails& EstimatedEnergyMetricSummary::varDetails() const noexcept { return m_varDetails; }

NativeCommunicationCostDetails::NativeCommunicationCostDetails(
    std::uint64_t u64MessageBytes,
    std::uint64_t u64KeyBytes,
    std::uint64_t u64MacBytes
)
    : m_u64MessageBytes(u64MessageBytes),
      m_u64KeyBytes(u64KeyBytes),
      m_u64MacBytes(u64MacBytes)
{
}

std::uint64_t NativeCommunicationCostDetails::u64MessageBytes() const noexcept { return m_u64MessageBytes; }
std::uint64_t NativeCommunicationCostDetails::u64KeyBytes() const noexcept { return m_u64KeyBytes; }
std::uint64_t NativeCommunicationCostDetails::u64MacBytes() const noexcept { return m_u64MacBytes; }

ImprovedCommunicationCostDetails::ImprovedCommunicationCostDetails(
    std::uint64_t u64MessageBytes,
    std::uint64_t u64KeyBytes,
    std::uint64_t u64TauBytes,
    std::uint64_t u64FastGroupTagBytes
)
    : m_u64MessageBytes(u64MessageBytes),
      m_u64KeyBytes(u64KeyBytes),
      m_u64TauBytes(u64TauBytes),
      m_u64FastGroupTagBytes(u64FastGroupTagBytes)
{
}

std::uint64_t ImprovedCommunicationCostDetails::u64MessageBytes() const noexcept { return m_u64MessageBytes; }
std::uint64_t ImprovedCommunicationCostDetails::u64KeyBytes() const noexcept { return m_u64KeyBytes; }
std::uint64_t ImprovedCommunicationCostDetails::u64TauBytes() const noexcept { return m_u64TauBytes; }
std::uint64_t ImprovedCommunicationCostDetails::u64FastGroupTagBytes() const noexcept { return m_u64FastGroupTagBytes; }

CommunicationCostMetricSummary::CommunicationCostMetricSummary(
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    CommunicationCostDetails varDetails
)
    : m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_varDetails(std::move(varDetails))
{
    if (m_u64TimestampMilliseconds == 0
        || m_strRoundId.empty()
        || m_strSenderId.empty())
    {
        throw std::invalid_argument("Communication cost metric summary is invalid");
    }
}

std::uint64_t CommunicationCostMetricSummary::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& CommunicationCostMetricSummary::strRoundId() const noexcept { return m_strRoundId; }
const std::string& CommunicationCostMetricSummary::strSenderId() const noexcept { return m_strSenderId; }
std::uint64_t CommunicationCostMetricSummary::u64ChainId() const noexcept { return m_u64ChainId; }
AuthenticationMetricMode CommunicationCostMetricSummary::modeAuthentication() const noexcept
{
    return std::holds_alternative<NativeCommunicationCostDetails>(m_varDetails)
        ? AuthenticationMetricMode::Native
        : AuthenticationMetricMode::Improved;
}

std::uint64_t CommunicationCostMetricSummary::u64TotalBytes() const noexcept
{
    if (const auto* pNative = std::get_if<NativeCommunicationCostDetails>(
            &m_varDetails
        ))
    {
        return pNative->u64MessageBytes()
            + pNative->u64KeyBytes()
            + pNative->u64MacBytes();
    }

    const auto& detImproved = std::get<ImprovedCommunicationCostDetails>(
        m_varDetails
    );
    return detImproved.u64MessageBytes()
        + detImproved.u64KeyBytes()
        + detImproved.u64TauBytes()
        + detImproved.u64FastGroupTagBytes();
}

const CommunicationCostDetails& CommunicationCostMetricSummary::varDetails() const noexcept { return m_varDetails; }

AuthenticationRoundArchiveConfiguration::
AuthenticationRoundArchiveConfiguration(
    AuthenticationMetricMode modeAuthentication,
    std::string strCryptoAlgorithm,
    std::string strPayloadHash,
    std::uint32_t u32PacketCount,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32IntervalMilliseconds,
    std::uint32_t u32DisclosureDelay,
    std::uint32_t u32GroupSize,
    std::uint32_t u32DetectionThreshold
)
    : m_modeAuthentication(modeAuthentication),
      m_strCryptoAlgorithm(std::move(strCryptoAlgorithm)),
      m_strPayloadHash(std::move(strPayloadHash)),
      m_u32PacketCount(u32PacketCount),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32IntervalMilliseconds(u32IntervalMilliseconds),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u32GroupSize(u32GroupSize),
      m_u32DetectionThreshold(u32DetectionThreshold)
{
    if (m_strCryptoAlgorithm.empty()
        || m_u32PacketCount == 0
        || m_u32PacketsPerInterval == 0
        || m_u32IntervalMilliseconds == 0
        || m_u32DisclosureDelay == 0
        || (m_modeAuthentication == AuthenticationMetricMode::Native
            && (m_u32GroupSize != 0 || m_u32DetectionThreshold != 0))
        || (m_modeAuthentication == AuthenticationMetricMode::Improved
            && (m_u32GroupSize == 0 || m_u32DetectionThreshold == 0)))
    {
        throw std::invalid_argument("Round archive configuration is invalid");
    }
}

AuthenticationMetricMode AuthenticationRoundArchiveConfiguration::
modeAuthentication() const noexcept { return m_modeAuthentication; }
const std::string& AuthenticationRoundArchiveConfiguration::
strCryptoAlgorithm() const noexcept { return m_strCryptoAlgorithm; }
const std::string& AuthenticationRoundArchiveConfiguration::
strPayloadHash() const noexcept { return m_strPayloadHash; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32PacketCount() const noexcept { return m_u32PacketCount; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32PacketsPerInterval() const noexcept { return m_u32PacketsPerInterval; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32IntervalMilliseconds() const noexcept { return m_u32IntervalMilliseconds; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32DisclosureDelay() const noexcept { return m_u32DisclosureDelay; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32GroupSize() const noexcept { return m_u32GroupSize; }
std::uint32_t AuthenticationRoundArchiveConfiguration::
u32DetectionThreshold() const noexcept { return m_u32DetectionThreshold; }

SenderRoundArchiveDetails::SenderRoundArchiveDetails(
    std::uint32_t u32SentPacketCount,
    std::string strConfiguredFault,
    std::string strConfiguredFaultValue,
    std::uint64_t u64RandomSeed,
    std::uint64_t u64FileSize
)
    : m_u32SentPacketCount(u32SentPacketCount),
      m_strConfiguredFault(std::move(strConfiguredFault)),
      m_strConfiguredFaultValue(std::move(strConfiguredFaultValue)),
      m_u64RandomSeed(u64RandomSeed),
      m_u64FileSize(u64FileSize)
{
    if (m_strConfiguredFault.empty())
    {
        throw std::invalid_argument("Sender round archive fault type is empty");
    }
}

std::uint32_t SenderRoundArchiveDetails::u32SentPacketCount() const noexcept { return m_u32SentPacketCount; }
const std::string& SenderRoundArchiveDetails::strConfiguredFault() const noexcept { return m_strConfiguredFault; }
const std::string& SenderRoundArchiveDetails::strConfiguredFaultValue() const noexcept { return m_strConfiguredFaultValue; }
std::uint64_t SenderRoundArchiveDetails::u64RandomSeed() const noexcept { return m_u64RandomSeed; }
std::uint64_t SenderRoundArchiveDetails::u64FileSize() const noexcept { return m_u64FileSize; }

ReceiverRoundArchiveDetails::ReceiverRoundArchiveDetails(
    std::uint32_t u32ReceivedPacketCount,
    std::uint32_t u32AuthenticatedPacketCount,
    std::uint32_t u32FailedPacketCount,
    std::uint32_t u32MissingPacketCount,
    std::uint32_t u32FallbackGroupCount,
    std::uint64_t u64VerifyTimeNanoseconds,
    std::uint64_t u64ReceivedAuthBytes,
    double dEstimatedEnergyMicroJoule,
    std::uint64_t u64FileSize,
    std::uint64_t u64RecoveredFileSize,
    std::string strRecoveredFileHash
)
    : m_u32ReceivedPacketCount(u32ReceivedPacketCount),
      m_u32AuthenticatedPacketCount(u32AuthenticatedPacketCount),
      m_u32FailedPacketCount(u32FailedPacketCount),
      m_u32MissingPacketCount(u32MissingPacketCount),
      m_u32FallbackGroupCount(u32FallbackGroupCount),
      m_u64VerifyTimeNanoseconds(u64VerifyTimeNanoseconds),
      m_u64ReceivedAuthBytes(u64ReceivedAuthBytes),
      m_dEstimatedEnergyMicroJoule(dEstimatedEnergyMicroJoule),
      m_u64FileSize(u64FileSize),
      m_u64RecoveredFileSize(u64RecoveredFileSize),
      m_strRecoveredFileHash(std::move(strRecoveredFileHash))
{
    if (m_dEstimatedEnergyMicroJoule < 0.0
        || m_u64RecoveredFileSize > m_u64FileSize)
    {
        throw std::invalid_argument("Receiver round archive details are invalid");
    }
}

std::uint32_t ReceiverRoundArchiveDetails::u32ReceivedPacketCount() const noexcept { return m_u32ReceivedPacketCount; }
std::uint32_t ReceiverRoundArchiveDetails::u32AuthenticatedPacketCount() const noexcept { return m_u32AuthenticatedPacketCount; }
std::uint32_t ReceiverRoundArchiveDetails::u32FailedPacketCount() const noexcept { return m_u32FailedPacketCount; }
std::uint32_t ReceiverRoundArchiveDetails::u32MissingPacketCount() const noexcept { return m_u32MissingPacketCount; }
std::uint32_t ReceiverRoundArchiveDetails::u32FallbackGroupCount() const noexcept { return m_u32FallbackGroupCount; }
std::uint64_t ReceiverRoundArchiveDetails::u64VerifyTimeNanoseconds() const noexcept { return m_u64VerifyTimeNanoseconds; }
std::uint64_t ReceiverRoundArchiveDetails::u64ReceivedAuthBytes() const noexcept { return m_u64ReceivedAuthBytes; }
double ReceiverRoundArchiveDetails::dEstimatedEnergyMicroJoule() const noexcept { return m_dEstimatedEnergyMicroJoule; }
std::uint64_t ReceiverRoundArchiveDetails::u64FileSize() const noexcept { return m_u64FileSize; }
std::uint64_t ReceiverRoundArchiveDetails::u64RecoveredFileSize() const noexcept { return m_u64RecoveredFileSize; }
const std::string& ReceiverRoundArchiveDetails::strRecoveredFileHash() const noexcept { return m_strRecoveredFileHash; }

AuthenticationRoundArchiveSummary::AuthenticationRoundArchiveSummary(
    std::uint64_t u64TimestampMilliseconds,
    std::string strExperimentId,
    std::string strRunId,
    std::string strGitCommit,
    std::string strNodeId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    AuthenticationRoundArchiveConfiguration cfgConfiguration,
    std::string strRoundStatus,
    bool bValidSample,
    std::string strInvalidReason,
    AuthenticationRoundArchiveDetails varDetails
)
    : m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strExperimentId(std::move(strExperimentId)),
      m_strRunId(std::move(strRunId)),
      m_strGitCommit(std::move(strGitCommit)),
      m_strNodeId(std::move(strNodeId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_cfgConfiguration(std::move(cfgConfiguration)),
      m_strRoundStatus(std::move(strRoundStatus)),
      m_bValidSample(bValidSample),
      m_strInvalidReason(std::move(strInvalidReason)),
      m_varDetails(std::move(varDetails))
{
    if (m_u64TimestampMilliseconds == 0
        || m_strExperimentId.empty()
        || m_strRunId.empty()
        || m_strGitCommit.empty()
        || m_strNodeId.empty()
        || m_strSenderId.empty()
        || m_strRoundStatus.empty()
        || (m_bValidSample && !m_strInvalidReason.empty())
        || (!m_bValidSample && m_strInvalidReason.empty()))
    {
        throw std::invalid_argument("Authentication round archive identity is invalid");
    }
}

std::uint64_t AuthenticationRoundArchiveSummary::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& AuthenticationRoundArchiveSummary::strExperimentId() const noexcept { return m_strExperimentId; }
const std::string& AuthenticationRoundArchiveSummary::strRunId() const noexcept { return m_strRunId; }
const std::string& AuthenticationRoundArchiveSummary::strGitCommit() const noexcept { return m_strGitCommit; }
const std::string& AuthenticationRoundArchiveSummary::strNodeId() const noexcept { return m_strNodeId; }
const std::string& AuthenticationRoundArchiveSummary::strSenderId() const noexcept { return m_strSenderId; }
std::uint64_t AuthenticationRoundArchiveSummary::u64ChainId() const noexcept { return m_u64ChainId; }
const AuthenticationRoundArchiveConfiguration& AuthenticationRoundArchiveSummary::cfgConfiguration() const noexcept { return m_cfgConfiguration; }
const std::string& AuthenticationRoundArchiveSummary::strRoundStatus() const noexcept { return m_strRoundStatus; }
bool AuthenticationRoundArchiveSummary::bValidSample() const noexcept { return m_bValidSample; }
const std::string& AuthenticationRoundArchiveSummary::strInvalidReason() const noexcept { return m_strInvalidReason; }
const AuthenticationRoundArchiveDetails& AuthenticationRoundArchiveSummary::varDetails() const noexcept { return m_varDetails; }

double EstimatedEnergyCalculator::dEstimateMicroJoule(
    std::uint64_t u64VerifyTimeNanoseconds,
    std::uint64_t u64ReceivedAuthBytes
) noexcept
{
    const double dVerifyTimeMicroseconds =
        static_cast<double>(u64VerifyTimeNanoseconds) / 1000.0;
    return CPU_MICRO_JOULE_PER_MICROSECOND * dVerifyTimeMicroseconds
        + WIFI_MICRO_JOULE_PER_BYTE
            * static_cast<double>(u64ReceivedAuthBytes);
}

AuthenticationRoundMetricCollector::AuthenticationRoundMetricCollector(
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    AuthenticationMetricMode modeAuthentication,
    std::uint32_t u32PacketCount
)
    : m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_modeAuthentication(modeAuthentication),
      m_u32PacketCount(u32PacketCount),
      m_u64VerifyTimeNanoseconds(0),
      m_u64ReceivedAuthBytes(0),
      m_u32VerifiedPacketCount(0),
      m_u32FastGroupCount(0),
      m_u32FallbackGroupCount(0),
      m_u32IncompleteGroupCount(0),
      m_bNormalComparisonEligible(true)
{
    validateIdentity(m_strRoundId, m_strSenderId, m_u32PacketCount);
}

void AuthenticationRoundMetricCollector::addDisclosureKeyMeasurement(
    const PerformanceMeasurement& mstMeasurement
)
{
    m_u64VerifyTimeNanoseconds += mstMeasurement.u64DurationNanoseconds();
}

void AuthenticationRoundMetricCollector::addVerificationSample(
    const VerificationMetricSample& smpVerification
)
{
    if (smpVerification.strRoundId() != m_strRoundId
        || smpVerification.strSenderId() != m_strSenderId
        || smpVerification.u64ChainId() != m_u64ChainId
        || smpVerification.modeAuthentication() != m_modeAuthentication)
    {
        throw std::invalid_argument("Verification metric sample belongs to another round");
    }

    m_u64VerifyTimeNanoseconds +=
        smpVerification.mstPerformance().u64DurationNanoseconds();
    if (m_modeAuthentication == AuthenticationMetricMode::Native)
    {
        m_u32VerifiedPacketCount += smpVerification.u32PacketCount();
        return;
    }

    switch (smpVerification.pathVerification())
    {
    case VerificationMetricPath::FastGroupPass:
        ++m_u32FastGroupCount;
        break;
    case VerificationMetricPath::KsRsFallback:
        ++m_u32FallbackGroupCount;
        break;
    case VerificationMetricPath::IncompleteGroupTags:
        ++m_u32IncompleteGroupCount;
        break;
    case VerificationMetricPath::NativePacketVerify:
        throw std::invalid_argument("Improved metric sample has a native path");
    }
}

void AuthenticationRoundMetricCollector::addReceivedAuthBytes(
    std::uint64_t u64ByteCount
)
{
    m_u64ReceivedAuthBytes += u64ByteCount;
}

void AuthenticationRoundMetricCollector::markNormalComparisonIneligible() noexcept
{
    m_bNormalComparisonEligible = false;
}

EstimatedEnergyMetricSummary AuthenticationRoundMetricCollector::sumCreateEnergySummary(
    std::uint64_t u64TimestampMilliseconds,
    bool bRoundCompleteNormally
) const
{
    AuthenticationRoundMetricDetails varDetails =
        m_modeAuthentication == AuthenticationMetricMode::Native
        ? AuthenticationRoundMetricDetails(
            NativeRoundMetricDetails(m_u32VerifiedPacketCount)
        )
        : AuthenticationRoundMetricDetails(ImprovedRoundMetricDetails(
            m_u32FastGroupCount,
            m_u32FallbackGroupCount,
            m_u32IncompleteGroupCount
        ));

    const bool bPathEligible =
        m_modeAuthentication == AuthenticationMetricMode::Native
        || (m_u32FastGroupCount > 0
            && m_u32FallbackGroupCount == 0
            && m_u32IncompleteGroupCount == 0);
    return EstimatedEnergyMetricSummary(
        u64TimestampMilliseconds,
        m_strRoundId,
        m_strSenderId,
        m_u64ChainId,
        m_u32PacketCount,
        m_u64VerifyTimeNanoseconds,
        m_u64ReceivedAuthBytes,
        EstimatedEnergyCalculator::dEstimateMicroJoule(
            m_u64VerifyTimeNanoseconds,
            m_u64ReceivedAuthBytes
        ),
        bRoundCompleteNormally
            && m_bNormalComparisonEligible
            && bPathEligible,
        std::move(varDetails)
    );
}

AuthenticationMetricStore::AuthenticationMetricStore(
    std::size_t nMaximumRecordCount
)
    : m_nMaximumRecordCount(nMaximumRecordCount)
{
    if (m_nMaximumRecordCount == 0)
    {
        throw std::invalid_argument("Metric store limit must be positive");
    }
}

bool AuthenticationMetricStore::bAppend(
    const AuthenticationMetricRecord& varRecord
)
{
    const std::string strKey = strRecordKey(varRecord);
    std::lock_guard<std::mutex> lckRecords(m_mtxRecords);
    if (m_setRecordKeys.count(strKey) > 0)
    {
        return false;
    }

    m_deqRecords.push_back(StoredRecord{strKey, varRecord});
    m_setRecordKeys.insert(strKey);
    while (m_deqRecords.size() > m_nMaximumRecordCount)
    {
        m_setRecordKeys.erase(m_deqRecords.front().strKey);
        m_deqRecords.pop_front();
    }
    return true;
}

void AuthenticationMetricStore::clear()
{
    std::lock_guard<std::mutex> lckRecords(m_mtxRecords);
    m_deqRecords.clear();
    m_setRecordKeys.clear();
}

std::vector<AuthenticationMetricRecord> AuthenticationMetricStore::vecSnapshot() const
{
    std::lock_guard<std::mutex> lckRecords(m_mtxRecords);
    std::vector<AuthenticationMetricRecord> vecRecords;
    vecRecords.reserve(m_deqRecords.size());
    for (const StoredRecord& recStored : m_deqRecords)
    {
        vecRecords.push_back(recStored.varRecord);
    }
    return vecRecords;
}

std::size_t AuthenticationMetricStore::nRecordCount() const
{
    std::lock_guard<std::mutex> lckRecords(m_mtxRecords);
    return m_deqRecords.size();
}

std::string AuthenticationMetricStore::strRecordKey(
    const AuthenticationMetricRecord& varRecord
)
{
    if (const auto* pSample = std::get_if<VerificationMetricSample>(&varRecord))
    {
        return "V:" + std::to_string(pSample->u64EventId());
    }

    if (const auto* pEnergy = std::get_if<EstimatedEnergyMetricSummary>(
            &varRecord
        ))
    {
        return "E:" + pEnergy->strRoundId() + ":"
            + pEnergy->strSenderId() + ":"
            + std::to_string(pEnergy->u64ChainId());
    }

    if (const auto* pCommunication = std::get_if<CommunicationCostMetricSummary>(
            &varRecord
        ))
    {
        return "C:" + pCommunication->strRoundId() + ":"
            + pCommunication->strSenderId() + ":"
            + std::to_string(pCommunication->u64ChainId());
    }

    const auto& sumArchive = std::get<AuthenticationRoundArchiveSummary>(
        varRecord
    );
    const char chRole = std::holds_alternative<SenderRoundArchiveDetails>(
        sumArchive.varDetails()
    ) ? 'S' : 'R';
    return std::string("A:") + chRole + ":" + sumArchive.strRunId() + ":"
        + sumArchive.strNodeId() + ":" + sumArchive.strSenderId() + ":"
        + std::to_string(sumArchive.u64ChainId());
}
}

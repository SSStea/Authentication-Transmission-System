#include "tesla/protocol/MonitorControl.h"

#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
void validateText(
    const std::string& strValue,
    const char* pName,
    bool bAllowEmpty = false,
    std::size_t nMaximumLength = 2048
)
{
    if ((!bAllowEmpty && strValue.empty()) || strValue.size() > nMaximumLength)
    {
        throw std::invalid_argument(std::string(pName) + " has an invalid length");
    }
}
}

NativePacketObservationDetails::NativePacketObservationDetails(
    BinaryBlock arrPacketMac
)
    : m_arrPacketMac(std::move(arrPacketMac))
{
}

const BinaryBlock& NativePacketObservationDetails::arrPacketMac() const noexcept
{
    return m_arrPacketMac;
}

ImprovedPacketObservationDetails::ImprovedPacketObservationDetails(
    std::vector<BinaryBlock> vecSamdTau,
    std::optional<BinaryBlock> optFastGroupTag
)
    : m_vecSamdTau(std::move(vecSamdTau)),
      m_optFastGroupTag(std::move(optFastGroupTag))
{
    if (m_vecSamdTau.empty() != !m_optFastGroupTag.has_value())
    {
        throw std::invalid_argument(
            "Improved packet observation must contain both group fields or neither"
        );
    }
}

const std::vector<BinaryBlock>&
ImprovedPacketObservationDetails::vecSamdTau() const noexcept
{
    return m_vecSamdTau;
}

const std::optional<BinaryBlock>&
ImprovedPacketObservationDetails::optFastGroupTag() const noexcept
{
    return m_optFastGroupTag;
}

DataPacketObservationDetails::DataPacketObservationDetails(
    BinaryBlock arrMessage,
    std::optional<BinaryBlock> optDisclosedKey,
    PacketModeObservationDetails varModeDetails
)
    : m_arrMessage(std::move(arrMessage)),
      m_optDisclosedKey(std::move(optDisclosedKey)),
      m_varModeDetails(std::move(varModeDetails))
{
}

const BinaryBlock& DataPacketObservationDetails::arrMessage() const noexcept
{
    return m_arrMessage;
}

const std::optional<BinaryBlock>&
DataPacketObservationDetails::optDisclosedKey() const noexcept
{
    return m_optDisclosedKey;
}

const PacketModeObservationDetails&
DataPacketObservationDetails::varModeDetails() const noexcept
{
    return m_varModeDetails;
}

DisclosurePacketObservationDetails::DisclosurePacketObservationDetails(
    BinaryBlock arrDisclosedKey
)
    : m_arrDisclosedKey(std::move(arrDisclosedKey))
{
}

const BinaryBlock&
DisclosurePacketObservationDetails::arrDisclosedKey() const noexcept
{
    return m_arrDisclosedKey;
}

PacketObservationControlDetails::PacketObservationControlDetails(
    std::uint64_t u64EventId,
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::string strSenderIp,
    std::string strActualSourceIp,
    std::string strPeer,
    PacketObservationDirection dirDirection,
    PacketSourceType typeSource,
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32DisclosureDelay,
    AuthenticationCryptoAlgorithm algCryptoAlgorithm,
    UdpAuthenticationMode modeAuthentication,
    PacketAuthenticationStatus statusAuthentication,
    std::string strCandidateHash,
    std::uint32_t u32DuplicateCount,
    std::string strReason,
    PacketPayloadObservationDetails varPayloadDetails,
    ByteBuffer vecRawDatagram
)
    : m_u64EventId(u64EventId),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_strSenderIp(std::move(strSenderIp)),
      m_strActualSourceIp(std::move(strActualSourceIp)),
      m_strPeer(std::move(strPeer)),
      m_dirDirection(dirDirection),
      m_typeSource(typeSource),
      m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_algCryptoAlgorithm(algCryptoAlgorithm),
      m_modeAuthentication(modeAuthentication),
      m_statusAuthentication(statusAuthentication),
      m_strCandidateHash(std::move(strCandidateHash)),
      m_u32DuplicateCount(u32DuplicateCount),
      m_strReason(std::move(strReason)),
      m_varPayloadDetails(std::move(varPayloadDetails)),
      m_vecRawDatagram(std::move(vecRawDatagram))
{
    validateText(m_strRoundId, "Observation round ID");
    validateText(m_strSenderId, "Observation sender ID");
    validateText(m_strSenderIp, "Observation sender IP", true);
    validateText(m_strActualSourceIp, "Observation actual source IP", true);
    validateText(m_strPeer, "Observation peer");
    validateText(m_strCandidateHash, "Observation candidate hash");
    validateText(m_strReason, "Observation reason", true);

    if (m_u64EventId == 0
        || m_u64TimestampMilliseconds == 0
        || m_u64ChainId == 0
        || m_u32IntervalIndex == 0
        || m_u32PacketsPerInterval == 0
        || m_u32DisclosureDelay == 0
        || m_u32DuplicateCount == 0
        || m_vecRawDatagram.empty())
    {
        throw std::invalid_argument("Packet observation contains an invalid value");
    }

    const bool bDataPacket = std::holds_alternative<
        DataPacketObservationDetails
    >(m_varPayloadDetails);
    if (bDataPacket != (m_u32PacketIndex != 0))
    {
        throw std::invalid_argument(
            "Packet observation index does not match DATA/DISCLOSE details"
        );
    }
}

std::uint64_t PacketObservationControlDetails::u64EventId() const noexcept { return m_u64EventId; }
std::uint64_t PacketObservationControlDetails::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& PacketObservationControlDetails::strRoundId() const noexcept { return m_strRoundId; }
const std::string& PacketObservationControlDetails::strSenderId() const noexcept { return m_strSenderId; }
const std::string& PacketObservationControlDetails::strSenderIp() const noexcept { return m_strSenderIp; }
const std::string& PacketObservationControlDetails::strActualSourceIp() const noexcept { return m_strActualSourceIp; }
const std::string& PacketObservationControlDetails::strPeer() const noexcept { return m_strPeer; }
PacketObservationDirection PacketObservationControlDetails::dirDirection() const noexcept { return m_dirDirection; }
PacketSourceType PacketObservationControlDetails::typeSource() const noexcept { return m_typeSource; }
std::uint64_t PacketObservationControlDetails::u64ChainId() const noexcept { return m_u64ChainId; }
std::uint32_t PacketObservationControlDetails::u32IntervalIndex() const noexcept { return m_u32IntervalIndex; }
std::uint32_t PacketObservationControlDetails::u32PacketIndex() const noexcept { return m_u32PacketIndex; }
std::uint32_t PacketObservationControlDetails::u32PacketsPerInterval() const noexcept { return m_u32PacketsPerInterval; }
std::uint32_t PacketObservationControlDetails::u32DisclosureDelay() const noexcept { return m_u32DisclosureDelay; }
AuthenticationCryptoAlgorithm PacketObservationControlDetails::algCryptoAlgorithm() const noexcept { return m_algCryptoAlgorithm; }
UdpAuthenticationMode PacketObservationControlDetails::modeAuthentication() const noexcept { return m_modeAuthentication; }
PacketAuthenticationStatus PacketObservationControlDetails::statusAuthentication() const noexcept { return m_statusAuthentication; }
const std::string& PacketObservationControlDetails::strCandidateHash() const noexcept { return m_strCandidateHash; }
std::uint32_t PacketObservationControlDetails::u32DuplicateCount() const noexcept { return m_u32DuplicateCount; }
const std::string& PacketObservationControlDetails::strReason() const noexcept { return m_strReason; }
const PacketPayloadObservationDetails& PacketObservationControlDetails::varPayloadDetails() const noexcept { return m_varPayloadDetails; }
const ByteBuffer& PacketObservationControlDetails::vecRawDatagram() const noexcept { return m_vecRawDatagram; }

PacketFailureControlDetails::PacketFailureControlDetails(
    std::uint64_t u64EventId,
    std::uint64_t u64PacketEventId,
    std::uint64_t u64TimestampMilliseconds,
    ObservationSeverity sevSeverity,
    AuthenticationFailureType typeFailure,
    std::string strRoundId,
    std::string strSenderId,
    std::string strSenderIp,
    std::string strActualSourceIp,
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex,
    std::optional<std::uint32_t> optGroupIndex,
    std::string strCandidateHash,
    std::string strReason,
    std::string strReceivedTagDigest,
    std::string strCalculatedTagDigest,
    std::vector<std::uint32_t> vecLocatedPacketIndexes,
    std::uint32_t u32DuplicateCount
)
    : m_u64EventId(u64EventId),
      m_u64PacketEventId(u64PacketEventId),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_sevSeverity(sevSeverity),
      m_typeFailure(typeFailure),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_strSenderIp(std::move(strSenderIp)),
      m_strActualSourceIp(std::move(strActualSourceIp)),
      m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex),
      m_optGroupIndex(std::move(optGroupIndex)),
      m_strCandidateHash(std::move(strCandidateHash)),
      m_strReason(std::move(strReason)),
      m_strReceivedTagDigest(std::move(strReceivedTagDigest)),
      m_strCalculatedTagDigest(std::move(strCalculatedTagDigest)),
      m_vecLocatedPacketIndexes(std::move(vecLocatedPacketIndexes)),
      m_u32DuplicateCount(u32DuplicateCount)
{
    validateText(m_strRoundId, "Failure round ID", true);
    validateText(m_strSenderId, "Failure sender ID", true);
    validateText(m_strSenderIp, "Failure sender IP", true);
    validateText(m_strActualSourceIp, "Failure source IP", true);
    validateText(m_strCandidateHash, "Failure candidate hash", true);
    validateText(m_strReason, "Failure reason");
    validateText(m_strReceivedTagDigest, "Received tag digest", true);
    validateText(m_strCalculatedTagDigest, "Calculated tag digest", true);

    if (m_u64EventId == 0
        || m_u64TimestampMilliseconds == 0
        || m_u32DuplicateCount == 0)
    {
        throw std::invalid_argument("Failure event contains an invalid value");
    }
}

std::uint64_t PacketFailureControlDetails::u64EventId() const noexcept { return m_u64EventId; }
std::uint64_t PacketFailureControlDetails::u64PacketEventId() const noexcept { return m_u64PacketEventId; }
std::uint64_t PacketFailureControlDetails::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
ObservationSeverity PacketFailureControlDetails::sevSeverity() const noexcept { return m_sevSeverity; }
AuthenticationFailureType PacketFailureControlDetails::typeFailure() const noexcept { return m_typeFailure; }
const std::string& PacketFailureControlDetails::strRoundId() const noexcept { return m_strRoundId; }
const std::string& PacketFailureControlDetails::strSenderId() const noexcept { return m_strSenderId; }
const std::string& PacketFailureControlDetails::strSenderIp() const noexcept { return m_strSenderIp; }
const std::string& PacketFailureControlDetails::strActualSourceIp() const noexcept { return m_strActualSourceIp; }
std::uint64_t PacketFailureControlDetails::u64ChainId() const noexcept { return m_u64ChainId; }
std::uint32_t PacketFailureControlDetails::u32IntervalIndex() const noexcept { return m_u32IntervalIndex; }
std::uint32_t PacketFailureControlDetails::u32PacketIndex() const noexcept { return m_u32PacketIndex; }
const std::optional<std::uint32_t>& PacketFailureControlDetails::optGroupIndex() const noexcept { return m_optGroupIndex; }
const std::string& PacketFailureControlDetails::strCandidateHash() const noexcept { return m_strCandidateHash; }
const std::string& PacketFailureControlDetails::strReason() const noexcept { return m_strReason; }
const std::string& PacketFailureControlDetails::strReceivedTagDigest() const noexcept { return m_strReceivedTagDigest; }
const std::string& PacketFailureControlDetails::strCalculatedTagDigest() const noexcept { return m_strCalculatedTagDigest; }
const std::vector<std::uint32_t>& PacketFailureControlDetails::vecLocatedPacketIndexes() const noexcept { return m_vecLocatedPacketIndexes; }
std::uint32_t PacketFailureControlDetails::u32DuplicateCount() const noexcept { return m_u32DuplicateCount; }

MatrixLocationStepControlDetails::MatrixLocationStepControlDetails(
    std::uint32_t u32StepIndex,
    std::string strOperation,
    std::vector<std::uint32_t> vecNewGoodPacketIndexes,
    std::vector<std::uint32_t> vecRemainingCandidateIndexes
)
    : m_u32StepIndex(u32StepIndex),
      m_strOperation(std::move(strOperation)),
      m_vecNewGoodPacketIndexes(std::move(vecNewGoodPacketIndexes)),
      m_vecRemainingCandidateIndexes(std::move(vecRemainingCandidateIndexes))
{
    validateText(m_strOperation, "Matrix location operation");
}

std::uint32_t MatrixLocationStepControlDetails::u32StepIndex() const noexcept { return m_u32StepIndex; }
const std::string& MatrixLocationStepControlDetails::strOperation() const noexcept { return m_strOperation; }
const std::vector<std::uint32_t>& MatrixLocationStepControlDetails::vecNewGoodPacketIndexes() const noexcept { return m_vecNewGoodPacketIndexes; }
const std::vector<std::uint32_t>& MatrixLocationStepControlDetails::vecRemainingCandidateIndexes() const noexcept { return m_vecRemainingCandidateIndexes; }

ImprovedGroupObservationControlDetails::ImprovedGroupObservationControlDetails(
    std::uint64_t u64EventId,
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32GroupIndex,
    std::uint32_t u32FirstPacketIndex,
    std::uint32_t u32LastPacketIndex,
    std::uint32_t u32DetectionThreshold,
    GroupVerificationPath pathVerification,
    bool bFastGroupTagMatched,
    bool bDetectionThresholdExceeded,
    std::vector<std::uint32_t> vecLocatedPacketIndexes,
    std::vector<MatrixLocationStepControlDetails> vecLocationSteps
)
    : m_u64EventId(u64EventId),
      m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32GroupIndex(u32GroupIndex),
      m_u32FirstPacketIndex(u32FirstPacketIndex),
      m_u32LastPacketIndex(u32LastPacketIndex),
      m_u32DetectionThreshold(u32DetectionThreshold),
      m_pathVerification(pathVerification),
      m_bFastGroupTagMatched(bFastGroupTagMatched),
      m_bDetectionThresholdExceeded(bDetectionThresholdExceeded),
      m_vecLocatedPacketIndexes(std::move(vecLocatedPacketIndexes)),
      m_vecLocationSteps(std::move(vecLocationSteps))
{
    validateText(m_strRoundId, "Group observation round ID");
    validateText(m_strSenderId, "Group observation sender ID");
    if (m_u64EventId == 0
        || m_u64TimestampMilliseconds == 0
        || m_u64ChainId == 0
        || m_u32GroupIndex == 0
        || m_u32FirstPacketIndex == 0
        || m_u32LastPacketIndex < m_u32FirstPacketIndex
        || m_u32DetectionThreshold == 0)
    {
        throw std::invalid_argument("Group observation contains an invalid value");
    }

    if (m_pathVerification == GroupVerificationPath::FastGroupPass
        && (!m_vecLocatedPacketIndexes.empty() || !m_vecLocationSteps.empty()))
    {
        throw std::invalid_argument(
            "Fast group pass must not contain matrix location details"
        );
    }
}

std::uint64_t ImprovedGroupObservationControlDetails::u64EventId() const noexcept { return m_u64EventId; }
std::uint64_t ImprovedGroupObservationControlDetails::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
const std::string& ImprovedGroupObservationControlDetails::strRoundId() const noexcept { return m_strRoundId; }
const std::string& ImprovedGroupObservationControlDetails::strSenderId() const noexcept { return m_strSenderId; }
std::uint64_t ImprovedGroupObservationControlDetails::u64ChainId() const noexcept { return m_u64ChainId; }
std::uint32_t ImprovedGroupObservationControlDetails::u32GroupIndex() const noexcept { return m_u32GroupIndex; }
std::uint32_t ImprovedGroupObservationControlDetails::u32FirstPacketIndex() const noexcept { return m_u32FirstPacketIndex; }
std::uint32_t ImprovedGroupObservationControlDetails::u32LastPacketIndex() const noexcept { return m_u32LastPacketIndex; }
std::uint32_t ImprovedGroupObservationControlDetails::u32DetectionThreshold() const noexcept { return m_u32DetectionThreshold; }
GroupVerificationPath ImprovedGroupObservationControlDetails::pathVerification() const noexcept { return m_pathVerification; }
bool ImprovedGroupObservationControlDetails::bFastGroupTagMatched() const noexcept { return m_bFastGroupTagMatched; }
bool ImprovedGroupObservationControlDetails::bDetectionThresholdExceeded() const noexcept { return m_bDetectionThresholdExceeded; }
const std::vector<std::uint32_t>& ImprovedGroupObservationControlDetails::vecLocatedPacketIndexes() const noexcept { return m_vecLocatedPacketIndexes; }
const std::vector<MatrixLocationStepControlDetails>& ImprovedGroupObservationControlDetails::vecLocationSteps() const noexcept { return m_vecLocationSteps; }

DosSummaryControlDetails::DosSummaryControlDetails(
    std::uint64_t u64TimestampMilliseconds,
    std::uint32_t u32WindowMilliseconds,
    std::uint64_t u64InvalidPacketCount,
    std::uint64_t u64RateLimitedDropCount,
    std::uint64_t u64LegitimatePacketCount,
    std::uint64_t u64ReceiveQueueOverflowCount
)
    : m_u64TimestampMilliseconds(u64TimestampMilliseconds),
      m_u32WindowMilliseconds(u32WindowMilliseconds),
      m_u64InvalidPacketCount(u64InvalidPacketCount),
      m_u64RateLimitedDropCount(u64RateLimitedDropCount),
      m_u64LegitimatePacketCount(u64LegitimatePacketCount),
      m_u64ReceiveQueueOverflowCount(u64ReceiveQueueOverflowCount)
{
    if (m_u64TimestampMilliseconds == 0 || m_u32WindowMilliseconds == 0)
    {
        throw std::invalid_argument("DoS summary window is invalid");
    }
}

std::uint64_t DosSummaryControlDetails::u64TimestampMilliseconds() const noexcept { return m_u64TimestampMilliseconds; }
std::uint32_t DosSummaryControlDetails::u32WindowMilliseconds() const noexcept { return m_u32WindowMilliseconds; }
std::uint64_t DosSummaryControlDetails::u64InvalidPacketCount() const noexcept { return m_u64InvalidPacketCount; }
std::uint64_t DosSummaryControlDetails::u64RateLimitedDropCount() const noexcept { return m_u64RateLimitedDropCount; }
std::uint64_t DosSummaryControlDetails::u64LegitimatePacketCount() const noexcept { return m_u64LegitimatePacketCount; }
std::uint64_t DosSummaryControlDetails::u64ReceiveQueueOverflowCount() const noexcept { return m_u64ReceiveQueueOverflowCount; }

AbnormalEventSnapshotControlDetails::AbnormalEventSnapshotControlDetails(
    std::string strRequestId,
    std::uint32_t u32Sequence,
    bool bFinalBatch,
    std::vector<PacketObservationControlDetails> vecPacketEvents,
    std::vector<PacketFailureControlDetails> vecFailureEvents
)
    : m_strRequestId(std::move(strRequestId)),
      m_u32Sequence(u32Sequence),
      m_bFinalBatch(bFinalBatch),
      m_vecPacketEvents(std::move(vecPacketEvents)),
      m_vecFailureEvents(std::move(vecFailureEvents))
{
    validateText(m_strRequestId, "Abnormal snapshot request ID");
    if (m_u32Sequence == 0
        || m_vecPacketEvents.size() > 64
        || m_vecFailureEvents.size() > 64)
    {
        throw std::invalid_argument("Abnormal snapshot batch is invalid");
    }
}

const std::string& AbnormalEventSnapshotControlDetails::strRequestId() const noexcept { return m_strRequestId; }
std::uint32_t AbnormalEventSnapshotControlDetails::u32Sequence() const noexcept { return m_u32Sequence; }
bool AbnormalEventSnapshotControlDetails::bFinalBatch() const noexcept { return m_bFinalBatch; }
const std::vector<PacketObservationControlDetails>& AbnormalEventSnapshotControlDetails::vecPacketEvents() const noexcept { return m_vecPacketEvents; }
const std::vector<PacketFailureControlDetails>& AbnormalEventSnapshotControlDetails::vecFailureEvents() const noexcept { return m_vecFailureEvents; }
}

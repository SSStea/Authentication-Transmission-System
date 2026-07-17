#pragma once

#include "tesla/protocol/AuthenticationControl.h"
#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace tesla::protocol
{
enum class PacketObservationDirection
{
    Tx,
    Rx
};

enum class PacketSourceType
{
    NormalSender,
    AttackInjection,
    UnknownSource
};

enum class PacketAuthenticationStatus
{
    Generated,
    Pending,
    Passed,
    Failed
};

enum class AuthenticationFailureType
{
    MacFailed,
    TamperedVariant,
    FastGroupFailed,
    GroupTauFailed,
    DetectionThresholdExceeded,
    ReplayDuplicate,
    ReplayLate,
    ReplayExpiredChain,
    MissingPacket,
    IncompleteGroupTags,
    UnverifiableMissingBaseline,
    UnknownContext,
    ProtocolError,
    InvalidSchedulingOverrun,
    AbnormalRecordLimitReached
};

enum class ObservationSeverity
{
    Information,
    Warning,
    Error
};

enum class GroupVerificationPath
{
    FastGroupPass,
    KsRsFallback,
    IncompleteGroupTags
};

/** @brief 原生TESLA报文展示字段，仅保存该模式实际携带的逐包MAC。 */
class NativePacketObservationDetails final
{
public:
    explicit NativePacketObservationDetails(BinaryBlock arrPacketMac);

    const BinaryBlock& arrPacketMac() const noexcept;

private:
    BinaryBlock m_arrPacketMac;
};

/** @brief 改进TESLA报文展示字段；只有组末报文携带tau和FastGroupTag。 */
class ImprovedPacketObservationDetails final
{
public:
    ImprovedPacketObservationDetails(
        std::vector<BinaryBlock> vecSamdTau,
        std::optional<BinaryBlock> optFastGroupTag
    );

    const std::vector<BinaryBlock>& vecSamdTau() const noexcept;
    const std::optional<BinaryBlock>& optFastGroupTag() const noexcept;

private:
    std::vector<BinaryBlock>   m_vecSamdTau;
    std::optional<BinaryBlock> m_optFastGroupTag;
};

using PacketModeObservationDetails = std::variant<
    NativePacketObservationDetails,
    ImprovedPacketObservationDetails
>;

/** @brief DATA报文详情，保留固定Message、可选披露密钥和模式专用认证字段。 */
class DataPacketObservationDetails final
{
public:
    DataPacketObservationDetails(
        BinaryBlock arrMessage,
        std::optional<BinaryBlock> optDisclosedKey,
        PacketModeObservationDetails varModeDetails
    );

    const BinaryBlock& arrMessage() const noexcept;
    const std::optional<BinaryBlock>& optDisclosedKey() const noexcept;
    const PacketModeObservationDetails& varModeDetails() const noexcept;

private:
    BinaryBlock                      m_arrMessage;
    std::optional<BinaryBlock>       m_optDisclosedKey;
    PacketModeObservationDetails     m_varModeDetails;
};

/** @brief 数据发送结束后的DISCLOSE尾包详情。 */
class DisclosurePacketObservationDetails final
{
public:
    explicit DisclosurePacketObservationDetails(BinaryBlock arrDisclosedKey);

    const BinaryBlock& arrDisclosedKey() const noexcept;

private:
    BinaryBlock m_arrDisclosedKey;
};

using PacketPayloadObservationDetails = std::variant<
    DataPacketObservationDetails,
    DisclosurePacketObservationDetails
>;

/**
 * @brief 一条真实UDP收发记录，公共定位字段与DATA/DISCLOSE专用字段分开保存。
 *
 * 同一eventId的后续事件用于更新认证状态；candidateHash用于区分同一报文编号
 * 下Message不同的候选版本，完全相同的副本只更新duplicateCount。
 */
class PacketObservationControlDetails final
{
public:
    PacketObservationControlDetails(
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
    );

    std::uint64_t u64EventId() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    const std::string& strSenderIp() const noexcept;
    const std::string& strActualSourceIp() const noexcept;
    const std::string& strPeer() const noexcept;
    PacketObservationDirection dirDirection() const noexcept;
    PacketSourceType typeSource() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32IntervalIndex() const noexcept;
    std::uint32_t u32PacketIndex() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    AuthenticationCryptoAlgorithm algCryptoAlgorithm() const noexcept;
    UdpAuthenticationMode modeAuthentication() const noexcept;
    PacketAuthenticationStatus statusAuthentication() const noexcept;
    const std::string& strCandidateHash() const noexcept;
    std::uint32_t u32DuplicateCount() const noexcept;
    const std::string& strReason() const noexcept;
    const PacketPayloadObservationDetails& varPayloadDetails() const noexcept;
    const ByteBuffer& vecRawDatagram() const noexcept;

private:
    std::uint64_t                   m_u64EventId;
    std::uint64_t                   m_u64TimestampMilliseconds;
    std::string                     m_strRoundId;
    std::string                     m_strSenderId;
    std::string                     m_strSenderIp;
    std::string                     m_strActualSourceIp;
    std::string                     m_strPeer;
    PacketObservationDirection      m_dirDirection;
    PacketSourceType                m_typeSource;
    std::uint64_t                   m_u64ChainId;
    std::uint32_t                   m_u32IntervalIndex;
    std::uint32_t                   m_u32PacketIndex;
    std::uint32_t                   m_u32PacketsPerInterval;
    std::uint32_t                   m_u32DisclosureDelay;
    AuthenticationCryptoAlgorithm   m_algCryptoAlgorithm;
    UdpAuthenticationMode           m_modeAuthentication;
    PacketAuthenticationStatus      m_statusAuthentication;
    std::string                     m_strCandidateHash;
    std::uint32_t                   m_u32DuplicateCount;
    std::string                     m_strReason;
    PacketPayloadObservationDetails m_varPayloadDetails;
    ByteBuffer                      m_vecRawDatagram;
};

/** @brief 可跳转到报文或预期槽位的统一结构化失败事件。 */
class PacketFailureControlDetails final
{
public:
    PacketFailureControlDetails(
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
    );

    std::uint64_t u64EventId() const noexcept;
    std::uint64_t u64PacketEventId() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;
    ObservationSeverity sevSeverity() const noexcept;
    AuthenticationFailureType typeFailure() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    const std::string& strSenderIp() const noexcept;
    const std::string& strActualSourceIp() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32IntervalIndex() const noexcept;
    std::uint32_t u32PacketIndex() const noexcept;
    const std::optional<std::uint32_t>& optGroupIndex() const noexcept;
    const std::string& strCandidateHash() const noexcept;
    const std::string& strReason() const noexcept;
    const std::string& strReceivedTagDigest() const noexcept;
    const std::string& strCalculatedTagDigest() const noexcept;
    const std::vector<std::uint32_t>& vecLocatedPacketIndexes() const noexcept;
    std::uint32_t u32DuplicateCount() const noexcept;

private:
    std::uint64_t                m_u64EventId;
    std::uint64_t                m_u64PacketEventId;
    std::uint64_t                m_u64TimestampMilliseconds;
    ObservationSeverity          m_sevSeverity;
    AuthenticationFailureType    m_typeFailure;
    std::string                  m_strRoundId;
    std::string                  m_strSenderId;
    std::string                  m_strSenderIp;
    std::string                  m_strActualSourceIp;
    std::uint64_t                m_u64ChainId;
    std::uint32_t                m_u32IntervalIndex;
    std::uint32_t                m_u32PacketIndex;
    std::optional<std::uint32_t> m_optGroupIndex;
    std::string                  m_strCandidateHash;
    std::string                  m_strReason;
    std::string                  m_strReceivedTagDigest;
    std::string                  m_strCalculatedTagDigest;
    std::vector<std::uint32_t>   m_vecLocatedPacketIndexes;
    std::uint32_t                m_u32DuplicateCount;
};

/** @brief GUI展示“排除好包、留下坏包”过程中的一个步骤。 */
class MatrixLocationStepControlDetails final
{
public:
    MatrixLocationStepControlDetails(
        std::uint32_t u32StepIndex,
        std::string strOperation,
        std::vector<std::uint32_t> vecNewGoodPacketIndexes,
        std::vector<std::uint32_t> vecRemainingCandidateIndexes
    );

    std::uint32_t u32StepIndex() const noexcept;
    const std::string& strOperation() const noexcept;
    const std::vector<std::uint32_t>& vecNewGoodPacketIndexes() const noexcept;
    const std::vector<std::uint32_t>& vecRemainingCandidateIndexes() const noexcept;

private:
    std::uint32_t              m_u32StepIndex;
    std::string                m_strOperation;
    std::vector<std::uint32_t> m_vecNewGoodPacketIndexes;
    std::vector<std::uint32_t> m_vecRemainingCandidateIndexes;
};

/** @brief 一次改进TESLA分组验证的路径、最终定位和可展示步骤。 */
class ImprovedGroupObservationControlDetails final
{
public:
    ImprovedGroupObservationControlDetails(
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
    );

    std::uint64_t u64EventId() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32GroupIndex() const noexcept;
    std::uint32_t u32FirstPacketIndex() const noexcept;
    std::uint32_t u32LastPacketIndex() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;
    GroupVerificationPath pathVerification() const noexcept;
    bool bFastGroupTagMatched() const noexcept;
    bool bDetectionThresholdExceeded() const noexcept;
    const std::vector<std::uint32_t>& vecLocatedPacketIndexes() const noexcept;
    const std::vector<MatrixLocationStepControlDetails>& vecLocationSteps() const noexcept;

private:
    std::uint64_t                                 m_u64EventId;
    std::uint64_t                                 m_u64TimestampMilliseconds;
    std::string                                   m_strRoundId;
    std::string                                   m_strSenderId;
    std::uint64_t                                 m_u64ChainId;
    std::uint32_t                                 m_u32GroupIndex;
    std::uint32_t                                 m_u32FirstPacketIndex;
    std::uint32_t                                 m_u32LastPacketIndex;
    std::uint32_t                                 m_u32DetectionThreshold;
    GroupVerificationPath                        m_pathVerification;
    bool                                          m_bFastGroupTagMatched;
    bool                                          m_bDetectionThresholdExceeded;
    std::vector<std::uint32_t>                    m_vecLocatedPacketIndexes;
    std::vector<MatrixLocationStepControlDetails> m_vecLocationSteps;
};

/** @brief 高频无效流量的固定1000ms窗口汇总，不生成逐包失败详情。 */
class DosSummaryControlDetails final
{
public:
    DosSummaryControlDetails(
        std::uint64_t u64TimestampMilliseconds,
        std::uint32_t u32WindowMilliseconds,
        std::uint64_t u64InvalidPacketCount,
        std::uint64_t u64RateLimitedDropCount,
        std::uint64_t u64LegitimatePacketCount,
        std::uint64_t u64ReceiveQueueOverflowCount
    );

    std::uint64_t u64TimestampMilliseconds() const noexcept;
    std::uint32_t u32WindowMilliseconds() const noexcept;
    std::uint64_t u64InvalidPacketCount() const noexcept;
    std::uint64_t u64RateLimitedDropCount() const noexcept;
    std::uint64_t u64LegitimatePacketCount() const noexcept;
    std::uint64_t u64ReceiveQueueOverflowCount() const noexcept;

private:
    std::uint64_t m_u64TimestampMilliseconds;
    std::uint32_t m_u32WindowMilliseconds;
    std::uint64_t m_u64InvalidPacketCount;
    std::uint64_t m_u64RateLimitedDropCount;
    std::uint64_t m_u64LegitimatePacketCount;
    std::uint64_t m_u64ReceiveQueueOverflowCount;
};

using AuthenticationObservation = std::variant<
    PacketObservationControlDetails,
    PacketFailureControlDetails,
    ImprovedGroupObservationControlDetails,
    DosSummaryControlDetails
>;

/** @brief MONITOR重连时分批返回的有界异常事件快照。 */
class AbnormalEventSnapshotControlDetails final
{
public:
    AbnormalEventSnapshotControlDetails(
        std::string strRequestId,
        std::uint32_t u32Sequence,
        bool bFinalBatch,
        std::vector<PacketObservationControlDetails> vecPacketEvents,
        std::vector<PacketFailureControlDetails> vecFailureEvents
    );

    const std::string& strRequestId() const noexcept;
    std::uint32_t u32Sequence() const noexcept;
    bool bFinalBatch() const noexcept;
    const std::vector<PacketObservationControlDetails>& vecPacketEvents() const noexcept;
    const std::vector<PacketFailureControlDetails>& vecFailureEvents() const noexcept;

private:
    std::string                              m_strRequestId;
    std::uint32_t                            m_u32Sequence;
    bool                                     m_bFinalBatch;
    std::vector<PacketObservationControlDetails> m_vecPacketEvents;
    std::vector<PacketFailureControlDetails> m_vecFailureEvents;
};
}

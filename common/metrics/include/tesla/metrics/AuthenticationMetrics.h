#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_set>
#include <variant>
#include <vector>

namespace tesla::metrics
{
enum class AuthenticationMetricMode
{
    Native,
    Improved
};

enum class VerificationMetricPath
{
    NativePacketVerify,
    FastGroupPass,
    KsRsFallback,
    IncompleteGroupTags
};

/** @brief 硬件性能计数器的可用状态；不可用时不得用零值伪装成实测结果。 */
enum class HardwareCounterStatus
{
    Supported,
    NotSupported,
    PermissionDenied,
    ReadFailed
};

class HardwarePerformanceCounters final
{
public:
    HardwarePerformanceCounters(
        HardwareCounterStatus statusCounters,
        std::uint64_t u64CpuCycles,
        std::uint64_t u64CacheReferences,
        std::uint64_t u64CacheMisses
    );

    HardwareCounterStatus statusCounters() const noexcept;
    std::uint64_t u64CpuCycles() const noexcept;
    std::uint64_t u64CacheReferences() const noexcept;
    std::uint64_t u64CacheMisses() const noexcept;
    double dCacheHitRate() const noexcept;

private:
    HardwareCounterStatus m_statusCounters;
    std::uint64_t         m_u64CpuCycles;
    std::uint64_t         m_u64CacheReferences;
    std::uint64_t         m_u64CacheMisses;
};

/** @brief 一段真实认证计算的单调时钟耗时和同范围硬件计数。 */
class PerformanceMeasurement final
{
public:
    PerformanceMeasurement(
        std::uint64_t u64DurationNanoseconds,
        HardwarePerformanceCounters ctrHardware
    );

    std::uint64_t u64DurationNanoseconds() const noexcept;
    const HardwarePerformanceCounters& ctrHardware() const noexcept;

private:
    std::uint64_t             m_u64DurationNanoseconds;
    HardwarePerformanceCounters m_ctrHardware;
};

class NativeVerificationMetricDetails final
{
public:
    NativeVerificationMetricDetails(
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex
    );

    std::uint32_t u32IntervalIndex() const noexcept;
    std::uint32_t u32PacketIndex() const noexcept;

private:
    std::uint32_t m_u32IntervalIndex;
    std::uint32_t m_u32PacketIndex;
};

class ImprovedVerificationMetricDetails final
{
public:
    ImprovedVerificationMetricDetails(
        std::uint32_t u32GroupIndex,
        std::uint32_t u32FirstPacketIndex,
        std::uint32_t u32LastPacketIndex,
        VerificationMetricPath pathVerification
    );

    std::uint32_t u32GroupIndex() const noexcept;
    std::uint32_t u32FirstPacketIndex() const noexcept;
    std::uint32_t u32LastPacketIndex() const noexcept;
    VerificationMetricPath pathVerification() const noexcept;

private:
    std::uint32_t          m_u32GroupIndex;
    std::uint32_t          m_u32FirstPacketIndex;
    std::uint32_t          m_u32LastPacketIndex;
    VerificationMetricPath m_pathVerification;
};

using VerificationMetricDetails = std::variant<
    NativeVerificationMetricDetails,
    ImprovedVerificationMetricDetails
>;

/** @brief 原生单包或改进完整分组的一次真实验证采样。 */
class VerificationMetricSample final
{
public:
    VerificationMetricSample(
        std::uint64_t u64EventId,
        std::uint64_t u64TimestampMilliseconds,
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint32_t u32PacketCount,
        PerformanceMeasurement mstPerformance,
        VerificationMetricDetails varDetails
    );

    std::uint64_t u64EventId() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32PacketCount() const noexcept;
    const PerformanceMeasurement& mstPerformance() const noexcept;
    const VerificationMetricDetails& varDetails() const noexcept;
    AuthenticationMetricMode modeAuthentication() const noexcept;
    VerificationMetricPath pathVerification() const noexcept;
    double dAveragePacketVerifyTimeMicroseconds() const noexcept;

private:
    std::uint64_t             m_u64EventId;
    std::uint64_t             m_u64TimestampMilliseconds;
    std::string               m_strRoundId;
    std::string               m_strSenderId;
    std::uint64_t             m_u64ChainId;
    std::uint32_t             m_u32PacketCount;
    PerformanceMeasurement    m_mstPerformance;
    VerificationMetricDetails m_varDetails;
};

class NativeRoundMetricDetails final
{
public:
    explicit NativeRoundMetricDetails(std::uint32_t u32VerifiedPacketCount);

    std::uint32_t u32VerifiedPacketCount() const noexcept;

private:
    std::uint32_t m_u32VerifiedPacketCount;
};

class ImprovedRoundMetricDetails final
{
public:
    ImprovedRoundMetricDetails(
        std::uint32_t u32FastGroupCount,
        std::uint32_t u32FallbackGroupCount,
        std::uint32_t u32IncompleteGroupCount
    );

    std::uint32_t u32FastGroupCount() const noexcept;
    std::uint32_t u32FallbackGroupCount() const noexcept;
    std::uint32_t u32IncompleteGroupCount() const noexcept;

private:
    std::uint32_t m_u32FastGroupCount;
    std::uint32_t m_u32FallbackGroupCount;
    std::uint32_t m_u32IncompleteGroupCount;
};

using AuthenticationRoundMetricDetails = std::variant<
    NativeRoundMetricDetails,
    ImprovedRoundMetricDetails
>;

/** @brief 使用固定文献系数和本轮真实输入计算的估算验证能耗。 */
class EstimatedEnergyMetricSummary final
{
public:
    EstimatedEnergyMetricSummary(
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
    );

    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32PacketCount() const noexcept;
    std::uint64_t u64VerifyTimeNanoseconds() const noexcept;
    std::uint64_t u64ReceivedAuthBytes() const noexcept;
    double dEstimatedEnergyMicroJoule() const noexcept;
    double dEstimatedEnergyMilliJoule() const noexcept;
    double dAveragePacketEnergyMicroJoule() const noexcept;
    bool bNormalComparisonEligible() const noexcept;
    AuthenticationMetricMode modeAuthentication() const noexcept;
    const AuthenticationRoundMetricDetails& varDetails() const noexcept;

private:
    std::uint64_t                    m_u64TimestampMilliseconds;
    std::string                      m_strRoundId;
    std::string                      m_strSenderId;
    std::uint64_t                    m_u64ChainId;
    std::uint32_t                    m_u32PacketCount;
    std::uint64_t                    m_u64VerifyTimeNanoseconds;
    std::uint64_t                    m_u64ReceivedAuthBytes;
    double                           m_dEstimatedEnergyMicroJoule;
    bool                             m_bNormalComparisonEligible;
    AuthenticationRoundMetricDetails m_varDetails;
};

class NativeCommunicationCostDetails final
{
public:
    NativeCommunicationCostDetails(
        std::uint64_t u64MessageBytes,
        std::uint64_t u64KeyBytes,
        std::uint64_t u64MacBytes
    );

    std::uint64_t u64MessageBytes() const noexcept;
    std::uint64_t u64KeyBytes() const noexcept;
    std::uint64_t u64MacBytes() const noexcept;

private:
    std::uint64_t m_u64MessageBytes;
    std::uint64_t m_u64KeyBytes;
    std::uint64_t m_u64MacBytes;
};

class ImprovedCommunicationCostDetails final
{
public:
    ImprovedCommunicationCostDetails(
        std::uint64_t u64MessageBytes,
        std::uint64_t u64KeyBytes,
        std::uint64_t u64TauBytes,
        std::uint64_t u64FastGroupTagBytes
    );

    std::uint64_t u64MessageBytes() const noexcept;
    std::uint64_t u64KeyBytes() const noexcept;
    std::uint64_t u64TauBytes() const noexcept;
    std::uint64_t u64FastGroupTagBytes() const noexcept;

private:
    std::uint64_t m_u64MessageBytes;
    std::uint64_t m_u64KeyBytes;
    std::uint64_t m_u64TauBytes;
    std::uint64_t m_u64FastGroupTagBytes;
};

using CommunicationCostDetails = std::variant<
    NativeCommunicationCostDetails,
    ImprovedCommunicationCostDetails
>;

/** @brief 只计算TESLA算法字段，不包含UDP/TCP协议和序列化字节。 */
class CommunicationCostMetricSummary final
{
public:
    CommunicationCostMetricSummary(
        std::uint64_t u64TimestampMilliseconds,
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        CommunicationCostDetails varDetails
    );

    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    AuthenticationMetricMode modeAuthentication() const noexcept;
    std::uint64_t u64TotalBytes() const noexcept;
    const CommunicationCostDetails& varDetails() const noexcept;

private:
    std::uint64_t            m_u64TimestampMilliseconds;
    std::string              m_strRoundId;
    std::string              m_strSenderId;
    std::uint64_t            m_u64ChainId;
    CommunicationCostDetails m_varDetails;
};

/** @brief 一轮归档中可复现实验配置的公共字段。 */
class AuthenticationRoundArchiveConfiguration final
{
public:
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
    );

    AuthenticationMetricMode modeAuthentication() const noexcept;
    const std::string& strCryptoAlgorithm() const noexcept;
    const std::string& strPayloadHash() const noexcept;
    std::uint32_t u32PacketCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;

private:
    AuthenticationMetricMode m_modeAuthentication;
    std::string               m_strCryptoAlgorithm;
    std::string               m_strPayloadHash;
    std::uint32_t             m_u32PacketCount;
    std::uint32_t             m_u32PacketsPerInterval;
    std::uint32_t             m_u32IntervalMilliseconds;
    std::uint32_t             m_u32DisclosureDelay;
    std::uint32_t             m_u32GroupSize;
    std::uint32_t             m_u32DetectionThreshold;
};

/** @brief Sender逐轮归档详情，只保存发送和本地故障计划数据。 */
class SenderRoundArchiveDetails final
{
public:
    SenderRoundArchiveDetails(
        std::uint32_t u32SentPacketCount,
        std::string strConfiguredFault,
        std::string strConfiguredFaultValue,
        std::uint64_t u64RandomSeed,
        std::uint64_t u64FileSize
    );

    std::uint32_t u32SentPacketCount() const noexcept;
    const std::string& strConfiguredFault() const noexcept;
    const std::string& strConfiguredFaultValue() const noexcept;
    std::uint64_t u64RandomSeed() const noexcept;
    std::uint64_t u64FileSize() const noexcept;

private:
    std::uint32_t m_u32SentPacketCount;
    std::string   m_strConfiguredFault;
    std::string   m_strConfiguredFaultValue;
    std::uint64_t m_u64RandomSeed;
    std::uint64_t m_u64FileSize;
};

/** @brief Receiver逐轮归档详情，集中保存认证结果、指标和文件恢复结果。 */
class ReceiverRoundArchiveDetails final
{
public:
    ReceiverRoundArchiveDetails(
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
    );

    std::uint32_t u32ReceivedPacketCount() const noexcept;
    std::uint32_t u32AuthenticatedPacketCount() const noexcept;
    std::uint32_t u32FailedPacketCount() const noexcept;
    std::uint32_t u32MissingPacketCount() const noexcept;
    std::uint32_t u32FallbackGroupCount() const noexcept;
    std::uint64_t u64VerifyTimeNanoseconds() const noexcept;
    std::uint64_t u64ReceivedAuthBytes() const noexcept;
    double dEstimatedEnergyMicroJoule() const noexcept;
    std::uint64_t u64FileSize() const noexcept;
    std::uint64_t u64RecoveredFileSize() const noexcept;
    const std::string& strRecoveredFileHash() const noexcept;

private:
    std::uint32_t m_u32ReceivedPacketCount;
    std::uint32_t m_u32AuthenticatedPacketCount;
    std::uint32_t m_u32FailedPacketCount;
    std::uint32_t m_u32MissingPacketCount;
    std::uint32_t m_u32FallbackGroupCount;
    std::uint64_t m_u64VerifyTimeNanoseconds;
    std::uint64_t m_u64ReceivedAuthBytes;
    double        m_dEstimatedEnergyMicroJoule;
    std::uint64_t m_u64FileSize;
    std::uint64_t m_u64RecoveredFileSize;
    std::string   m_strRecoveredFileHash;
};

using AuthenticationRoundArchiveDetails = std::variant<
    SenderRoundArchiveDetails,
    ReceiverRoundArchiveDetails
>;

/**
 * @brief 节点生成的逐轮可追溯记录，公共配置与角色专用结果使用variant隔离。
 *
 * payloadHash在Sender接受载荷或Receiver成功恢复后生成；恢复未完成时允许为空。
 */
class AuthenticationRoundArchiveSummary final
{
public:
    AuthenticationRoundArchiveSummary(
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
    );

    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strExperimentId() const noexcept;
    const std::string& strRunId() const noexcept;
    const std::string& strGitCommit() const noexcept;
    const std::string& strNodeId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const AuthenticationRoundArchiveConfiguration& cfgConfiguration() const noexcept;
    const std::string& strRoundStatus() const noexcept;
    bool bValidSample() const noexcept;
    const std::string& strInvalidReason() const noexcept;
    const AuthenticationRoundArchiveDetails& varDetails() const noexcept;

private:
    std::uint64_t                         m_u64TimestampMilliseconds;
    std::string                           m_strExperimentId;
    std::string                           m_strRunId;
    std::string                           m_strGitCommit;
    std::string                           m_strNodeId;
    std::string                           m_strSenderId;
    std::uint64_t                         m_u64ChainId;
    AuthenticationRoundArchiveConfiguration m_cfgConfiguration;
    std::string                           m_strRoundStatus;
    bool                                  m_bValidSample;
    std::string                           m_strInvalidReason;
    AuthenticationRoundArchiveDetails    m_varDetails;
};

using AuthenticationMetricRecord = std::variant<
    VerificationMetricSample,
    EstimatedEnergyMetricSummary,
    CommunicationCostMetricSummary,
    AuthenticationRoundArchiveSummary
>;

/** @brief 固定文献系数能耗模型，不接受外部功率传感器输入。 */
class EstimatedEnergyCalculator final
{
public:
    static constexpr double CPU_MICRO_JOULE_PER_MICROSECOND = 0.181;
    static constexpr double WIFI_MICRO_JOULE_PER_BYTE = 0.038504;

    static double dEstimateMicroJoule(
        std::uint64_t u64VerifyTimeNanoseconds,
        std::uint64_t u64ReceivedAuthBytes
    ) noexcept;

private:
    EstimatedEnergyCalculator() = delete;
};

/** @brief 汇总一名Receiver在一轮中的验证耗时、路径和实际接收算法字节。 */
class AuthenticationRoundMetricCollector final
{
public:
    AuthenticationRoundMetricCollector(
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        AuthenticationMetricMode modeAuthentication,
        std::uint32_t u32PacketCount
    );

    void addDisclosureKeyMeasurement(const PerformanceMeasurement& mstMeasurement);
    void addVerificationSample(const VerificationMetricSample& smpVerification);
    void addReceivedAuthBytes(std::uint64_t u64ByteCount);
    /** @brief 标记攻击、重放、丢失或协议异常，使本轮只能用于诊断而不能进入正常对比。 */
    void markNormalComparisonIneligible() noexcept;
    EstimatedEnergyMetricSummary sumCreateEnergySummary(
        std::uint64_t u64TimestampMilliseconds,
        bool bRoundCompleteNormally
    ) const;

private:
    std::string              m_strRoundId;
    std::string              m_strSenderId;
    std::uint64_t            m_u64ChainId;
    AuthenticationMetricMode m_modeAuthentication;
    std::uint32_t            m_u32PacketCount;
    std::uint64_t            m_u64VerifyTimeNanoseconds;
    std::uint64_t            m_u64ReceivedAuthBytes;
    std::uint32_t            m_u32VerifiedPacketCount;
    std::uint32_t            m_u32FastGroupCount;
    std::uint32_t            m_u32FallbackGroupCount;
    std::uint32_t            m_u32IncompleteGroupCount;
    bool                     m_bNormalComparisonEligible;
};

/** @brief 保留有界指标记录并按稳定记录键去重，供实时事件和重连快照共用。 */
class AuthenticationMetricStore final
{
public:
    explicit AuthenticationMetricStore(std::size_t nMaximumRecordCount = 8192);

    bool bAppend(const AuthenticationMetricRecord& varRecord);
    void clear();
    std::vector<AuthenticationMetricRecord> vecSnapshot() const;
    std::size_t nRecordCount() const;

private:
    struct StoredRecord final
    {
        std::string                strKey;
        AuthenticationMetricRecord varRecord;
    };

    static std::string strRecordKey(const AuthenticationMetricRecord& varRecord);

    std::size_t                         m_nMaximumRecordCount;
    mutable std::mutex                  m_mtxRecords;
    std::deque<StoredRecord>            m_deqRecords;
    std::unordered_set<std::string>     m_setRecordKeys;
};
}

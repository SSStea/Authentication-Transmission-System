#pragma once

#include "tesla/metrics/AuthenticationMetrics.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace tesla::metrics
{
/** @brief 第20章固定算法字段公式，不读取完整UDP报文序列化长度。 */
class CommunicationCostCalculator final
{
public:
    static constexpr std::uint64_t ALGORITHM_FIELD_SIZE = 32;

    static CommunicationCostMetricSummary sumNative(
        std::uint64_t u64TimestampMilliseconds,
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint64_t u64PacketCount,
        std::uint64_t u64DataIntervalCount
    );
    static CommunicationCostMetricSummary sumImproved(
        std::uint64_t u64TimestampMilliseconds,
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint64_t u64PacketCount,
        std::uint64_t u64DataIntervalCount,
        std::uint64_t u64TauCount,
        std::uint64_t u64GroupCount
    );

    static std::uint64_t u64NativeDataPacketBytes() noexcept;
    static std::uint64_t u64ImprovedDataPacketBytes(
        std::size_t nTauCount,
        bool bHasFastGroupTag
    );
    static std::uint64_t u64DisclosedKeyBytes() noexcept;

private:
    CommunicationCostCalculator() = delete;
};

/** @brief Sender按成功发送的逻辑报文累计实际算法字段，供公式核对。 */
class CommunicationCostAccumulator final
{
public:
    explicit CommunicationCostAccumulator(
        AuthenticationMetricMode modeAuthentication
    );

    void addNativeDataPacket();
    void addImprovedDataPacket(
        std::size_t nTauCount,
        bool bHasFastGroupTag
    );
    void addDisclosedKey();
    CommunicationCostMetricSummary sumCreate(
        std::uint64_t u64TimestampMilliseconds,
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId
    ) const;

private:
    AuthenticationMetricMode m_modeAuthentication;
    std::uint64_t            m_u64MessageBytes;
    std::uint64_t            m_u64KeyBytes;
    std::uint64_t            m_u64MacBytes;
    std::uint64_t            m_u64TauBytes;
    std::uint64_t            m_u64FastGroupTagBytes;
};
}

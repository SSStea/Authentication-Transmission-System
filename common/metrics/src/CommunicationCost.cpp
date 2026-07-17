#include "tesla/metrics/CommunicationCost.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::metrics
{
namespace
{
std::uint64_t u64MultiplyFieldCount(std::uint64_t u64FieldCount)
{
    if (u64FieldCount
        > std::numeric_limits<std::uint64_t>::max()
            / CommunicationCostCalculator::ALGORITHM_FIELD_SIZE)
    {
        throw std::overflow_error("Communication cost field count overflows");
    }
    return u64FieldCount * CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
}
}

CommunicationCostMetricSummary CommunicationCostCalculator::sumNative(
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint64_t u64PacketCount,
    std::uint64_t u64DataIntervalCount
)
{
    return CommunicationCostMetricSummary(
        u64TimestampMilliseconds,
        std::move(strRoundId),
        std::move(strSenderId),
        u64ChainId,
        NativeCommunicationCostDetails(
            u64MultiplyFieldCount(u64PacketCount),
            u64MultiplyFieldCount(u64DataIntervalCount),
            u64MultiplyFieldCount(u64PacketCount)
        )
    );
}

CommunicationCostMetricSummary CommunicationCostCalculator::sumImproved(
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint64_t u64PacketCount,
    std::uint64_t u64DataIntervalCount,
    std::uint64_t u64TauCount,
    std::uint64_t u64GroupCount
)
{
    return CommunicationCostMetricSummary(
        u64TimestampMilliseconds,
        std::move(strRoundId),
        std::move(strSenderId),
        u64ChainId,
        ImprovedCommunicationCostDetails(
            u64MultiplyFieldCount(u64PacketCount),
            u64MultiplyFieldCount(u64DataIntervalCount),
            u64MultiplyFieldCount(u64TauCount),
            u64MultiplyFieldCount(u64GroupCount)
        )
    );
}

std::uint64_t CommunicationCostCalculator::u64NativeDataPacketBytes() noexcept
{
    return ALGORITHM_FIELD_SIZE * 2U;
}

std::uint64_t CommunicationCostCalculator::u64ImprovedDataPacketBytes(
    std::size_t nTauCount,
    bool bHasFastGroupTag
)
{
    return u64MultiplyFieldCount(
        1U + static_cast<std::uint64_t>(nTauCount)
            + (bHasFastGroupTag ? 1U : 0U)
    );
}

std::uint64_t CommunicationCostCalculator::u64DisclosedKeyBytes() noexcept
{
    return ALGORITHM_FIELD_SIZE;
}

CommunicationCostAccumulator::CommunicationCostAccumulator(
    AuthenticationMetricMode modeAuthentication
)
    : m_modeAuthentication(modeAuthentication),
      m_u64MessageBytes(0),
      m_u64KeyBytes(0),
      m_u64MacBytes(0),
      m_u64TauBytes(0),
      m_u64FastGroupTagBytes(0)
{
}

void CommunicationCostAccumulator::addNativeDataPacket()
{
    if (m_modeAuthentication != AuthenticationMetricMode::Native)
    {
        throw std::logic_error("Native packet cannot enter an improved accumulator");
    }

    m_u64MessageBytes += CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
    m_u64MacBytes += CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
}

void CommunicationCostAccumulator::addImprovedDataPacket(
    std::size_t nTauCount,
    bool bHasFastGroupTag
)
{
    if (m_modeAuthentication != AuthenticationMetricMode::Improved)
    {
        throw std::logic_error("Improved packet cannot enter a native accumulator");
    }

    m_u64MessageBytes += CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
    m_u64TauBytes += u64MultiplyFieldCount(
        static_cast<std::uint64_t>(nTauCount)
    );
    if (bHasFastGroupTag)
    {
        m_u64FastGroupTagBytes +=
            CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
    }
}

void CommunicationCostAccumulator::addDisclosedKey()
{
    m_u64KeyBytes += CommunicationCostCalculator::ALGORITHM_FIELD_SIZE;
}

CommunicationCostMetricSummary CommunicationCostAccumulator::sumCreate(
    std::uint64_t u64TimestampMilliseconds,
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId
) const
{
    CommunicationCostDetails varDetails =
        m_modeAuthentication == AuthenticationMetricMode::Native
        ? CommunicationCostDetails(NativeCommunicationCostDetails(
            m_u64MessageBytes,
            m_u64KeyBytes,
            m_u64MacBytes
        ))
        : CommunicationCostDetails(ImprovedCommunicationCostDetails(
            m_u64MessageBytes,
            m_u64KeyBytes,
            m_u64TauBytes,
            m_u64FastGroupTagBytes
        ));
    return CommunicationCostMetricSummary(
        u64TimestampMilliseconds,
        std::move(strRoundId),
        std::move(strSenderId),
        u64ChainId,
        std::move(varDetails)
    );
}
}

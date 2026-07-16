#include "tesla/core/KsRsVerificationResult.h"

#include <utility>

namespace tesla::core
{
// KS+RS验证结果是回退算法与策略层之间的位置级数据载体。
KsRsVerificationResult::KsRsVerificationResult(
    std::vector<std::size_t> vecGoodPositions,
    std::vector<std::size_t> vecBadPositions,
    bool bDetectionThresholdExceeded
)
    : m_vecGoodPositions(std::move(vecGoodPositions)),
      m_vecBadPositions(std::move(vecBadPositions)),
      m_bDetectionThresholdExceeded(bDetectionThresholdExceeded)
{
}

bool KsRsVerificationResult::bDetectionThresholdExceeded() const noexcept
{
    return m_bDetectionThresholdExceeded;
}

const std::vector<std::size_t>& KsRsVerificationResult::vecBadPositions() const noexcept
{
    return m_vecBadPositions;
}

const std::vector<std::size_t>& KsRsVerificationResult::vecGoodPositions() const noexcept
{
    return m_vecGoodPositions;
}
}

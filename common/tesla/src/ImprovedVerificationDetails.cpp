#include "tesla/core/ImprovedVerificationDetails.h"

#include <utility>

namespace tesla::core
{
// 改进验证详情集中保存实际路径、位置分类和门限判定。
ImprovedVerificationDetails::ImprovedVerificationDetails(
    ImprovedVerificationPath pathVerification,
    bool bFastGroupTagMatched,
    std::vector<std::size_t> vecAuthenticatedPositions,
    std::vector<std::size_t> vecRejectedPositions,
    bool bDetectionThresholdExceeded
)
    : m_pathVerification(pathVerification),
      m_bFastGroupTagMatched(bFastGroupTagMatched),
      m_vecAuthenticatedPositions(std::move(vecAuthenticatedPositions)),
      m_vecRejectedPositions(std::move(vecRejectedPositions)),
      m_bDetectionThresholdExceeded(bDetectionThresholdExceeded)
{
}

bool ImprovedVerificationDetails::bDetectionThresholdExceeded() const noexcept
{
    return m_bDetectionThresholdExceeded;
}

bool ImprovedVerificationDetails::bFastGroupTagMatched() const noexcept
{
    return m_bFastGroupTagMatched;
}

ImprovedVerificationPath ImprovedVerificationDetails::pathVerification() const noexcept
{
    return m_pathVerification;
}

const std::vector<std::size_t>&
ImprovedVerificationDetails::vecAuthenticatedPositions() const noexcept
{
    return m_vecAuthenticatedPositions;
}

const std::vector<std::size_t>&
ImprovedVerificationDetails::vecRejectedPositions() const noexcept
{
    return m_vecRejectedPositions;
}
}

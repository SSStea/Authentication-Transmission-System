#include "tesla/core/ImprovedTeslaDetails.h"

#include <utility>

namespace tesla::core
{
// 改进模式详情独立封装SAMD标签和快速组标签，避免污染统一结果类型。
ImprovedAuthenticationDetails::ImprovedAuthenticationDetails(
    std::vector<crypto::Digest> vecSamdTau,
    std::optional<crypto::Digest> optFastGroupTag
)
    : m_vecSamdTau(std::move(vecSamdTau)),
      m_optFastGroupTag(std::move(optFastGroupTag))
{
}

const std::optional<crypto::Digest>&
ImprovedAuthenticationDetails::optFastGroupTag() const noexcept
{
    return m_optFastGroupTag;
}

const std::vector<crypto::Digest>& ImprovedAuthenticationDetails::vecSamdTau() const noexcept
{
    return m_vecSamdTau;
}

ImprovedVerificationDetails::ImprovedVerificationDetails(
    ImprovedVerificationPath pathVerification,
    bool bFastGroupTagMatched,
    std::vector<std::size_t> vecAuthenticatedPositions,
    std::vector<std::size_t> vecRejectedPositions,
    bool bDetectionThresholdExceeded,
    std::vector<KsRsLocationStep> vecLocationSteps
)
    : m_pathVerification(pathVerification),
      m_bFastGroupTagMatched(bFastGroupTagMatched),
      m_vecAuthenticatedPositions(std::move(vecAuthenticatedPositions)),
      m_vecRejectedPositions(std::move(vecRejectedPositions)),
      m_bDetectionThresholdExceeded(bDetectionThresholdExceeded),
      m_vecLocationSteps(std::move(vecLocationSteps))
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

ImprovedVerificationPath
ImprovedVerificationDetails::pathVerification() const noexcept
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

const std::vector<KsRsLocationStep>&
ImprovedVerificationDetails::vecLocationSteps() const noexcept
{
    return m_vecLocationSteps;
}
}

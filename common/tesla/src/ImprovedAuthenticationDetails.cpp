#include "tesla/core/ImprovedAuthenticationDetails.h"

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
}

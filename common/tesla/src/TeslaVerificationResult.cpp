#include "tesla/core/TeslaVerificationResult.h"

#include <utility>

namespace tesla::core
{
// 统一结果仅组合总体状态和模式专用variant，不平铺不同模式字段。
TeslaVerificationResult::TeslaVerificationResult(
    bool bPassed,
    TeslaVerificationDetails varDetails
)
    : m_bPassed(bPassed),
      m_varDetails(std::move(varDetails))
{
}

bool TeslaVerificationResult::bPassed() const noexcept
{
    return m_bPassed;
}

const TeslaVerificationDetails& TeslaVerificationResult::varDetails() const noexcept
{
    return m_varDetails;
}
}

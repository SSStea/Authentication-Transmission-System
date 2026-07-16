#pragma once

#include "tesla/core/TeslaVerificationDetails.h"

namespace tesla::core
{
/**
 * @brief 组合总体通过状态和当前模式专用验证详情。
 */
class TeslaVerificationResult final
{
public:
    /**
     * @brief 创建统一验证结果。
     * @param bPassed 整个认证组是否通过当前策略验证。
     * @param varDetails 原生或改进模式专用详情。
     */
    TeslaVerificationResult(bool bPassed, TeslaVerificationDetails varDetails);

    /** @return 整个认证组通过时返回true。 */
    bool bPassed() const noexcept;

    /** @return 当前策略对应的模式专用详情variant。 */
    const TeslaVerificationDetails& varDetails() const noexcept;

private:
    bool                     m_bPassed;
    TeslaVerificationDetails m_varDetails;
};
}

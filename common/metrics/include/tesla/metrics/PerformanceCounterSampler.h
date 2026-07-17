#pragma once

#include "tesla/metrics/AuthenticationMetrics.h"

#include <memory>

namespace tesla::metrics
{
/** @brief 验证策略使用的性能采样边界，所有实现必须提供单调时钟耗时。 */
class VerificationPerformanceSampler
{
public:
    virtual ~VerificationPerformanceSampler() = default;

    virtual void begin() = 0;
    virtual PerformanceMeasurement mstEnd() noexcept = 0;
};

/** @brief 创建当前平台可用的采样策略；硬件计数失败时自动保留耗时采样。 */
std::unique_ptr<VerificationPerformanceSampler>
    ptrCreateVerificationPerformanceSampler();
}

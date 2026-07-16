#pragma once

#include "tesla/core/KsRsMatrix.h"
#include "tesla/core/TeslaStrategy.h"
#include "tesla/crypto/CryptoProvider.h"

#include <cstddef>

namespace tesla::core
{
/**
 * @brief 实现快速组标签优先、KS+RS与SAMD回退定位的改进TESLA策略。
 */
class ImprovedTeslaStrategy final : public TeslaStrategy
{
public:
    /**
     * @brief 创建绑定固定KS+RS参数的改进TESLA策略。
     * @param crpProvider 生命周期必须覆盖本策略的密码提供者。
     * @param nGroupSize 每个认证组允许的最大固定槽位数量。
     * @param nDetectionThreshold KS+RS检测门限。
     * @throws std::invalid_argument 组大小或检测门限无效时抛出。
     * @throws std::runtime_error 无法构造有效KS+RS矩阵时抛出。
     */
    ImprovedTeslaStrategy(
        const crypto::CryptoProvider& crpProvider,
        std::size_t nGroupSize,
        std::size_t nDetectionThreshold
    );

    /** @copydoc TeslaStrategy::authCreateAuthenticationDetails() */
    TeslaAuthenticationDetails authCreateAuthenticationDetails(
        const AuthenticationGroupInput& grpInput,
        const crypto::Digest& digDataKey
    ) const override;

    /** @copydoc TeslaStrategy::vfyVerify() */
    TeslaVerificationResult vfyVerify(
        const AuthenticationGroupInput& grpInput,
        const TeslaAuthenticationDetails& varReceivedDetails,
        const crypto::Digest& digDataKey
    ) const override;

private:
    std::vector<std::optional<crypto::Digest>> vecComputePacketMacSlots(
        const AuthenticationGroupInput& grpInput,
        const crypto::Digest& digDataKey
    ) const;

    const crypto::CryptoProvider& m_crpProvider;
    KsRsMatrix                    m_matKsRs;
};
}

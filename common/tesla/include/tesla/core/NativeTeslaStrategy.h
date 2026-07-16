#pragma once

#include "tesla/core/TeslaStrategy.h"
#include "tesla/crypto/CryptoProvider.h"

namespace tesla::core
{
/**
 * @brief 实现为每个报文独立生成和验证MAC的原生TESLA策略。
 */
class NativeTeslaStrategy final : public TeslaStrategy
{
public:
    /**
     * @brief 创建原生TESLA策略。
     * @param crpProvider 生命周期必须覆盖本策略的密码提供者。
     */
    explicit NativeTeslaStrategy(const crypto::CryptoProvider& crpProvider);

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
    const crypto::CryptoProvider& m_crpProvider;
};
}

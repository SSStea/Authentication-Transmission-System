#pragma once

#include "tesla/core/AuthenticationGroupInput.h"
#include "tesla/core/TeslaAuthenticationDetails.h"
#include "tesla/core/TeslaVerificationResult.h"
#include "tesla/crypto/CryptoTypes.h"

namespace tesla::core
{
/**
 * @brief 原生和改进TESLA认证模式的统一策略接口。
 *
 * 公共调用方通过统一接口工作，具体字段保存在模式专用variant详情中。
 */
class TeslaStrategy
{
public:
    virtual ~TeslaStrategy() = default;

    /**
     * @brief 为发送端完整报文组生成当前模式的认证详情。
     * @param grpInput 不含缺失报文的算法组输入。
     * @param digDataKey 当前TESLA间隔的数据密钥。
     * @return 当前策略对应的模式专用认证详情variant。
     * @throws std::invalid_argument 输入组不满足当前策略约束时抛出。
     */
    virtual TeslaAuthenticationDetails authCreateAuthenticationDetails(
        const AuthenticationGroupInput& grpInput,
        const crypto::Digest& digDataKey
    ) const = 0;

    /**
     * @brief 验证接收组及其模式专用认证详情。
     * @param grpInput 保留实际丢包位置的接收组算法输入。
     * @param varReceivedDetails 当前模式接收到的认证详情variant。
     * @param digDataKey 已验证披露的当前TESLA间隔数据密钥。
     * @return 总体状态和模式专用验证详情。
     * @throws std::invalid_argument variant模式或输入尺寸与当前策略不匹配时抛出。
     */
    virtual TeslaVerificationResult vfyVerify(
        const AuthenticationGroupInput& grpInput,
        const TeslaAuthenticationDetails& varReceivedDetails,
        const crypto::Digest& digDataKey
    ) const = 0;
};
}

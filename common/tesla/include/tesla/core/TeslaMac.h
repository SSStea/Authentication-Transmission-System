#pragma once

#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/crypto/CryptoProvider.h"

#include <vector>

namespace tesla::core
{
/**
 * @brief 负责TESLA逐包MAC、快速组标签及其域隔离密钥派生。
 */
class TeslaMac final
{
public:
    /**
     * @brief 为完整认证组计算快速组标签。
     * @param crpProvider 密码算法提供者。
     * @param digDataKey 当前TESLA间隔数据密钥。
     * @param grpInput 不含缺失报文的组算法输入。
     * @param vecSamdTau 当前组的SAMD标签。
     * @return 经过专用密钥和确定性组输入计算的HMAC。
     */
    static crypto::Digest digComputeFastGroupTag(
        const crypto::CryptoProvider& crpProvider,
        const crypto::Digest& digDataKey,
        const AuthenticationGroupInput& grpInput,
        const std::vector<crypto::Digest>& vecSamdTau
    );

    /**
     * @brief 为单个认证报文计算TESLA MAC。
     * @param crpProvider 密码算法提供者。
     * @param digDataKey 当前TESLA间隔数据密钥。
     * @param pktInput 单包算法输入。
     * @return 单包HMAC。
     */
    static crypto::Digest digComputePacketMac(
        const crypto::CryptoProvider& crpProvider,
        const crypto::Digest& digDataKey,
        const AuthenticationPacketInput& pktInput
    );

    /**
     * @brief 通过固定域标签派生快速组标签专用密钥。
     * @param crpProvider 密码算法提供者。
     * @param digDataKey 当前TESLA间隔数据密钥。
     * @return 快速组标签专用密钥。
     */
    static crypto::Digest digDeriveFastGroupKey(
        const crypto::CryptoProvider& crpProvider,
        const crypto::Digest& digDataKey
    );

    /**
     * @brief 通过单向散列从间隔数据密钥派生逐包MAC密钥。
     * @param crpProvider 密码算法提供者。
     * @param digDataKey 当前TESLA间隔数据密钥。
     * @return 逐包MAC专用密钥。
     */
    static crypto::Digest digDerivePacketMacKey(
        const crypto::CryptoProvider& crpProvider,
        const crypto::Digest& digDataKey
    );

private:
    TeslaMac() = delete;
};
}

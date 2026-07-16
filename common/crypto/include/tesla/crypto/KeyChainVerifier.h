#pragma once

#include "tesla/crypto/CryptoProvider.h"

#include <cstddef>

namespace tesla::crypto
{
/**
 * @brief 根据K0承诺验证TESLA披露密钥及其链索引。
 */
class KeyChainVerifier final
{
public:
    /**
     * @brief 将披露密钥按索引次数回哈希至K0并进行常量时间比较。
     * @param crpProvider 与密钥链生成阶段相同的密码提供者。
     * @param digDisclosedKey 待验证的披露密钥。
     * @param nDisclosedKeyIndex 披露密钥在链中的索引。
     * @param digCommitmentKey 预先可信分发的K0。
     * @return 密钥能够回溯到K0时返回true。
     */
    static bool bVerifyDisclosedKey(
        const CryptoProvider& crpProvider,
        const Digest& digDisclosedKey,
        std::size_t nDisclosedKeyIndex,
        const Digest& digCommitmentKey
    );

private:
    KeyChainVerifier() = delete;
};
}

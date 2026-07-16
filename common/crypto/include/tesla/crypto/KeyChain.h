#pragma once

#include "tesla/crypto/CryptoProvider.h"

#include <cstddef>
#include <vector>

namespace tesla::crypto
{
/**
 * @brief 保存由单向散列函数生成的TESLA密钥链。
 *
 * 索引0固定为承诺密钥K0，数据间隔从索引1开始使用后续密钥。
 */
class KeyChain final
{
public:
    /**
     * @brief 根据种子和数据间隔数量创建完整密钥链。
     * @param crpProvider 用于链式散列的密码提供者。
     * @param vecSeed 仅用于生成链尾的非空种子。
     * @param nDataIntervalCount 需要生成的数据间隔密钥数量。
     * @return 包含K0和全部数据密钥的密钥链。
     * @throws std::invalid_argument 种子为空或间隔数量为0时抛出。
     */
    static KeyChain keyCreate(
        const CryptoProvider& crpProvider,
        const ByteBuffer& vecSeed,
        std::size_t nDataIntervalCount
    );

    /**
     * @brief 获取用于预先分发和验证披露密钥的承诺密钥K0。
     * @return 承诺密钥的只读引用。
     */
    const Digest& digCommitmentKey() const noexcept;

    /**
     * @brief 获取指定TESLA数据间隔使用的密钥。
     * @param nIntervalIndex 从1开始的数据间隔索引。
     * @return 对应数据密钥的只读引用。
     * @throws std::out_of_range 索引为0或超过已生成间隔范围时抛出。
     */
    const Digest& digDataKey(std::size_t nIntervalIndex) const;

    /**
     * @brief 获取密钥链可服务的数据间隔数量。
     * @return 不包含K0的间隔密钥数量。
     */
    std::size_t nDataIntervalCount() const noexcept;

private:
    explicit KeyChain(std::vector<Digest> vecKeys);

    std::vector<Digest> m_vecKeys;
};

/**
 * @brief 根据K0承诺验证TESLA披露密钥及其链索引。
 *
 * 验证逻辑与密钥链生成遵循同一单向散列关系，因此与KeyChain保存在同一模块文件。
 */
class KeyChainVerifier final
{
public:
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

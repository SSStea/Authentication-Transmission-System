#pragma once

#include "tesla/crypto/CryptoAlgorithm.h"
#include "tesla/crypto/CryptoTypes.h"

namespace tesla::crypto
{
/**
 * @brief 摘要和HMAC运算的策略接口。
 *
 * TESLA核心算法只依赖本接口，不直接依赖具体密码库或算法实现。
 */
class CryptoProvider
{
public:
    virtual ~CryptoProvider() = default;

    /**
     * @brief 获取当前提供者使用的密码算法。
     * @return 当前密码算法。
     */
    virtual CryptoAlgorithm algAlgorithm() const noexcept = 0;

    /**
     * @brief 计算输入数据的固定32字节摘要。
     * @param vecData 待摘要的原始字节。
     * @return 计算得到的摘要。
     * @throws std::runtime_error 底层密码运算失败时抛出。
     */
    virtual Digest digHash(const ByteBuffer& vecData) const = 0;

    /**
     * @brief 使用指定密钥计算输入数据的HMAC。
     * @param vecKey HMAC原始密钥字节。
     * @param vecData 待认证的原始字节。
     * @return 固定32字节HMAC。
     * @throws std::invalid_argument 密钥长度不受底层实现支持时抛出。
     * @throws std::runtime_error 底层密码运算失败时抛出。
     */
    virtual Digest digHmac(const ByteBuffer& vecKey, const ByteBuffer& vecData) const = 0;
};
}

#pragma once

#include "tesla/crypto/CryptoTypes.h"

#include <cstddef>

namespace tesla::crypto
{
/**
 * @brief 为CA等安全敏感模块提供可替换的密码学随机字节接口。
 *
 * 正式程序使用OpenSSL实现；测试可以注入确定性序列，以稳定覆盖chainId冲突重试。
 */
class SecureRandomProvider
{
public:
    virtual ~SecureRandomProvider() = default;

    /**
     * @brief 生成指定数量的密码学安全随机字节。
     * @param nSize 需要生成的字节数，必须大于0。
     * @return 恰好包含nSize个随机字节的缓冲区。
     */
    virtual ByteBuffer vecGenerateBytes(std::size_t nSize) const = 0;
};
}

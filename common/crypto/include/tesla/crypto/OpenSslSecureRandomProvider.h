#pragma once

#include "tesla/crypto/SecureRandomProvider.h"

namespace tesla::crypto
{
/** @brief 使用OpenSSL系统熵源实现密码学安全随机字节生成。 */
class OpenSslSecureRandomProvider final : public SecureRandomProvider
{
public:
    /** @copydoc SecureRandomProvider::vecGenerateBytes() */
    ByteBuffer vecGenerateBytes(std::size_t nSize) const override;
};
}

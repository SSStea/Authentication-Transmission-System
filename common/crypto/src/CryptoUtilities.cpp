#include "tesla/crypto/CryptoUtilities.h"

#include <openssl/crypto.h>

namespace tesla::crypto
{
bool CryptoUtilities::bDigestEquals(const Digest& digLeft, const Digest& digRight) noexcept
{
    // 密码摘要必须使用常量时间比较，避免短路比较泄漏首个差异位置。
    return CRYPTO_memcmp(digLeft.data(), digRight.data(), digLeft.size()) == 0;
}

ByteBuffer CryptoUtilities::vecToByteBuffer(const Digest& digValue)
{
    return ByteBuffer(digValue.begin(), digValue.end());
}
}

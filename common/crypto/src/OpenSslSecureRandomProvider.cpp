#include "tesla/crypto/OpenSslSecureRandomProvider.h"

#include <openssl/rand.h>

#include <climits>
#include <stdexcept>

namespace tesla::crypto
{
ByteBuffer OpenSslSecureRandomProvider::vecGenerateBytes(std::size_t nSize) const
{
    if (nSize == 0)
    {
        throw std::invalid_argument("Secure random byte count must be positive");
    }

    if (nSize > static_cast<std::size_t>(INT_MAX))
    {
        throw std::invalid_argument("Secure random byte count is too large");
    }

    ByteBuffer vecBytes(nSize);

    // RAND_bytes使用OpenSSL已播种的系统级CSPRNG，失败时不得降级到普通伪随机数。
    if (RAND_bytes(vecBytes.data(), static_cast<int>(vecBytes.size())) != 1)
    {
        throw std::runtime_error("OpenSSL secure random generation failed");
    }

    return vecBytes;
}
}

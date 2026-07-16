#include "tesla/crypto/OpenSslCryptoProvider.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <climits>
#include <stdexcept>

namespace tesla::crypto
{
OpenSslCryptoProvider::OpenSslCryptoProvider(CryptoAlgorithm algAlgorithm)
    : m_algAlgorithm(algAlgorithm)
{
}

CryptoAlgorithm OpenSslCryptoProvider::algAlgorithm() const noexcept
{
    return m_algAlgorithm;
}

Digest OpenSslCryptoProvider::digHash(const ByteBuffer& vecData) const
{
    Digest             digResult{};
    unsigned int       nDigestLength = 0;

    // OpenSSL允许空输入，但空vector不能无条件解引用data指针。
    const std::uint8_t* pData = vecData.empty() ? nullptr : vecData.data();

    if (EVP_Digest(
            pData,
            vecData.size(),
            digResult.data(),
            &nDigestLength,
            pResolveDigest(),
            nullptr
        ) != 1 || nDigestLength != digResult.size())
    {
        throw std::runtime_error("OpenSSL hash calculation failed");
    }

    return digResult;
}

Digest OpenSslCryptoProvider::digHmac(const ByteBuffer& vecKey, const ByteBuffer& vecData) const
{
    if (vecKey.size() > static_cast<std::size_t>(INT_MAX))
    {
        throw std::invalid_argument("HMAC key is too large");
    }

    Digest             digResult{};
    unsigned int       nDigestLength = 0;

    // 同时处理空密钥和空消息，并校验OpenSSL实际输出仍为32字节。
    const std::uint8_t* pKey = vecKey.empty() ? nullptr : vecKey.data();
    const std::uint8_t* pData = vecData.empty() ? nullptr : vecData.data();

    if (HMAC(
            pResolveDigest(),
            pKey,
            static_cast<int>(vecKey.size()),
            pData,
            vecData.size(),
            digResult.data(),
            &nDigestLength
        ) == nullptr || nDigestLength != digResult.size())
    {
        throw std::runtime_error("OpenSSL HMAC calculation failed");
    }

    return digResult;
}

const EVP_MD* OpenSslCryptoProvider::pResolveDigest() const
{
    switch (m_algAlgorithm)
    {
    case CryptoAlgorithm::Sha256:
        return EVP_sha256();
    case CryptoAlgorithm::Sm3:
        return EVP_sm3();
    case CryptoAlgorithm::Sha3_256:
        return EVP_sha3_256();
    }

    throw std::invalid_argument("Unsupported crypto algorithm");
}
}

#pragma once

#include "tesla/crypto/CryptoProvider.h"

typedef struct evp_md_st EVP_MD;

namespace tesla::crypto
{
/**
 * @brief 基于OpenSSL EVP接口实现摘要和HMAC运算。
 */
class OpenSslCryptoProvider final : public CryptoProvider
{
public:
    /**
     * @brief 创建使用指定摘要算法的密码提供者。
     * @param algAlgorithm SHA-256、SM3或SHA3-256。
     */
    explicit OpenSslCryptoProvider(CryptoAlgorithm algAlgorithm);

    /** @copydoc CryptoProvider::algAlgorithm() */
    CryptoAlgorithm algAlgorithm() const noexcept override;

    /** @copydoc CryptoProvider::digHash() */
    Digest digHash(const ByteBuffer& vecData) const override;

    /** @copydoc CryptoProvider::digHmac() */
    Digest digHmac(const ByteBuffer& vecKey, const ByteBuffer& vecData) const override;

private:
    const EVP_MD* pResolveDigest() const;

    CryptoAlgorithm m_algAlgorithm;
};
}

#include "tesla/crypto/KeyChainVerifier.h"

#include "tesla/crypto/CryptoUtilities.h"

namespace tesla::crypto
{
bool KeyChainVerifier::bVerifyDisclosedKey(
    const CryptoProvider& crpProvider,
    const Digest& digDisclosedKey,
    std::size_t nDisclosedKeyIndex,
    const Digest& digCommitmentKey
)
{
    Digest digCurrent = digDisclosedKey;

    // 索引i的密钥连续散列i次应恰好回到预先可信的K0。
    for (std::size_t nIndex = 0; nIndex < nDisclosedKeyIndex; ++nIndex)
    {
        digCurrent = crpProvider.digHash(CryptoUtilities::vecToByteBuffer(digCurrent));
    }

    return CryptoUtilities::bDigestEquals(digCurrent, digCommitmentKey);
}
}

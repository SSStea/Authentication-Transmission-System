#include "tesla/crypto/KeyChain.h"

#include "tesla/crypto/CryptoUtilities.h"

#include <stdexcept>
#include <utility>

namespace tesla::crypto
{
KeyChain KeyChain::keyCreate(
    const CryptoProvider& crpProvider,
    const ByteBuffer& vecSeed,
    std::size_t nDataIntervalCount
)
{
    if (vecSeed.empty())
    {
        throw std::invalid_argument("Key-chain seed must not be empty");
    }

    if (nDataIntervalCount == 0)
    {
        throw std::invalid_argument("Key chain requires at least one data interval");
    }

    std::vector<Digest> vecKeys(nDataIntervalCount + 1);

    // 先由种子产生链尾，再反向散列至索引0，保证后续密钥只能验证而不能预测。
    vecKeys[nDataIntervalCount] = crpProvider.digHash(vecSeed);

    for (std::size_t nIndex = nDataIntervalCount; nIndex > 0; --nIndex)
    {
        vecKeys[nIndex - 1] = crpProvider.digHash(
            CryptoUtilities::vecToByteBuffer(vecKeys[nIndex])
        );
    }

    return KeyChain(std::move(vecKeys));
}

const Digest& KeyChain::digCommitmentKey() const noexcept
{
    return m_vecKeys.front();
}

const Digest& KeyChain::digDataKey(std::size_t nIntervalIndex) const
{
    if (nIntervalIndex == 0 || nIntervalIndex >= m_vecKeys.size())
    {
        throw std::out_of_range("Data-key interval index is out of range");
    }

    return m_vecKeys[nIntervalIndex];
}

std::size_t KeyChain::nDataIntervalCount() const noexcept
{
    return m_vecKeys.size() - 1;
}

KeyChain::KeyChain(std::vector<Digest> vecKeys)
    : m_vecKeys(std::move(vecKeys))
{
}
}

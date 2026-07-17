#include "tesla/core/LocalSenderKeyChainObservation.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
LocalSenderKeyChainSnapshot::LocalSenderKeyChainSnapshot(
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32DisclosureDelay,
    std::vector<crypto::Digest> vecKeys
)
    : m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_vecKeys(std::move(vecKeys))
{
    if (m_strSenderId.empty()
        || m_u64ChainId == 0
        || m_u32DisclosureDelay == 0
        || m_vecKeys.size() < 2)
    {
        throw std::invalid_argument("Local sender key-chain snapshot is invalid");
    }
}

const std::string& LocalSenderKeyChainSnapshot::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t LocalSenderKeyChainSnapshot::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t LocalSenderKeyChainSnapshot::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

const std::vector<crypto::Digest>&
LocalSenderKeyChainSnapshot::vecKeys() const noexcept
{
    return m_vecKeys;
}

LocalSenderKeyChainProgress::LocalSenderKeyChainProgress(
    std::string strRoundId,
    std::uint64_t u64ChainId,
    std::uint32_t u32CurrentDataKeyIndex,
    std::uint32_t u32DisclosedThroughKeyIndex,
    bool bCompleted
)
    : m_strRoundId(std::move(strRoundId)),
      m_u64ChainId(u64ChainId),
      m_u32CurrentDataKeyIndex(u32CurrentDataKeyIndex),
      m_u32DisclosedThroughKeyIndex(u32DisclosedThroughKeyIndex),
      m_bCompleted(bCompleted)
{
    if (m_strRoundId.empty() || m_u64ChainId == 0)
    {
        throw std::invalid_argument("Local sender key-chain progress is invalid");
    }
}

const std::string& LocalSenderKeyChainProgress::strRoundId() const noexcept
{
    return m_strRoundId;
}

std::uint64_t LocalSenderKeyChainProgress::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t
LocalSenderKeyChainProgress::u32CurrentDataKeyIndex() const noexcept
{
    return m_u32CurrentDataKeyIndex;
}

std::uint32_t
LocalSenderKeyChainProgress::u32DisclosedThroughKeyIndex() const noexcept
{
    return m_u32DisclosedThroughKeyIndex;
}

bool LocalSenderKeyChainProgress::bCompleted() const noexcept
{
    return m_bCompleted;
}
}

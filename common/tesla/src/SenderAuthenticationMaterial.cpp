#include "tesla/core/SenderAuthenticationMaterial.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
SenderAuthenticationMaterial::SenderAuthenticationMaterial(
    std::string strSenderId,
    std::uint64_t u64ChainId,
    crypto::ByteBuffer vecChainSeed,
    crypto::Digest digCommitmentKey,
    AuthenticationRoundParameters prmRoundParameters
)
    : m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_vecChainSeed(std::move(vecChainSeed)),
      m_digCommitmentKey(std::move(digCommitmentKey)),
      m_prmRoundParameters(std::move(prmRoundParameters))
{
    if (m_strSenderId.empty())
    {
        throw std::invalid_argument("Sender ID must not be empty");
    }

    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Chain ID must not be zero");
    }

    if (m_vecChainSeed.size() != CHAIN_SEED_SIZE)
    {
        throw std::invalid_argument("Sender key-chain seed must contain exactly 32 bytes");
    }
}

const std::string& SenderAuthenticationMaterial::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t SenderAuthenticationMaterial::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const crypto::ByteBuffer& SenderAuthenticationMaterial::vecChainSeed() const noexcept
{
    return m_vecChainSeed;
}

const crypto::Digest& SenderAuthenticationMaterial::digCommitmentKey() const noexcept
{
    return m_digCommitmentKey;
}

const AuthenticationRoundParameters&
SenderAuthenticationMaterial::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}
}

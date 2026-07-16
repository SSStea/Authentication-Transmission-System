#include "tesla/core/SenderAuthenticationContext.h"

#include "tesla/crypto/CryptoUtilities.h"

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
        throw std::invalid_argument(
            "Sender key-chain seed must contain exactly 32 bytes"
        );
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

const crypto::ByteBuffer&
SenderAuthenticationMaterial::vecChainSeed() const noexcept
{
    return m_vecChainSeed;
}

const crypto::Digest&
SenderAuthenticationMaterial::digCommitmentKey() const noexcept
{
    return m_digCommitmentKey;
}

const AuthenticationRoundParameters&
SenderAuthenticationMaterial::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}

SenderAuthenticationContext SenderAuthenticationContext::ctxCreateVerified(
    SenderAuthenticationMaterial matMaterial,
    const crypto::CryptoProvider& crpProvider
)
{
    if (crpProvider.algAlgorithm()
        != matMaterial.prmRoundParameters().algCryptoAlgorithm())
    {
        throw std::invalid_argument(
            "Sender crypto provider does not match authentication configuration"
        );
    }

    crypto::KeyChain keyChain = crypto::KeyChain::keyCreate(
        crpProvider,
        matMaterial.vecChainSeed(),
        matMaterial.prmRoundParameters().nDataIntervalCount()
    );

    // K0属于公开承诺值，仍使用常量时间比较，避免给配置校验路径引入可测时序差异。
    if (!crypto::CryptoUtilities::bDigestEquals(
            keyChain.digCommitmentKey(),
            matMaterial.digCommitmentKey()
        ))
    {
        throw std::invalid_argument(
            "Sender key-chain commitment does not match supplied K0"
        );
    }

    return SenderAuthenticationContext(std::move(matMaterial), std::move(keyChain));
}

const SenderAuthenticationMaterial&
SenderAuthenticationContext::matMaterial() const noexcept
{
    return m_matMaterial;
}

const crypto::KeyChain& SenderAuthenticationContext::keyChain() const noexcept
{
    return m_keyChain;
}

SenderAuthenticationContext::SenderAuthenticationContext(
    SenderAuthenticationMaterial matMaterial,
    crypto::KeyChain keyChain
)
    : m_matMaterial(std::move(matMaterial)),
      m_keyChain(std::move(keyChain))
{
}
}

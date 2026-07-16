#include "tesla/core/SenderAuthenticationContext.h"

#include "tesla/crypto/CryptoUtilities.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
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

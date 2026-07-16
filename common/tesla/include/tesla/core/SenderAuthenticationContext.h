#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/CryptoProvider.h"
#include "tesla/crypto/CryptoTypes.h"
#include "tesla/crypto/KeyChain.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace tesla::core
{
/**
 * @brief 保存CA仅向指定Sender下发的私有认证材料。
 *
 * 私有材料和经验证的Sender运行上下文具有相同生命周期，但仍与Receiver公开上下文分离。
 */
class SenderAuthenticationMaterial final
{
public:
    static constexpr std::size_t CHAIN_SEED_SIZE = 32;

    SenderAuthenticationMaterial(
        std::string strSenderId,
        std::uint64_t u64ChainId,
        crypto::ByteBuffer vecChainSeed,
        crypto::Digest digCommitmentKey,
        AuthenticationRoundParameters prmRoundParameters
    );

    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const crypto::ByteBuffer& vecChainSeed() const noexcept;
    const crypto::Digest& digCommitmentKey() const noexcept;
    const AuthenticationRoundParameters& prmRoundParameters() const noexcept;

private:
    std::string                    m_strSenderId;
    std::uint64_t                  m_u64ChainId;
    crypto::ByteBuffer             m_vecChainSeed;
    crypto::Digest                 m_digCommitmentKey;
    AuthenticationRoundParameters  m_prmRoundParameters;
};

/**
 * @brief 保存Sender验证通过后的认证材料和本地重建密钥链。
 *
 * 创建时会重新计算K0并做常量时间比较；只有完整验证通过的配置才能成为运行时状态。
 */
class SenderAuthenticationContext final
{
public:
    static SenderAuthenticationContext ctxCreateVerified(
        SenderAuthenticationMaterial matMaterial,
        const crypto::CryptoProvider& crpProvider
    );

    const SenderAuthenticationMaterial& matMaterial() const noexcept;
    const crypto::KeyChain& keyChain() const noexcept;

private:
    SenderAuthenticationContext(
        SenderAuthenticationMaterial matMaterial,
        crypto::KeyChain keyChain
    );

    SenderAuthenticationMaterial  m_matMaterial;
    crypto::KeyChain              m_keyChain;
};
}

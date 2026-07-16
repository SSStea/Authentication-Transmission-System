#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/CryptoTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace tesla::core
{
/**
 * @brief 保存CA仅向指定Sender下发的私有认证材料。
 *
 * 该类型包含密钥链种子，不能用于Receiver配置或日志输出，从类型层面降低秘密材料误发风险。
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
}

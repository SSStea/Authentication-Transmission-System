#pragma once

#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/crypto/SecureRandomProvider.h"

#include <cstdint>
#include <mutex>
#include <set>
#include <string>

namespace tesla::core
{
/**
 * @brief 为每个Sender签发独立的TESLA链标识、随机种子和承诺密钥。
 *
 * CA只在签发期间构造完整密钥链以取得K0，不保存也不向Receiver分发完整密钥链。
 */
class AuthenticationAuthority final
{
public:
    explicit AuthenticationAuthority(
        const crypto::SecureRandomProvider& rngSecureRandomProvider
    );

    SenderAuthenticationMaterial matIssueSenderMaterial(
        std::string strSenderId,
        AuthenticationRoundParameters prmRoundParameters
    );

    ReceiverAuthenticationContext ctxCreateReceiverContext(
        const SenderAuthenticationMaterial& matMaterial,
        std::string strSenderIpAddress
    ) const;

private:
    static std::uint64_t u64DecodeChainId(
        const crypto::ByteBuffer& vecChainIdBytes
    );

    const crypto::SecureRandomProvider&  m_rngSecureRandomProvider;
    std::mutex                           m_mtxIssuedMaterials;
    std::set<std::uint64_t>              m_setIssuedChainIds;
    std::set<crypto::ByteBuffer>          m_setIssuedSeeds;
    std::set<crypto::Digest>              m_setIssuedCommitmentKeys;
};
}

#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/CryptoTypes.h"

#include <cstdint>
#include <string>

namespace tesla::core
{
/**
 * @brief 保存Receiver验证某个Sender密钥链所需的公开上下文。
 *
 * Receiver上下文只包含来源映射、chainId和K0，明确不包含种子或完整密钥链。
 */
class ReceiverAuthenticationContext final
{
public:
    ReceiverAuthenticationContext(
        std::string strSenderId,
        std::string strSenderIpAddress,
        std::uint64_t u64ChainId,
        crypto::Digest digCommitmentKey,
        AuthenticationRoundParameters prmRoundParameters
    );

    const std::string& strSenderId() const noexcept;
    const std::string& strSenderIpAddress() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const crypto::Digest& digCommitmentKey() const noexcept;
    const AuthenticationRoundParameters& prmRoundParameters() const noexcept;

private:
    std::string                    m_strSenderId;
    std::string                    m_strSenderIpAddress;
    std::uint64_t                  m_u64ChainId;
    crypto::Digest                 m_digCommitmentKey;
    AuthenticationRoundParameters  m_prmRoundParameters;
};
}

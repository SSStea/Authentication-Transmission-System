#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/CryptoTypes.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
/**
 * @brief 保存Receiver验证某个Sender密钥链所需的公开上下文。
 *
 * 公开上下文与其索引存储共同变化，但文件中仍不存在Sender种子或完整密钥链。
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

enum class ReceiverAuthenticationContextLookupError
{
    UnknownSourceIp,
    UnknownChainId
};

using ReceiverAuthenticationContextLookupResult = std::variant<
    ReceiverAuthenticationContext,
    ReceiverAuthenticationContextLookupError
>;

/**
 * @brief 以来源IP先映射Sender，再以Sender和chainId查找公开认证上下文。
 *
 * replaceAll先在临时容器中完成全部校验，确认无冲突后一次性交换，避免半更新状态。
 */
class ReceiverAuthenticationContextStore final
{
public:
    void replaceAll(std::vector<ReceiverAuthenticationContext> vecContexts);

    ReceiverAuthenticationContextLookupResult resFind(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;

    std::size_t nSize() const;

private:
    using SenderChainKey = std::pair<std::string, std::uint64_t>;

    mutable std::mutex                                  m_mtxContexts;
    std::map<std::string, std::string>                  m_mapSenderIdByIpAddress;
    std::map<std::string, std::string>                  m_mapIpAddressBySenderId;
    std::map<SenderChainKey, ReceiverAuthenticationContext> m_mapContextBySenderChain;
};
}

#pragma once

#include "tesla/protocol/AuthenticationControlTypes.h"
#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/protocol/UdpAuthenticationPacketContext.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tesla::protocol
{
/** @brief 改进TESLA控制配置中的分组大小和检测门限。 */
class ImprovedTeslaControlParameters final
{
public:
    ImprovedTeslaControlParameters(
        std::uint32_t u32GroupSize,
        std::uint32_t u32DetectionThreshold
    );

    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;

private:
    std::uint32_t m_u32GroupSize;
    std::uint32_t m_u32DetectionThreshold;
};

/**
 * @brief CA、Sender和Receiver共享的一轮认证算法及调度参数。
 *
 * chainLength作为控制面校验值保留，NodeAgent会与本地公式重新计算的结果比较。
 */
class AuthenticationRoundControlParameters final
{
public:
    AuthenticationRoundControlParameters(
        AuthenticationCryptoAlgorithm algCryptoAlgorithm,
        UdpAuthenticationMode modeAuthentication,
        std::uint32_t u32TotalPacketCount,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32IntervalMilliseconds,
        std::uint64_t u64StartTimestampMilliseconds,
        std::uint32_t u32ChainLength,
        std::optional<ImprovedTeslaControlParameters> optImprovedParameters = std::nullopt
    );

    AuthenticationCryptoAlgorithm algCryptoAlgorithm() const noexcept;
    UdpAuthenticationMode modeAuthentication() const noexcept;
    std::uint32_t u32TotalPacketCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    std::uint64_t u64StartTimestampMilliseconds() const noexcept;
    std::uint32_t u32ChainLength() const noexcept;
    const std::optional<ImprovedTeslaControlParameters>&
        optImprovedParameters() const noexcept;

private:
    AuthenticationCryptoAlgorithm                  m_algCryptoAlgorithm;
    UdpAuthenticationMode                         m_modeAuthentication;
    std::uint32_t                                 m_u32TotalPacketCount;
    std::uint32_t                                 m_u32PacketsPerInterval;
    std::uint32_t                                 m_u32DisclosureDelay;
    std::uint32_t                                 m_u32IntervalMilliseconds;
    std::uint64_t                                 m_u64StartTimestampMilliseconds;
    std::uint32_t                                 m_u32ChainLength;
    std::optional<ImprovedTeslaControlParameters> m_optImprovedParameters;
};

/** @brief 只向Sender下发的配置详情，包含密钥链种子。 */
class SenderAuthenticationConfigControlDetails final
{
public:
    SenderAuthenticationConfigControlDetails(
        std::string strRequestId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        BinaryBlock arrChainSeed,
        BinaryBlock arrCommitmentKey,
        AuthenticationRoundControlParameters prmRoundParameters
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const BinaryBlock& arrChainSeed() const noexcept;
    const BinaryBlock& arrCommitmentKey() const noexcept;
    const AuthenticationRoundControlParameters& prmRoundParameters() const noexcept;

private:
    std::string                           m_strRequestId;
    std::string                           m_strSenderId;
    std::uint64_t                         m_u64ChainId;
    BinaryBlock                           m_arrChainSeed;
    BinaryBlock                           m_arrCommitmentKey;
    AuthenticationRoundControlParameters  m_prmRoundParameters;
};

/** @brief Receiver配置中的单个Sender公开上下文，不包含种子或完整密钥链。 */
class ReceiverAuthenticationContextControlDetails final
{
public:
    ReceiverAuthenticationContextControlDetails(
        std::string strSenderId,
        std::string strSenderIpAddress,
        std::uint64_t u64ChainId,
        BinaryBlock arrCommitmentKey,
        AuthenticationRoundControlParameters prmRoundParameters
    );

    const std::string& strSenderId() const noexcept;
    const std::string& strSenderIpAddress() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const BinaryBlock& arrCommitmentKey() const noexcept;
    const AuthenticationRoundControlParameters& prmRoundParameters() const noexcept;

private:
    std::string                           m_strSenderId;
    std::string                           m_strSenderIpAddress;
    std::uint64_t                         m_u64ChainId;
    BinaryBlock                           m_arrCommitmentKey;
    AuthenticationRoundControlParameters  m_prmRoundParameters;
};

/** @brief 一次性替换Receiver全部可信Sender上下文的控制消息。 */
class ReceiverAuthenticationContextsControlDetails final
{
public:
    ReceiverAuthenticationContextsControlDetails(
        std::string strRequestId,
        std::vector<ReceiverAuthenticationContextControlDetails> vecContexts
    );

    const std::string& strRequestId() const noexcept;
    const std::vector<ReceiverAuthenticationContextControlDetails>&
        vecContexts() const noexcept;

private:
    std::string                                               m_strRequestId;
    std::vector<ReceiverAuthenticationContextControlDetails>  m_vecContexts;
};

/** @brief NodeAgent对Sender或Receiver认证配置的明确接收结果。 */
class AuthenticationConfigAcknowledgementControlDetails final
{
public:
    AuthenticationConfigAcknowledgementControlDetails(
        std::string strRequestId,
        AuthenticationConfigTarget targetConfig,
        bool bAccepted,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    AuthenticationConfigTarget targetConfig() const noexcept;
    bool bAccepted() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string                 m_strRequestId;
    AuthenticationConfigTarget  m_targetConfig;
    bool                        m_bAccepted;
    std::string                 m_strErrorCode;
    std::string                 m_strMessage;
};
}

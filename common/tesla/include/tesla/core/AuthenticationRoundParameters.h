#pragma once

#include "tesla/core/ImprovedTeslaParameters.h"
#include "tesla/core/TeslaAuthenticationMode.h"
#include "tesla/crypto/CryptoAlgorithm.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace tesla::core
{
/**
 * @brief 保存CA、Sender和Receiver共同信任的一轮认证算法与时间参数。
 *
 * 密钥链长度由数据报文总数和每间隔发包数唯一计算，不允许调用方单独指定。
 */
class AuthenticationRoundParameters final
{
public:
    AuthenticationRoundParameters(
        crypto::CryptoAlgorithm algCryptoAlgorithm,
        TeslaAuthenticationMode modeAuthentication,
        std::uint32_t u32TotalPacketCount,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32IntervalMilliseconds,
        std::uint64_t u64StartTimestampMilliseconds,
        std::optional<ImprovedTeslaParameters> optImprovedParameters = std::nullopt
    );

    crypto::CryptoAlgorithm algCryptoAlgorithm() const noexcept;
    TeslaAuthenticationMode modeAuthentication() const noexcept;
    std::uint32_t u32TotalPacketCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    std::uint64_t u64StartTimestampMilliseconds() const noexcept;
    std::size_t nDataIntervalCount() const noexcept;
    std::uint32_t u32ChainLength() const noexcept;
    const std::optional<ImprovedTeslaParameters>& optImprovedParameters() const noexcept;

private:
    crypto::CryptoAlgorithm                 m_algCryptoAlgorithm;
    TeslaAuthenticationMode                 m_modeAuthentication;
    std::uint32_t                           m_u32TotalPacketCount;
    std::uint32_t                           m_u32PacketsPerInterval;
    std::uint32_t                           m_u32DisclosureDelay;
    std::uint32_t                           m_u32IntervalMilliseconds;
    std::uint64_t                           m_u64StartTimestampMilliseconds;
    std::size_t                             m_nDataIntervalCount;
    std::optional<ImprovedTeslaParameters>  m_optImprovedParameters;
};
}

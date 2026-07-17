#pragma once

#include "tesla/crypto/CryptoTypes.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace tesla::core
{
/** @brief 算法域使用的原生或改进TESLA模式。 */
enum class TeslaAuthenticationMode
{
    Native,
    Improved
};

enum class AuthenticationPayloadMode
{
    Text,
    File
};

/** @brief 保存改进TESLA分组和检测门限，并预先验证KS+RS矩阵可构造。 */
class ImprovedTeslaParameters final
{
public:
    ImprovedTeslaParameters(
        std::uint32_t u32GroupSize,
        std::uint32_t u32DetectionThreshold
    );

    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;
    std::size_t nTauCount() const noexcept;

private:
    std::uint32_t m_u32GroupSize;
    std::uint32_t m_u32DetectionThreshold;
    std::size_t   m_nTauCount;
};

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
        std::optional<ImprovedTeslaParameters> optImprovedParameters = std::nullopt,
        AuthenticationPayloadMode modePayload = AuthenticationPayloadMode::Text
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
    AuthenticationPayloadMode modePayload() const noexcept;
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
    AuthenticationPayloadMode              m_modePayload;
};
}

#include "tesla/core/AuthenticationRoundParameters.h"

#include "tesla/core/KsRsMatrix.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::core
{
ImprovedTeslaParameters::ImprovedTeslaParameters(
    std::uint32_t u32GroupSize,
    std::uint32_t u32DetectionThreshold
)
    : m_u32GroupSize(u32GroupSize),
      m_u32DetectionThreshold(u32DetectionThreshold),
      m_nTauCount(
          KsRsMatrix(
              static_cast<std::size_t>(u32GroupSize),
              static_cast<std::size_t>(u32DetectionThreshold)
          ).nRowCount()
      )
{
}

std::uint32_t ImprovedTeslaParameters::u32GroupSize() const noexcept
{
    return m_u32GroupSize;
}

std::uint32_t ImprovedTeslaParameters::u32DetectionThreshold() const noexcept
{
    return m_u32DetectionThreshold;
}

std::size_t ImprovedTeslaParameters::nTauCount() const noexcept
{
    return m_nTauCount;
}

AuthenticationRoundParameters::AuthenticationRoundParameters(
    crypto::CryptoAlgorithm algCryptoAlgorithm,
    TeslaAuthenticationMode modeAuthentication,
    std::uint32_t u32TotalPacketCount,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32DisclosureDelay,
    std::uint32_t u32IntervalMilliseconds,
    std::uint64_t u64StartTimestampMilliseconds,
    std::optional<ImprovedTeslaParameters> optImprovedParameters
)
    : m_algCryptoAlgorithm(algCryptoAlgorithm),
      m_modeAuthentication(modeAuthentication),
      m_u32TotalPacketCount(u32TotalPacketCount),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u32IntervalMilliseconds(u32IntervalMilliseconds),
      m_u64StartTimestampMilliseconds(u64StartTimestampMilliseconds),
      m_nDataIntervalCount(0),
      m_optImprovedParameters(std::move(optImprovedParameters))
{
    if (m_u32TotalPacketCount == 0 || m_u32PacketsPerInterval == 0)
    {
        throw std::invalid_argument("Authentication packet counts must be positive");
    }

    if (m_u32DisclosureDelay == 0 || m_u32IntervalMilliseconds == 0)
    {
        throw std::invalid_argument("Authentication timing parameters must be positive");
    }

    m_nDataIntervalCount =
        ((static_cast<std::size_t>(m_u32TotalPacketCount) - 1U)
            / m_u32PacketsPerInterval)
        + 1U;

    if (m_nDataIntervalCount >= std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("Authentication key-chain length exceeds uint32 range");
    }

    if (m_modeAuthentication == TeslaAuthenticationMode::Native)
    {
        if (m_optImprovedParameters.has_value())
        {
            throw std::invalid_argument("Native TESLA must not contain improved parameters");
        }

        return;
    }

    if (!m_optImprovedParameters.has_value())
    {
        throw std::invalid_argument("Improved TESLA requires grouping parameters");
    }

    if (m_u32PacketsPerInterval % m_optImprovedParameters->u32GroupSize() != 0)
    {
        throw std::invalid_argument(
            "Packets per interval must be divisible by improved group size"
        );
    }
}

crypto::CryptoAlgorithm AuthenticationRoundParameters::algCryptoAlgorithm() const noexcept
{
    return m_algCryptoAlgorithm;
}

TeslaAuthenticationMode AuthenticationRoundParameters::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

std::uint32_t AuthenticationRoundParameters::u32TotalPacketCount() const noexcept
{
    return m_u32TotalPacketCount;
}

std::uint32_t AuthenticationRoundParameters::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t AuthenticationRoundParameters::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint32_t AuthenticationRoundParameters::u32IntervalMilliseconds() const noexcept
{
    return m_u32IntervalMilliseconds;
}

std::uint64_t AuthenticationRoundParameters::u64StartTimestampMilliseconds() const noexcept
{
    return m_u64StartTimestampMilliseconds;
}

std::size_t AuthenticationRoundParameters::nDataIntervalCount() const noexcept
{
    return m_nDataIntervalCount;
}

std::uint32_t AuthenticationRoundParameters::u32ChainLength() const noexcept
{
    return static_cast<std::uint32_t>(m_nDataIntervalCount + 1U);
}

const std::optional<ImprovedTeslaParameters>&
AuthenticationRoundParameters::optImprovedParameters() const noexcept
{
    return m_optImprovedParameters;
}
}

#include "tesla/protocol/UdpAuthenticationPacketContext.h"

#include <limits>
#include <stdexcept>

namespace tesla::protocol
{
UdpAuthenticationPacketContext::UdpAuthenticationPacketContext(
    UdpAuthenticationMode modeAuthentication,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32DisclosureDelay,
    std::uint32_t u32TotalPacketCount,
    std::uint32_t u32GroupSize,
    std::size_t nTauCount
)
    : m_modeAuthentication(modeAuthentication),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u32TotalPacketCount(u32TotalPacketCount),
      m_u32GroupSize(u32GroupSize),
      m_nTauCount(nTauCount)
{
    if (m_u32PacketsPerInterval == 0 || m_u32TotalPacketCount == 0)
    {
        throw std::invalid_argument("UDP context packet counts must be positive");
    }

    if (m_u32DisclosureDelay == 0)
    {
        throw std::invalid_argument("TESLA disclosure delay must be positive");
    }

    const std::uint32_t u32FinalInterval =
        ((m_u32TotalPacketCount - 1U) / m_u32PacketsPerInterval) + 1U;
    if (m_u32DisclosureDelay
        > std::numeric_limits<std::uint32_t>::max() - u32FinalInterval)
    {
        throw std::invalid_argument("Disclosure schedule exceeds the interval index range");
    }

    if (m_modeAuthentication == UdpAuthenticationMode::Native)
    {
        if (m_u32GroupSize != 0 || m_nTauCount != 0)
        {
            throw std::invalid_argument("Native UDP context must not define improved-mode fields");
        }

        return;
    }

    if (m_u32GroupSize == 0 || m_nTauCount == 0)
    {
        throw std::invalid_argument("Improved UDP context requires group size and tau count");
    }

    if (m_u32PacketsPerInterval % m_u32GroupSize != 0)
    {
        throw std::invalid_argument("Packets per interval must be divisible by group size");
    }

    // 即使组末首包同时携带Key，最大合法UDP载荷也必须保持在65507字节以内。
    constexpr std::size_t MAX_SAFE_TAU_COUNT = 2043;
    if (m_nTauCount > MAX_SAFE_TAU_COUNT)
    {
        throw std::invalid_argument("Tau count exceeds the protocol safety limit");
    }

}

UdpAuthenticationMode UdpAuthenticationPacketContext::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

std::uint32_t UdpAuthenticationPacketContext::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t UdpAuthenticationPacketContext::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint32_t UdpAuthenticationPacketContext::u32TotalPacketCount() const noexcept
{
    return m_u32TotalPacketCount;
}

std::uint32_t UdpAuthenticationPacketContext::u32GroupSize() const noexcept
{
    return m_u32GroupSize;
}

std::size_t UdpAuthenticationPacketContext::nTauCount() const noexcept
{
    return m_nTauCount;
}

std::uint32_t UdpAuthenticationPacketContext::u32ExpectedInterval(
    std::uint32_t u32PacketIndex
) const
{
    if (u32PacketIndex == 0 || u32PacketIndex > m_u32TotalPacketCount)
    {
        throw std::out_of_range("Data packet index is outside the configured round");
    }

    return ((u32PacketIndex - 1U) / m_u32PacketsPerInterval) + 1U;
}

bool UdpAuthenticationPacketContext::bPacketCarriesDisclosedKey(
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex
) const noexcept
{
    return u32PacketIndex > 0
        && u32IntervalIndex > m_u32DisclosureDelay
        && ((u32PacketIndex - 1U) % m_u32PacketsPerInterval == 0);
}

bool UdpAuthenticationPacketContext::bIsImprovedGroupEnd(
    std::uint32_t u32PacketIndex
) const noexcept
{
    if (m_modeAuthentication != UdpAuthenticationMode::Improved || u32PacketIndex == 0)
    {
        return false;
    }

    return u32PacketIndex % m_u32GroupSize == 0
        || u32PacketIndex == m_u32TotalPacketCount;
}
}

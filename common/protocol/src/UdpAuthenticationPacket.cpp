#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
UdpAuthenticationPacketHeader::UdpAuthenticationPacketHeader(
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex
)
    : m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex)
{
    if (m_u64ChainId == 0 || m_u32IntervalIndex == 0)
    {
        throw std::invalid_argument("UDP authentication header identity is invalid");
    }
}

std::uint64_t UdpAuthenticationPacketHeader::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t UdpAuthenticationPacketHeader::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

std::uint32_t UdpAuthenticationPacketHeader::u32PacketIndex() const noexcept
{
    return m_u32PacketIndex;
}

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
            throw std::invalid_argument(
                "Native UDP context must not define improved-mode fields"
            );
        }

        return;
    }

    if (m_u32GroupSize == 0 || m_nTauCount == 0)
    {
        throw std::invalid_argument(
            "Improved UDP context requires group size and tau count"
        );
    }

    if (m_u32PacketsPerInterval % m_u32GroupSize != 0)
    {
        throw std::invalid_argument(
            "Packets per interval must be divisible by group size"
        );
    }

    constexpr std::size_t MAX_SAFE_TAU_COUNT = 2043;
    if (m_nTauCount > MAX_SAFE_TAU_COUNT)
    {
        throw std::invalid_argument("Tau count exceeds the protocol safety limit");
    }
}

UdpAuthenticationMode
UdpAuthenticationPacketContext::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

std::uint32_t
UdpAuthenticationPacketContext::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t
UdpAuthenticationPacketContext::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint32_t
UdpAuthenticationPacketContext::u32TotalPacketCount() const noexcept
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
    if (m_modeAuthentication != UdpAuthenticationMode::Improved
        || u32PacketIndex == 0)
    {
        return false;
    }

    return u32PacketIndex % m_u32GroupSize == 0
        || u32PacketIndex == m_u32TotalPacketCount;
}

NativeUdpAuthenticationDetails::NativeUdpAuthenticationDetails(BinaryBlock arrPacketMac)
    : m_arrPacketMac(arrPacketMac)
{
}

const BinaryBlock& NativeUdpAuthenticationDetails::arrPacketMac() const noexcept
{
    return m_arrPacketMac;
}

ImprovedUdpGroupAuthenticationDetails::ImprovedUdpGroupAuthenticationDetails(
    std::vector<BinaryBlock> vecSamdTau,
    BinaryBlock arrFastGroupTag
)
    : m_vecSamdTau(std::move(vecSamdTau)),
      m_arrFastGroupTag(arrFastGroupTag)
{
    // 空τ集合无法表达有效改进模式组末详情，必须在对象进入Codec前拒绝。
    if (m_vecSamdTau.empty())
    {
        throw std::invalid_argument("Improved UDP group details require at least one tau");
    }
}

const std::vector<BinaryBlock>&
ImprovedUdpGroupAuthenticationDetails::vecSamdTau() const noexcept
{
    return m_vecSamdTau;
}

const BinaryBlock& ImprovedUdpGroupAuthenticationDetails::arrFastGroupTag() const noexcept
{
    return m_arrFastGroupTag;
}

ImprovedUdpAuthenticationDetails::ImprovedUdpAuthenticationDetails(
    std::optional<ImprovedUdpGroupAuthenticationDetails> optGroupDetails
)
    : m_optGroupDetails(std::move(optGroupDetails))
{
}

const std::optional<ImprovedUdpGroupAuthenticationDetails>&
ImprovedUdpAuthenticationDetails::optGroupDetails() const noexcept
{
    return m_optGroupDetails;
}

UdpDataPacket::UdpDataPacket(
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex,
    BinaryBlock arrMessage,
    std::optional<BinaryBlock> optDisclosedKey,
    UdpDataAuthenticationDetails varAuthenticationDetails
)
    : m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex),
      m_arrMessage(arrMessage),
      m_optDisclosedKey(std::move(optDisclosedKey)),
      m_varAuthenticationDetails(std::move(varAuthenticationDetails))
{
    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("UDP data packet chain ID must not be zero");
    }

    if (m_u32IntervalIndex == 0 || m_u32PacketIndex == 0)
    {
        throw std::invalid_argument("UDP data packet indexes must start at one");
    }
}

std::uint64_t UdpDataPacket::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t UdpDataPacket::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

std::uint32_t UdpDataPacket::u32PacketIndex() const noexcept
{
    return m_u32PacketIndex;
}

const BinaryBlock& UdpDataPacket::arrMessage() const noexcept
{
    return m_arrMessage;
}

const std::optional<BinaryBlock>& UdpDataPacket::optDisclosedKey() const noexcept
{
    return m_optDisclosedKey;
}

const UdpDataAuthenticationDetails& UdpDataPacket::varAuthenticationDetails() const noexcept
{
    return m_varAuthenticationDetails;
}

UdpDisclosurePacket::UdpDisclosurePacket(
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    BinaryBlock arrDisclosedKey
)
    : m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_arrDisclosedKey(arrDisclosedKey)
{
    if (m_u64ChainId == 0 || m_u32IntervalIndex == 0)
    {
        throw std::invalid_argument("UDP disclosure packet requires non-zero chain and interval");
    }
}

std::uint64_t UdpDisclosurePacket::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t UdpDisclosurePacket::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

const BinaryBlock& UdpDisclosurePacket::arrDisclosedKey() const noexcept
{
    return m_arrDisclosedKey;
}

UdpAuthenticationPacket::UdpAuthenticationPacket(UdpAuthenticationPacketDetails varDetails)
    : m_varDetails(std::move(varDetails))
{
}

bool UdpAuthenticationPacket::bIsDataPacket() const noexcept
{
    return std::holds_alternative<UdpDataPacket>(m_varDetails);
}

const UdpAuthenticationPacketDetails& UdpAuthenticationPacket::varDetails() const noexcept
{
    return m_varDetails;
}
}

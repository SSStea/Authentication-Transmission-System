#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
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

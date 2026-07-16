#include "tesla/core/AuthenticationGroupInput.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::core
{
AuthenticationGroupInput::AuthenticationGroupInput(
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32GroupIndex,
    std::uint32_t u32FirstPacketIndex,
    std::vector<PacketSlot> vecPacketSlots
)
    : m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32GroupIndex(u32GroupIndex),
      m_u32FirstPacketIndex(u32FirstPacketIndex),
      m_vecPacketSlots(std::move(vecPacketSlots))
{
    if (m_strSenderId.empty())
    {
        throw std::invalid_argument("Group Sender ID must not be empty");
    }

    if (m_strSenderId.size() > std::numeric_limits<std::uint16_t>::max())
    {
        throw std::invalid_argument("Group Sender ID is too long");
    }

    if (m_u32IntervalIndex == 0 || m_u32GroupIndex == 0 || m_u32FirstPacketIndex == 0)
    {
        throw std::invalid_argument("Group and packet indexes must start at one");
    }

    if (m_vecPacketSlots.empty())
    {
        throw std::invalid_argument("Authentication group must contain packet slots");
    }

    if (m_vecPacketSlots.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("Authentication group is too large");
    }

    validatePacketSlots();
}

bool AuthenticationGroupInput::bHasMissingPackets() const noexcept
{
    for (const PacketSlot& optPacket : m_vecPacketSlots)
    {
        if (!optPacket.has_value())
        {
            return true;
        }
    }

    return false;
}

std::size_t AuthenticationGroupInput::nPacketSlotCount() const noexcept
{
    return m_vecPacketSlots.size();
}

const std::string& AuthenticationGroupInput::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t AuthenticationGroupInput::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t AuthenticationGroupInput::u32FirstPacketIndex() const noexcept
{
    return m_u32FirstPacketIndex;
}

std::uint32_t AuthenticationGroupInput::u32GroupIndex() const noexcept
{
    return m_u32GroupIndex;
}

std::uint32_t AuthenticationGroupInput::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

const std::vector<AuthenticationGroupInput::PacketSlot>&
AuthenticationGroupInput::vecPacketSlots() const noexcept
{
    return m_vecPacketSlots;
}

void AuthenticationGroupInput::validatePacketSlots() const
{
    // 只校验实际收到的报文；空槽位必须保留，供后续算法准确识别丢包位置。
    for (std::size_t nPosition = 0; nPosition < m_vecPacketSlots.size(); ++nPosition)
    {
        const PacketSlot& optPacket = m_vecPacketSlots[nPosition];

        if (!optPacket.has_value())
        {
            continue;
        }

        const AuthenticationPacketInput& pktCurrent = optPacket.value();

        // 组内实际报文必须来自同一个可信认证上下文。
        if (
            pktCurrent.strSenderId() != m_strSenderId
            || pktCurrent.u64ChainId() != m_u64ChainId
            || pktCurrent.u32IntervalIndex() != m_u32IntervalIndex
        )
        {
            throw std::invalid_argument("All group packets must share one authentication context");
        }

        // 槽位位置决定期望报文索引，禁止丢包后把剩余报文向前压缩。
        const std::uint64_t u64ExpectedPacketIndex =
            static_cast<std::uint64_t>(m_u32FirstPacketIndex) + nPosition;

        if (
            u64ExpectedPacketIndex > std::numeric_limits<std::uint32_t>::max()
            || pktCurrent.u32PacketIndex() != u64ExpectedPacketIndex
        )
        {
            throw std::invalid_argument("Packet index does not match its fixed group slot");
        }
    }
}
}

#include "tesla/core/AuthenticationPacketInput.h"

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::core
{
AuthenticationPacketInput::AuthenticationPacketInput(
    std::string strSenderId,
    std::uint64_t u64ChainId,
    std::uint32_t u32IntervalIndex,
    std::uint32_t u32PacketIndex,
    Message arrMessage
)
    : m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_u32IntervalIndex(u32IntervalIndex),
      m_u32PacketIndex(u32PacketIndex),
      m_arrMessage(arrMessage)
{
    // 在对象创建阶段锁定算法域约束，后续编码器可直接按合法字段编码。
    if (m_strSenderId.empty())
    {
        throw std::invalid_argument("Sender ID must not be empty");
    }

    if (m_strSenderId.size() > std::numeric_limits<std::uint16_t>::max())
    {
        throw std::invalid_argument("Sender ID is too long");
    }

    if (m_u32IntervalIndex == 0 || m_u32PacketIndex == 0)
    {
        throw std::invalid_argument("Interval and packet indexes must start at one");
    }
}

const std::string& AuthenticationPacketInput::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t AuthenticationPacketInput::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t AuthenticationPacketInput::u32IntervalIndex() const noexcept
{
    return m_u32IntervalIndex;
}

std::uint32_t AuthenticationPacketInput::u32PacketIndex() const noexcept
{
    return m_u32PacketIndex;
}

const AuthenticationPacketInput::Message& AuthenticationPacketInput::arrMessage() const noexcept
{
    return m_arrMessage;
}
}

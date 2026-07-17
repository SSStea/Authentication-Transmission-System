#include "tesla/workload/FileWorkload.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tesla::workload
{
namespace
{
std::uint32_t u32PacketCountFor(std::uint64_t u64ByteCount)
{
    if (u64ByteCount == 0)
    {
        throw std::invalid_argument("File workload must not be empty");
    }

    if (u64ByteCount > FileWorkload::MAXIMUM_FILE_SIZE)
    {
        throw std::invalid_argument("File workload exceeds the bounded file size");
    }

    return static_cast<std::uint32_t>(
        (u64ByteCount + FileWorkload::MESSAGE_SIZE - 1U)
        / FileWorkload::MESSAGE_SIZE
    );
}
}

FileWorkload::FileWorkload(std::vector<std::uint8_t> vecFileBytes)
    : m_vecFileBytes(std::move(vecFileBytes)),
      m_u32PacketCount(u32PacketCountFor(m_vecFileBytes.size()))
{
}

std::uint64_t FileWorkload::u64OriginalByteCount() const noexcept
{
    return static_cast<std::uint64_t>(m_vecFileBytes.size());
}

std::uint32_t FileWorkload::u32PacketCount() const noexcept
{
    return m_u32PacketCount;
}

FileWorkload::Message FileWorkload::arrMessage(
    std::uint32_t u32PacketIndex
) const
{
    if (u32PacketIndex == 0 || u32PacketIndex > m_u32PacketCount)
    {
        throw std::out_of_range("File workload packet index is outside the file");
    }

    Message arrResult{};
    const std::size_t nOffset = static_cast<std::size_t>(
        u32PacketIndex - 1U
    ) * MESSAGE_SIZE;
    const std::size_t nCopySize = std::min(
        MESSAGE_SIZE,
        m_vecFileBytes.size() - nOffset
    );
    std::copy_n(
        m_vecFileBytes.begin() + static_cast<std::ptrdiff_t>(nOffset),
        nCopySize,
        arrResult.begin()
    );
    return arrResult;
}

const std::vector<std::uint8_t>& FileWorkload::vecFileBytes() const noexcept
{
    return m_vecFileBytes;
}

std::vector<std::uint8_t> FileWorkload::vecRecover(
    const std::vector<Message>& vecMessages,
    std::uint64_t u64OriginalByteCount
)
{
    const std::uint32_t u32ExpectedPacketCount = u32PacketCountFor(
        u64OriginalByteCount
    );
    if (vecMessages.size() != u32ExpectedPacketCount)
    {
        throw std::invalid_argument(
            "Recovered file message count does not match the original size"
        );
    }

    std::vector<std::uint8_t> vecRecovered;
    vecRecovered.reserve(vecMessages.size() * MESSAGE_SIZE);
    for (const Message& arrMessage : vecMessages)
    {
        vecRecovered.insert(
            vecRecovered.end(),
            arrMessage.begin(),
            arrMessage.end()
        );
    }

    vecRecovered.resize(static_cast<std::size_t>(u64OriginalByteCount));
    return vecRecovered;
}
}

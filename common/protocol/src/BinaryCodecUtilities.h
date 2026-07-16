#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace tesla::protocol::detail
{
// 所有整数按网络字节序逐字节写入，禁止直接复制本机结构体内存。
inline void appendUint32(ByteBuffer& vecOutput, std::uint32_t u32Value)
{
    vecOutput.push_back(static_cast<std::uint8_t>((u32Value >> 24U) & 0xFFU));
    vecOutput.push_back(static_cast<std::uint8_t>((u32Value >> 16U) & 0xFFU));
    vecOutput.push_back(static_cast<std::uint8_t>((u32Value >> 8U) & 0xFFU));
    vecOutput.push_back(static_cast<std::uint8_t>(u32Value & 0xFFU));
}

inline void appendUint64(ByteBuffer& vecOutput, std::uint64_t u64Value)
{
    for (int nShift = 56; nShift >= 0; nShift -= 8)
    {
        vecOutput.push_back(static_cast<std::uint8_t>((u64Value >> nShift) & 0xFFU));
    }
}

inline void appendBytes(ByteBuffer& vecOutput, const std::uint8_t* pData, std::size_t nSize)
{
    vecOutput.insert(vecOutput.end(), pData, pData + nSize);
}

class BinaryReader final
{
public:
    explicit BinaryReader(const ByteBuffer& vecInput)
        : m_vecInput(vecInput)
    {
    }

    std::size_t nRemaining() const noexcept
    {
        return m_vecInput.size() - m_nOffset;
    }

    std::uint32_t u32Read()
    {
        ensureAvailable(sizeof(std::uint32_t));

        std::uint32_t u32Value = 0;
        for (std::size_t nIndex = 0; nIndex < sizeof(std::uint32_t); ++nIndex)
        {
            u32Value = static_cast<std::uint32_t>(
                (u32Value << 8U) | m_vecInput[m_nOffset + nIndex]
            );
        }

        m_nOffset += sizeof(std::uint32_t);
        return u32Value;
    }

    std::uint64_t u64Read()
    {
        ensureAvailable(sizeof(std::uint64_t));

        std::uint64_t u64Value = 0;
        for (std::size_t nIndex = 0; nIndex < sizeof(std::uint64_t); ++nIndex)
        {
            u64Value = (u64Value << 8U) | m_vecInput[m_nOffset + nIndex];
        }

        m_nOffset += sizeof(std::uint64_t);
        return u64Value;
    }

    template<std::size_t N>
    std::array<std::uint8_t, N> arrRead()
    {
        ensureAvailable(N);

        std::array<std::uint8_t, N> arrValue{};
        std::copy_n(m_vecInput.begin() + static_cast<std::ptrdiff_t>(m_nOffset), N, arrValue.begin());
        m_nOffset += N;
        return arrValue;
    }

    ByteBuffer vecRead(std::size_t nSize)
    {
        ensureAvailable(nSize);

        ByteBuffer vecValue(
            m_vecInput.begin() + static_cast<std::ptrdiff_t>(m_nOffset),
            m_vecInput.begin() + static_cast<std::ptrdiff_t>(m_nOffset + nSize)
        );
        m_nOffset += nSize;
        return vecValue;
    }

private:
    void ensureAvailable(std::size_t nSize) const
    {
        if (nSize > nRemaining())
        {
            throw std::out_of_range("Binary input is shorter than the requested field");
        }
    }

    const ByteBuffer& m_vecInput;
    std::size_t       m_nOffset = 0;
};
}

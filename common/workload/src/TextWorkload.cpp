#include "tesla/workload/TextWorkload.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tesla::workload
{
namespace
{
bool bIsContinuationByte(std::uint8_t u8Value)
{
    return (u8Value & 0xC0U) == 0x80U;
}

void validateUtf8(const std::string& strText)
{
    std::size_t nIndex = 0;

    while (nIndex < strText.size())
    {
        const std::uint8_t u8Lead = static_cast<std::uint8_t>(strText[nIndex]);

        if (u8Lead <= 0x7FU)
        {
            ++nIndex;
            continue;
        }

        std::size_t   nSequenceLength = 0;
        std::uint32_t u32CodePoint = 0;
        std::uint32_t u32MinimumCodePoint = 0;

        if ((u8Lead & 0xE0U) == 0xC0U)
        {
            nSequenceLength = 2;
            u32CodePoint = u8Lead & 0x1FU;
            u32MinimumCodePoint = 0x80U;
        }
        else if ((u8Lead & 0xF0U) == 0xE0U)
        {
            nSequenceLength = 3;
            u32CodePoint = u8Lead & 0x0FU;
            u32MinimumCodePoint = 0x800U;
        }
        else if ((u8Lead & 0xF8U) == 0xF0U)
        {
            nSequenceLength = 4;
            u32CodePoint = u8Lead & 0x07U;
            u32MinimumCodePoint = 0x10000U;
        }
        else
        {
            throw std::invalid_argument("Text payload is not valid UTF-8");
        }

        if (nIndex + nSequenceLength > strText.size())
        {
            throw std::invalid_argument("Text payload ends inside a UTF-8 sequence");
        }

        for (std::size_t nOffset = 1; nOffset < nSequenceLength; ++nOffset)
        {
            const std::uint8_t u8Continuation = static_cast<std::uint8_t>(
                strText[nIndex + nOffset]
            );
            if (!bIsContinuationByte(u8Continuation))
            {
                throw std::invalid_argument("Text payload has an invalid UTF-8 continuation byte");
            }

            u32CodePoint = (u32CodePoint << 6U) | (u8Continuation & 0x3FU);
        }

        if (u32CodePoint < u32MinimumCodePoint
            || u32CodePoint > 0x10FFFFU
            || (u32CodePoint >= 0xD800U && u32CodePoint <= 0xDFFFU))
        {
            throw std::invalid_argument("Text payload contains an invalid UTF-8 code point");
        }

        nIndex += nSequenceLength;
    }
}
}

TextPayload::TextPayload(std::string strUtf8Text)
    : m_strUtf8Text(std::move(strUtf8Text)),
      m_arrMessage{}
{
    if (m_strUtf8Text.empty() || m_strUtf8Text.size() > MESSAGE_SIZE)
    {
        throw std::invalid_argument("Text payload must contain between 1 and 32 UTF-8 bytes");
    }

    if (m_strUtf8Text.find('\0') != std::string::npos)
    {
        throw std::invalid_argument("Manual text payload must not contain a zero byte");
    }

    validateUtf8(m_strUtf8Text);

    // Message始终固定为32B，短文本的剩余字节保持零填充并参与MAC计算。
    std::copy(
        m_strUtf8Text.begin(),
        m_strUtf8Text.end(),
        m_arrMessage.begin()
    );
}

const std::string& TextPayload::strUtf8Text() const noexcept
{
    return m_strUtf8Text;
}

const TextPayload::Message& TextPayload::arrMessage() const noexcept
{
    return m_arrMessage;
}

TextWorkload::TextWorkload(
    TextPayload pldPayload,
    std::uint32_t u32PacketCount
)
    : m_pldPayload(std::move(pldPayload)),
      m_u32PacketCount(u32PacketCount)
{
    if (m_u32PacketCount == 0)
    {
        throw std::invalid_argument("Text workload packet count must be positive");
    }
}

const TextPayload& TextWorkload::pldPayload() const noexcept
{
    return m_pldPayload;
}

std::uint32_t TextWorkload::u32PacketCount() const noexcept
{
    return m_u32PacketCount;
}

const TextPayload::Message& TextWorkload::arrMessage(
    std::uint32_t u32PacketIndex
) const
{
    if (u32PacketIndex == 0 || u32PacketIndex > m_u32PacketCount)
    {
        throw std::out_of_range("Text workload packet index is outside the round");
    }

    return m_pldPayload.arrMessage();
}
}

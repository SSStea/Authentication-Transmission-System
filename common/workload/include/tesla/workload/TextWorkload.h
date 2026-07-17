#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace tesla::workload
{
/**
 * @brief 保存经过UTF-8校验并补零到固定32B的手动文本载荷。
 *
 * 原始文本和固定Message具有相同生命周期，因此放在同一不可变值对象中。
 */
class TextPayload final
{
public:
    static constexpr std::size_t MESSAGE_SIZE = 32;
    using Message = std::array<std::uint8_t, MESSAGE_SIZE>;

    explicit TextPayload(std::string strUtf8Text);

    const std::string& strUtf8Text() const noexcept;
    const Message& arrMessage() const noexcept;

private:
    std::string m_strUtf8Text;
    Message     m_arrMessage;
};

/** @brief 表示把同一条固定文本重复发送指定次数的阶段6工作负载。 */
class TextWorkload final
{
public:
    TextWorkload(TextPayload pldPayload, std::uint32_t u32PacketCount);

    const TextPayload& pldPayload() const noexcept;
    std::uint32_t u32PacketCount() const noexcept;
    const TextPayload::Message& arrMessage(std::uint32_t u32PacketIndex) const;

private:
    TextPayload   m_pldPayload;
    std::uint32_t m_u32PacketCount;
};
}

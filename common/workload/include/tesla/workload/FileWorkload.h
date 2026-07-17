#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tesla::workload
{
/**
 * @brief 保存一份已完整接收的文件，并按固定32字节生成TESLA Message。
 *
 * TCP上传分块不会进入本类型；只有上传结束且长度校验成功后的原始文件字节
 * 才能构造文件工作负载，从而保持管理传输分块与认证数据分片的边界。
 */
class FileWorkload final
{
public:
    static constexpr std::size_t MESSAGE_SIZE = 32U;
    static constexpr std::uint32_t MAXIMUM_PACKET_COUNT = 200000U;
    static constexpr std::size_t MAXIMUM_FILE_SIZE =
        MESSAGE_SIZE * MAXIMUM_PACKET_COUNT;

    using Message = std::array<std::uint8_t, MESSAGE_SIZE>;

    explicit FileWorkload(std::vector<std::uint8_t> vecFileBytes);

    std::uint64_t u64OriginalByteCount() const noexcept;
    std::uint32_t u32PacketCount() const noexcept;
    Message arrMessage(std::uint32_t u32PacketIndex) const;
    const std::vector<std::uint8_t>& vecFileBytes() const noexcept;

    static std::vector<std::uint8_t> vecRecover(
        const std::vector<Message>& vecMessages,
        std::uint64_t u64OriginalByteCount
    );

private:
    std::vector<std::uint8_t> m_vecFileBytes;
    std::uint32_t             m_u32PacketCount;
};
}

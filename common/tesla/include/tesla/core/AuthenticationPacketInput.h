#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace tesla::core
{
/**
 * @brief 表示计算单个认证报文MAC所需的逻辑输入。
 *
 * 本类型属于密码算法域，不表示也不序列化阶段3的UDP报文。
 */
class AuthenticationPacketInput final
{
public:
    /// 算法规定的消息字段固定长度。
    static constexpr std::size_t MESSAGE_SIZE = 32;

    /// 单个认证报文参与MAC计算的固定长度消息。
    using Message = std::array<std::uint8_t, MESSAGE_SIZE>;

    /**
     * @brief 创建一个经过基本约束检查的单包算法输入。
     * @param strSenderId 非空发送者标识，长度不得超过uint16可编码范围。
     * @param u64ChainId 密钥链标识。
     * @param u32IntervalIndex 从1开始的TESLA间隔索引。
     * @param u32PacketIndex 从1开始的报文索引。
     * @param arrMessage 参与认证的32字节消息。
     * @throws std::invalid_argument 发送者标识或索引不满足约束时抛出。
     */
    AuthenticationPacketInput(
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex,
        Message arrMessage
    );

    /** @return 发送者标识的只读引用。 */
    const std::string& strSenderId() const noexcept;

    /** @return 密钥链标识。 */
    std::uint64_t u64ChainId() const noexcept;

    /** @return 从1开始的TESLA间隔索引。 */
    std::uint32_t u32IntervalIndex() const noexcept;

    /** @return 从1开始的报文索引。 */
    std::uint32_t u32PacketIndex() const noexcept;

    /** @return 32字节消息的只读引用。 */
    const Message& arrMessage() const noexcept;

private:
    std::string   m_strSenderId;
    std::uint64_t m_u64ChainId;
    std::uint32_t m_u32IntervalIndex;
    std::uint32_t m_u32PacketIndex;
    Message       m_arrMessage;
};
}

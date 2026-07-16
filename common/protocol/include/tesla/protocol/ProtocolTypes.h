#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tesla::protocol
{
/// 协议编解码统一使用的任意长度字节缓冲区。
using ByteBuffer = std::vector<std::uint8_t>;

/// TESLA Message、Key、MAC和标签共同使用的固定32字节二进制块。
constexpr std::size_t BINARY_BLOCK_SIZE = 32;
using BinaryBlock = std::array<std::uint8_t, BINARY_BLOCK_SIZE>;

/** @brief 协议输入在进入业务或密码计算前可能产生的结构化错误类型。 */
enum class ProtocolDecodeErrorCode
{
    InvalidFrameLength,
    FrameTooLarge,
    UnsupportedFrameType,
    InvalidJsonPayload,
    InvalidFileChunk,
    InvalidControlMessage,
    InvalidDiscoveryMessage,
    DatagramTooShort,
    DatagramLengthMismatch,
    InvalidAuthenticationContext,
    InvalidPacketIndex,
    InvalidIntervalIndex,
    InvalidAuthenticationFields
};

/** @brief 保存可记录但不含敏感原始载荷的协议解析失败信息。 */
class ProtocolDecodeError final
{
public:
    ProtocolDecodeError(
        ProtocolDecodeErrorCode errCode,
        std::string strMessage
    );

    ProtocolDecodeErrorCode errCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    ProtocolDecodeErrorCode m_errCode;
    std::string             m_strMessage;
};
}

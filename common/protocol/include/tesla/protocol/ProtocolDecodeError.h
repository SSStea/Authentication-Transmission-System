#pragma once

#include <string>

namespace tesla::protocol
{
/**
 * @brief 协议输入在进入业务或密码计算前可能产生的结构化错误类型。
 */
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

/**
 * @brief 保存可记录但不含敏感原始载荷的协议解析失败信息。
 */
class ProtocolDecodeError final
{
public:
    ProtocolDecodeError(ProtocolDecodeErrorCode errCode, std::string strMessage);

    ProtocolDecodeErrorCode errCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    ProtocolDecodeErrorCode m_errCode;
    std::string             m_strMessage;
};
}

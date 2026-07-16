#pragma once

#include "tesla/protocol/ProtocolDecodeError.h"
#include "tesla/protocol/TcpFrame.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace tesla::protocol
{
/** @brief 一次流输入后解析出的完整帧以及可选的致命协议错误。 */
class TcpFrameStreamDecodeBatch final
{
public:
    TcpFrameStreamDecodeBatch(
        std::vector<TcpFrame> vecFrames,
        std::optional<ProtocolDecodeError> optError
    );

    const std::vector<TcpFrame>& vecFrames() const noexcept;
    const std::optional<ProtocolDecodeError>& optError() const noexcept;

private:
    std::vector<TcpFrame>              m_vecFrames;
    std::optional<ProtocolDecodeError> m_optError;
};

/**
 * @brief 将任意分片或粘连的TCP字节流恢复为完整帧。
 *
 * 一旦遇到非法长度或载荷，本解码器清空缓存并返回错误，调用方应关闭该连接，
 * 避免在已经失去边界同步后继续解释不可信字节。
 */
class TcpFrameStreamDecoder final
{
public:
    explicit TcpFrameStreamDecoder(std::size_t nMaximumFrameLength = 16U * 1024U * 1024U);

    TcpFrameStreamDecodeBatch batConsume(const ByteBuffer& vecBytes);
    void reset() noexcept;

private:
    std::size_t m_nMaximumFrameLength;
    ByteBuffer  m_vecPendingBytes;
};
}

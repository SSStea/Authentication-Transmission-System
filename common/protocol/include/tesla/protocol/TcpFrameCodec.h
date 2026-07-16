#pragma once

#include "tesla/protocol/ProtocolDecodeError.h"
#include "tesla/protocol/TcpFrame.h"

#include <variant>

namespace tesla::protocol
{
using TcpFrameDecodeResult = std::variant<TcpFrame, ProtocolDecodeError>;

/** @brief 对一整个TCP长度前缀帧逐字段编解码，不处理流分段。 */
class TcpFrameCodec final
{
public:
    static constexpr std::size_t LENGTH_PREFIX_SIZE = 4;
    static constexpr std::size_t TYPE_SIZE = 1;

    static ByteBuffer vecEncode(const TcpFrame& frmFrame);
    static TcpFrameDecodeResult resDecode(const ByteBuffer& vecFrameBytes);

private:
    TcpFrameCodec() = delete;
};
}

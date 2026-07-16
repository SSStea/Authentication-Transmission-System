#pragma once

#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <variant>

namespace tesla::protocol
{
using UdpAuthenticationPacketDecodeResult = std::variant<
    UdpAuthenticationPacket,
    ProtocolDecodeError
>;

/**
 * @brief 实现第14章固定UDP认证报文的逐字段网络字节序编解码。
 *
 * 本Codec不调用算法输入编码器；条件字段仅由可信的TCP上下文推导。
 */
class UdpAuthenticationPacketCodec final
{
public:
    static constexpr std::size_t FIXED_HEADER_SIZE = 16;
    static constexpr std::size_t DATA_PREFIX_SIZE = FIXED_HEADER_SIZE + BINARY_BLOCK_SIZE;
    static constexpr std::size_t DISCLOSURE_PACKET_SIZE = FIXED_HEADER_SIZE + BINARY_BLOCK_SIZE;

    static ByteBuffer vecEncode(
        const UdpAuthenticationPacket& udpPacket,
        const UdpAuthenticationPacketContext& ctxContext
    );

    static UdpAuthenticationPacketDecodeResult resDecode(
        const ByteBuffer& vecDatagram,
        const UdpAuthenticationPacketContext& ctxContext
    );

private:
    UdpAuthenticationPacketCodec() = delete;
};
}

#include "tesla/core/UdpAuthenticationInputMapper.h"

#include <algorithm>

namespace tesla::core
{
AuthenticationPacketInput UdpAuthenticationInputMapper::pktMapDataPacket(
    const std::string& strSenderId,
    const protocol::UdpDataPacket& udpDataPacket
)
{
    // 两个32B数组属于不同领域类型；逐字节复制能保持类型边界清晰且不依赖内存别名。
    AuthenticationPacketInput::Message arrMessage{};
    std::copy(
        udpDataPacket.arrMessage().begin(),
        udpDataPacket.arrMessage().end(),
        arrMessage.begin()
    );

    return AuthenticationPacketInput(
        strSenderId,
        udpDataPacket.u64ChainId(),
        udpDataPacket.u32IntervalIndex(),
        udpDataPacket.u32PacketIndex(),
        arrMessage
    );
}
}

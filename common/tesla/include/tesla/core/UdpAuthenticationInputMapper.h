#pragma once

#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <string>

namespace tesla::core
{
/**
 * @brief 在协议校验完成后，将UDP数据报文显式映射为密码算法输入。
 *
 * senderId来自可信的源IP和在线节点映射，不从UDP负载读取。本类只复制算法需要的
 * 逻辑字段，不复用UDP类型，也不把MAC、Key或组标签加入MAC输入对象。
 */
class UdpAuthenticationInputMapper final
{
public:
    static AuthenticationPacketInput pktMapDataPacket(
        const std::string& strSenderId,
        const protocol::UdpDataPacket& udpDataPacket
    );

private:
    UdpAuthenticationInputMapper() = delete;
};
}

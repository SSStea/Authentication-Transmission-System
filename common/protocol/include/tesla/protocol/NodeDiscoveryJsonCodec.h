#pragma once

#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/ProtocolDecodeError.h"

#include <string>
#include <variant>

namespace tesla::protocol
{
using NodeDiscoveryDecodeResult = std::variant<NodeDiscoveryMessage, ProtocolDecodeError>;

/** @brief 编解码一个完整UDP JSON发现数据报，不添加换行或长度前缀。 */
class NodeDiscoveryJsonCodec final
{
public:
    static std::string strEncode(const NodeDiscoveryMessage& msgMessage);
    static NodeDiscoveryDecodeResult resDecode(const std::string& strJson);

private:
    NodeDiscoveryJsonCodec() = delete;
};
}

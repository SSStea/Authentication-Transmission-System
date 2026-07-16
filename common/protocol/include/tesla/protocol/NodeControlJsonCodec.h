#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/ProtocolTypes.h"

#include <string>
#include <variant>

namespace tesla::protocol
{
using NodeControlDecodeResult = std::variant<NodeControlMessage, ProtocolDecodeError>;

/** @brief 编解码TCP JSON控制帧内的握手、状态和认证配置消息。 */
class NodeControlJsonCodec final
{
public:
    static std::string strEncode(const NodeControlMessage& msgMessage);
    static NodeControlDecodeResult resDecode(const std::string& strJson);

private:
    NodeControlJsonCodec() = delete;
};
}

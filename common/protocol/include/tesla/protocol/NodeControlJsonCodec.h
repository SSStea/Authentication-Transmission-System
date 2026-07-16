#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/ProtocolDecodeError.h"

#include <string>
#include <variant>

namespace tesla::protocol
{
using NodeControlDecodeResult = std::variant<NodeControlMessage, ProtocolDecodeError>;

/** @brief 编解码TCP JSON控制帧内的阶段3握手、探活和状态消息。 */
class NodeControlJsonCodec final
{
public:
    static std::string strEncode(const NodeControlMessage& msgMessage);
    static NodeControlDecodeResult resDecode(const std::string& strJson);

private:
    NodeControlJsonCodec() = delete;
};
}

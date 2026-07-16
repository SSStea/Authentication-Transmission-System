#include "tesla/protocol/ProtocolDecodeError.h"

#include <utility>

namespace tesla::protocol
{
// 错误对象只保留分类和可读说明，避免把不可信或敏感原始载荷带入日志。
ProtocolDecodeError::ProtocolDecodeError(
    ProtocolDecodeErrorCode errCode,
    std::string strMessage
)
    : m_errCode(errCode),
      m_strMessage(std::move(strMessage))
{
}

ProtocolDecodeErrorCode ProtocolDecodeError::errCode() const noexcept
{
    return m_errCode;
}

const std::string& ProtocolDecodeError::strMessage() const noexcept
{
    return m_strMessage;
}
}

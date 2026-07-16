#include "tesla/core/NativeVerificationDetails.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
// 原生验证详情保持逐包状态与输入固定槽位的一一对应关系。
NativeVerificationDetails::NativeVerificationDetails(
    std::vector<NativePacketStatus> vecPacketStatuses
)
    : m_vecPacketStatuses(std::move(vecPacketStatuses))
{
    if (m_vecPacketStatuses.empty())
    {
        throw std::invalid_argument("Native verification details require packet statuses");
    }
}

const std::vector<NativePacketStatus>&
NativeVerificationDetails::vecPacketStatuses() const noexcept
{
    return m_vecPacketStatuses;
}
}

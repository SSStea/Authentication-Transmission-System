#include "tesla/core/NativeTeslaDetails.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
// 原生模式详情只封装与固定报文槽位对应的逐包MAC。
NativeAuthenticationDetails::NativeAuthenticationDetails(
    std::vector<std::optional<crypto::Digest>> vecPacketMacs
)
    : m_vecPacketMacs(std::move(vecPacketMacs))
{
    if (m_vecPacketMacs.empty())
    {
        throw std::invalid_argument("Native authentication details require packet MAC slots");
    }
}

const std::vector<std::optional<crypto::Digest>>&
NativeAuthenticationDetails::vecPacketMacs() const noexcept
{
    return m_vecPacketMacs;
}

NativeVerificationDetails::NativeVerificationDetails(
    std::vector<NativePacketStatus> vecPacketStatuses
)
    : m_vecPacketStatuses(std::move(vecPacketStatuses))
{
    if (m_vecPacketStatuses.empty())
    {
        throw std::invalid_argument(
            "Native verification details require packet statuses"
        );
    }
}

const std::vector<NativePacketStatus>&
NativeVerificationDetails::vecPacketStatuses() const noexcept
{
    return m_vecPacketStatuses;
}
}

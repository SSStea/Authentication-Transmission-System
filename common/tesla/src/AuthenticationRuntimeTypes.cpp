#include "tesla/core/AuthenticationRuntimeTypes.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
TimeSynchronizationStatus::TimeSynchronizationStatus(
    bool bSynchronized,
    std::uint32_t u32ToleranceMilliseconds,
    std::string strMessage
)
    : m_bSynchronized(bSynchronized),
      m_u32ToleranceMilliseconds(u32ToleranceMilliseconds),
      m_strMessage(std::move(strMessage))
{
    if (m_strMessage.empty())
    {
        throw std::invalid_argument("Time synchronization status requires a message");
    }

    if (m_bSynchronized && m_u32ToleranceMilliseconds == 0)
    {
        throw std::invalid_argument(
            "Synchronized clock status requires a positive safety tolerance"
        );
    }
}

bool TimeSynchronizationStatus::bSynchronized() const noexcept
{
    return m_bSynchronized;
}

std::uint32_t
TimeSynchronizationStatus::u32ToleranceMilliseconds() const noexcept
{
    return m_u32ToleranceMilliseconds;
}

const std::string& TimeSynchronizationStatus::strMessage() const noexcept
{
    return m_strMessage;
}

AuthenticationRuntimeResult::AuthenticationRuntimeResult(
    std::string strRoundId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    AuthenticationRuntimeResultStatus statusResult,
    std::uint32_t u32ExpectedPacketCount,
    std::uint32_t u32ReceivedPacketCount,
    std::uint32_t u32AuthenticatedPacketCount,
    std::uint32_t u32FailedPacketCount,
    std::uint32_t u32MissingPacketCount,
    std::string strRecoveredText,
    std::string strMessage
)
    : m_strRoundId(std::move(strRoundId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_statusResult(statusResult),
      m_u32ExpectedPacketCount(u32ExpectedPacketCount),
      m_u32ReceivedPacketCount(u32ReceivedPacketCount),
      m_u32AuthenticatedPacketCount(u32AuthenticatedPacketCount),
      m_u32FailedPacketCount(u32FailedPacketCount),
      m_u32MissingPacketCount(u32MissingPacketCount),
      m_strRecoveredText(std::move(strRecoveredText)),
      m_strMessage(std::move(strMessage))
{
    if (m_strRoundId.empty() || m_strSenderId.empty() || m_u64ChainId == 0)
    {
        throw std::invalid_argument("Authentication runtime result identity is invalid");
    }

    if (m_u32ExpectedPacketCount == 0
        || m_u32ReceivedPacketCount > m_u32ExpectedPacketCount
        || m_u32AuthenticatedPacketCount > m_u32ReceivedPacketCount
        || m_u32FailedPacketCount > m_u32ReceivedPacketCount
        || m_u32MissingPacketCount > m_u32ExpectedPacketCount)
    {
        throw std::invalid_argument("Authentication runtime result counts are invalid");
    }

    if (m_strMessage.empty())
    {
        throw std::invalid_argument("Authentication runtime result requires a message");
    }
}

const std::string& AuthenticationRuntimeResult::strRoundId() const noexcept
{
    return m_strRoundId;
}

const std::string& AuthenticationRuntimeResult::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t AuthenticationRuntimeResult::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

AuthenticationRuntimeResultStatus
AuthenticationRuntimeResult::statusResult() const noexcept
{
    return m_statusResult;
}

std::uint32_t
AuthenticationRuntimeResult::u32ExpectedPacketCount() const noexcept
{
    return m_u32ExpectedPacketCount;
}

std::uint32_t
AuthenticationRuntimeResult::u32ReceivedPacketCount() const noexcept
{
    return m_u32ReceivedPacketCount;
}

std::uint32_t
AuthenticationRuntimeResult::u32AuthenticatedPacketCount() const noexcept
{
    return m_u32AuthenticatedPacketCount;
}

std::uint32_t
AuthenticationRuntimeResult::u32FailedPacketCount() const noexcept
{
    return m_u32FailedPacketCount;
}

std::uint32_t
AuthenticationRuntimeResult::u32MissingPacketCount() const noexcept
{
    return m_u32MissingPacketCount;
}

const std::string& AuthenticationRuntimeResult::strRecoveredText() const noexcept
{
    return m_strRecoveredText;
}

const std::string& AuthenticationRuntimeResult::strMessage() const noexcept
{
    return m_strMessage;
}
}

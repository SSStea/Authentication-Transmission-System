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

TextAuthenticationRuntimeResultDetails::TextAuthenticationRuntimeResultDetails(
    std::string strRecoveredText
)
    : m_strRecoveredText(std::move(strRecoveredText))
{
}

const std::string&
TextAuthenticationRuntimeResultDetails::strRecoveredText() const noexcept
{
    return m_strRecoveredText;
}

FileSenderAuthenticationRuntimeResultDetails::
FileSenderAuthenticationRuntimeResultDetails(
    std::uint64_t u64OriginalByteCount
)
    : m_u64OriginalByteCount(u64OriginalByteCount)
{
    if (m_u64OriginalByteCount == 0)
    {
        throw std::invalid_argument("File Sender result size must be positive");
    }
}

std::uint64_t
FileSenderAuthenticationRuntimeResultDetails::u64OriginalByteCount() const noexcept
{
    return m_u64OriginalByteCount;
}

FileReceiverAuthenticationRuntimeResultDetails::
FileReceiverAuthenticationRuntimeResultDetails(
    std::uint64_t u64OriginalByteCount,
    crypto::ByteBuffer vecRecoveredFileBytes,
    std::optional<crypto::Digest> optRecoveredSha256
)
    : m_u64OriginalByteCount(u64OriginalByteCount),
      m_vecRecoveredFileBytes(std::move(vecRecoveredFileBytes)),
      m_optRecoveredSha256(std::move(optRecoveredSha256))
{
    if (m_u64OriginalByteCount == 0
        || (m_vecRecoveredFileBytes.empty() && m_optRecoveredSha256.has_value())
        || (!m_vecRecoveredFileBytes.empty() && !m_optRecoveredSha256.has_value())
        || (!m_vecRecoveredFileBytes.empty()
            && m_vecRecoveredFileBytes.size() != m_u64OriginalByteCount))
    {
        throw std::invalid_argument("File Receiver result details are inconsistent");
    }
}

std::uint64_t
FileReceiverAuthenticationRuntimeResultDetails::u64OriginalByteCount() const noexcept
{
    return m_u64OriginalByteCount;
}

const crypto::ByteBuffer&
FileReceiverAuthenticationRuntimeResultDetails::vecRecoveredFileBytes() const noexcept
{
    return m_vecRecoveredFileBytes;
}

const std::optional<crypto::Digest>&
FileReceiverAuthenticationRuntimeResultDetails::optRecoveredSha256() const noexcept
{
    return m_optRecoveredSha256;
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
    AuthenticationRuntimeResultDetails varResultDetails,
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
      m_varResultDetails(std::move(varResultDetails)),
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

const AuthenticationRuntimeResultDetails&
AuthenticationRuntimeResult::varResultDetails() const noexcept
{
    return m_varResultDetails;
}

const std::string& AuthenticationRuntimeResult::strMessage() const noexcept
{
    return m_strMessage;
}
}

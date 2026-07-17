#pragma once

#include <cstdint>
#include <string>

namespace tesla::core
{
/** @brief 平台适配层向公共运行时提供的时钟同步检查结果。 */
class TimeSynchronizationStatus final
{
public:
    TimeSynchronizationStatus(
        bool bSynchronized,
        std::uint32_t u32ToleranceMilliseconds,
        std::string strMessage
    );

    bool bSynchronized() const noexcept;
    std::uint32_t u32ToleranceMilliseconds() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    bool          m_bSynchronized;
    std::uint32_t m_u32ToleranceMilliseconds;
    std::string   m_strMessage;
};

enum class AuthenticationRuntimeResultStatus
{
    Completed,
    AuthenticationFailed,
    VerificationTimeout,
    InvalidSchedulingOverrun,
    Stopped,
    ProtocolIncomplete,
    TimeUnsynchronized
};

/** @brief 公共Sender和Receiver运行时向节点适配层返回的最终轮次结果。 */
class AuthenticationRuntimeResult final
{
public:
    AuthenticationRuntimeResult(
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
    );

    const std::string& strRoundId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    AuthenticationRuntimeResultStatus statusResult() const noexcept;
    std::uint32_t u32ExpectedPacketCount() const noexcept;
    std::uint32_t u32ReceivedPacketCount() const noexcept;
    std::uint32_t u32AuthenticatedPacketCount() const noexcept;
    std::uint32_t u32FailedPacketCount() const noexcept;
    std::uint32_t u32MissingPacketCount() const noexcept;
    const std::string& strRecoveredText() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string                       m_strRoundId;
    std::string                       m_strSenderId;
    std::uint64_t                     m_u64ChainId;
    AuthenticationRuntimeResultStatus m_statusResult;
    std::uint32_t                     m_u32ExpectedPacketCount;
    std::uint32_t                     m_u32ReceivedPacketCount;
    std::uint32_t                     m_u32AuthenticatedPacketCount;
    std::uint32_t                     m_u32FailedPacketCount;
    std::uint32_t                     m_u32MissingPacketCount;
    std::string                       m_strRecoveredText;
    std::string                       m_strMessage;
};
}

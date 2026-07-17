#pragma once

#include <cstdint>
#include <string>
#include <variant>

namespace tesla::protocol
{
/** @brief 按可丢报文集合选择固定数量的位置，随机种子用于复现实验。 */
class PacketLossFaultDetails final
{
public:
    PacketLossFaultDetails(
        double dLossRatePercent,
        std::uint64_t u64RandomSeed,
        std::uint32_t u32ProtectedGroupSize
    );

    double dLossRatePercent() const noexcept;
    std::uint64_t u64RandomSeed() const noexcept;
    std::uint32_t u32ProtectedGroupSize() const noexcept;

private:
    double        m_dLossRatePercent;
    std::uint64_t m_u64RandomSeed;
    std::uint32_t m_u32ProtectedGroupSize;
};

/** @brief 连续抑制普通数据报文，标签承载组末报文始终受保护。 */
class LogicalDisconnectFaultDetails final
{
public:
    LogicalDisconnectFaultDetails(
        std::uint32_t u32StartPacketIndex,
        std::uint32_t u32DurationMilliseconds,
        std::uint32_t u32ProtectedGroupSize
    );

    std::uint32_t u32StartPacketIndex() const noexcept;
    std::uint32_t u32DurationMilliseconds() const noexcept;
    std::uint32_t u32ProtectedGroupSize() const noexcept;

private:
    std::uint32_t m_u32StartPacketIndex;
    std::uint32_t m_u32DurationMilliseconds;
    std::uint32_t m_u32ProtectedGroupSize;
};

/** @brief 对本轮全部TESLA UDP报文施加相同单向发送时间偏移。 */
class FixedDelayFaultDetails final
{
public:
    explicit FixedDelayFaultDetails(std::uint32_t u32DelayMilliseconds);

    std::uint32_t u32DelayMilliseconds() const noexcept;

private:
    std::uint32_t m_u32DelayMilliseconds;
};

using AuthenticationFaultDetails = std::variant<
    PacketLossFaultDetails,
    LogicalDisconnectFaultDetails,
    FixedDelayFaultDetails
>;

/** @brief 下发给目标Sender的单一故障计划，不允许同轮组合多个故障。 */
class FaultInjectionControlDetails final
{
public:
    FaultInjectionControlDetails(
        std::string strRequestId,
        std::string strRoundId,
        std::string strTargetSenderId,
        std::uint64_t u64ChainId,
        AuthenticationFaultDetails varFaultDetails
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strTargetSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const AuthenticationFaultDetails& varFaultDetails() const noexcept;

private:
    std::string                m_strRequestId;
    std::string                m_strRoundId;
    std::string                m_strTargetSenderId;
    std::uint64_t              m_u64ChainId;
    AuthenticationFaultDetails m_varFaultDetails;
};

enum class AttackSourceMappingAction
{
    Install,
    Clear
};

/**
 * @brief MANAGER在Receiver安装或清除的临时攻击源映射。
 *
 * 映射同时绑定round、Sender、chain、正常源IP、攻击源IP和过期时间，不能提升为
 * 永久可信来源。
 */
class AttackSourceMappingControlDetails final
{
public:
    AttackSourceMappingControlDetails(
        std::string strRequestId,
        std::string strRoundId,
        AttackSourceMappingAction actAction,
        std::string strTargetSenderId,
        std::string strTargetSenderIp,
        std::string strAttackSourceIp,
        std::uint64_t u64ChainId,
        std::uint64_t u64ExpiresAtMilliseconds
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    AttackSourceMappingAction actAction() const noexcept;
    const std::string& strTargetSenderId() const noexcept;
    const std::string& strTargetSenderIp() const noexcept;
    const std::string& strAttackSourceIp() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint64_t u64ExpiresAtMilliseconds() const noexcept;

private:
    std::string               m_strRequestId;
    std::string               m_strRoundId;
    AttackSourceMappingAction m_actAction;
    std::string               m_strTargetSenderId;
    std::string               m_strTargetSenderIp;
    std::string               m_strAttackSourceIp;
    std::uint64_t             m_u64ChainId;
    std::uint64_t             m_u64ExpiresAtMilliseconds;
};

/** @brief 节点对故障计划或临时攻击源映射的统一确认。 */
class ExperimentControlAcknowledgementDetails final
{
public:
    ExperimentControlAcknowledgementDetails(
        std::string strRequestId,
        std::string strRoundId,
        bool bAccepted,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    bool bAccepted() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string m_strRequestId;
    std::string m_strRoundId;
    bool        m_bAccepted;
    std::string m_strErrorCode;
    std::string m_strMessage;
};
}

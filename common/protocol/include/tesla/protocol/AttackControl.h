#pragma once

#include "tesla/protocol/AuthenticationControl.h"
#include "tesla/protocol/ProtocolTypes.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace tesla::protocol
{
/** @brief 管理端与独立攻击测试端共用的一条TCP控制连接上的消息类型。 */
enum class AttackControlMessageType
{
    ClientHello,
    Ping,
    Pong,
    StatusRequest,
    StatusResponse,
    RoundContext,
    Plan,
    PlanAccepted,
    Ready,
    RoundStart,
    Stop,
    EmergencyStop,
    ExecutionStatus,
    ErrorResponse
};

enum class AttackType
{
    Tamper,
    Replay,
    Dos
};

/** @brief 攻击端对外报告的有限状态，禁止用多个互相矛盾的布尔值表达生命周期。 */
enum class AttackExecutionState
{
    Idle,
    ContextReady,
    PlanPending,
    Ready,
    Scheduled,
    Running,
    Completed,
    Stopped,
    Failed
};

/** @brief 锁定攻击测试端TCP连接的管理方身份；攻击端不接受普通节点角色。 */
class AttackClientHelloDetails final
{
public:
    explicit AttackClientHelloDetails(std::string strClientName);

    const std::string& strClientName() const noexcept;

private:
    std::string m_strClientName;
};

/** @brief PING、PONG和STATUS_REQUEST共用的请求关联信息。 */
class AttackRequestControlDetails final
{
public:
    AttackRequestControlDetails(
        AttackControlMessageType typeMessage,
        std::string strRequestId
    );

    AttackControlMessageType typeMessage() const noexcept;
    const std::string& strRequestId() const noexcept;

private:
    AttackControlMessageType m_typeMessage;
    std::string              m_strRequestId;
};

/** @brief 攻击测试端当前连接、监听和执行状态的轻量快照。 */
class AttackStatusControlDetails final
{
public:
    AttackStatusControlDetails(
        std::string strRequestId,
        std::string strNodeName,
        bool bMulticastListening,
        AttackExecutionState stateExecution,
        std::uint64_t u64TimestampMilliseconds
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strNodeName() const noexcept;
    bool bMulticastListening() const noexcept;
    AttackExecutionState stateExecution() const noexcept;
    bool bAttackRunning() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;

private:
    std::string          m_strRequestId;
    std::string          m_strNodeName;
    bool                 m_bMulticastListening;
    AttackExecutionState m_stateExecution;
    std::uint64_t        m_u64TimestampMilliseconds;
};

/**
 * @brief 管理端下发给攻击端的目标公开上下文。
 *
 * 该类型不包含Sender种子、未披露密钥或完整业务载荷。
 */
class AttackRoundContextControlDetails final
{
public:
    AttackRoundContextControlDetails(
        std::string strRequestId,
        std::string strRoundId,
        std::string strTargetSenderId,
        std::string strTargetSenderIp,
        std::uint64_t u64ChainId,
        AuthenticationCryptoAlgorithm algCryptoAlgorithm,
        UdpAuthenticationMode modeAuthentication,
        std::uint32_t u32DataPacketCount,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32IntervalMilliseconds,
        std::uint32_t u32DisclosureDelay,
        std::uint64_t u64StartTimestampMilliseconds,
        std::uint32_t u32GroupSize,
        std::uint32_t u32DetectionThreshold,
        std::size_t nTauCount
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strTargetSenderId() const noexcept;
    const std::string& strTargetSenderIp() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    AuthenticationCryptoAlgorithm algCryptoAlgorithm() const noexcept;
    UdpAuthenticationMode modeAuthentication() const noexcept;
    std::uint32_t u32DataPacketCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint64_t u64StartTimestampMilliseconds() const noexcept;
    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;
    std::size_t nTauCount() const noexcept;

private:
    std::string           m_strRequestId;
    std::string           m_strRoundId;
    std::string           m_strTargetSenderId;
    std::string           m_strTargetSenderIp;
    std::uint64_t         m_u64ChainId;
    AuthenticationCryptoAlgorithm m_algCryptoAlgorithm;
    UdpAuthenticationMode m_modeAuthentication;
    std::uint32_t         m_u32DataPacketCount;
    std::uint32_t         m_u32PacketsPerInterval;
    std::uint32_t         m_u32IntervalMilliseconds;
    std::uint32_t         m_u32DisclosureDelay;
    std::uint64_t         m_u64StartTimestampMilliseconds;
    std::uint32_t         m_u32GroupSize;
    std::uint32_t         m_u32DetectionThreshold;
    std::size_t           m_nTauCount;
};

/** @brief 篡改攻击只改变Message中的指定字节，不允许重新计算认证字段。 */
class TamperAttackPlanDetails final
{
public:
    TamperAttackPlanDetails(
        std::vector<std::uint32_t> vecPacketIndexes,
        std::uint8_t u8MessageByteOffset,
        std::uint8_t u8XorMask,
        std::uint32_t u32RepeatCount
    );

    const std::vector<std::uint32_t>& vecPacketIndexes() const noexcept;
    std::uint8_t u8MessageByteOffset() const noexcept;
    std::uint8_t u8XorMask() const noexcept;
    std::uint32_t u32RepeatCount() const noexcept;

private:
    std::vector<std::uint32_t> m_vecPacketIndexes;
    std::uint8_t               m_u8MessageByteOffset;
    std::uint8_t               m_u8XorMask;
    std::uint32_t              m_u32RepeatCount;
};

/** @brief 重放攻击保留完整UDP认证载荷，仅配置延迟和重复节奏。 */
class ReplayAttackPlanDetails final
{
public:
    ReplayAttackPlanDetails(
        std::vector<std::uint32_t> vecPacketIndexes,
        std::uint32_t u32ReplayDelayMilliseconds,
        std::uint32_t u32RepeatCount,
        std::uint32_t u32RepeatGapMilliseconds
    );

    const std::vector<std::uint32_t>& vecPacketIndexes() const noexcept;
    std::uint32_t u32ReplayDelayMilliseconds() const noexcept;
    std::uint32_t u32RepeatCount() const noexcept;
    std::uint32_t u32RepeatGapMilliseconds() const noexcept;

private:
    std::vector<std::uint32_t> m_vecPacketIndexes;
    std::uint32_t              m_u32ReplayDelayMilliseconds;
    std::uint32_t              m_u32RepeatCount;
    std::uint32_t              m_u32RepeatGapMilliseconds;
};

/** @brief DoS只能指向程序内部TESLA组播，地址和端口不进入用户计划。 */
class DosAttackPlanDetails final
{
public:
    DosAttackPlanDetails(
        std::uint32_t u32RatePacketsPerSecond,
        std::uint32_t u32DurationMilliseconds,
        std::uint32_t u32PacketBytes
    );

    std::uint32_t u32RatePacketsPerSecond() const noexcept;
    std::uint32_t u32DurationMilliseconds() const noexcept;
    std::uint32_t u32PacketBytes() const noexcept;

private:
    std::uint32_t m_u32RatePacketsPerSecond;
    std::uint32_t m_u32DurationMilliseconds;
    std::uint32_t m_u32PacketBytes;
};

using AttackPlanDetails = std::variant<
    TamperAttackPlanDetails,
    ReplayAttackPlanDetails,
    DosAttackPlanDetails
>;

/** @brief 攻击计划的公共标识和模式专用详情。 */
class AttackPlanControlDetails final
{
public:
    AttackPlanControlDetails(
        std::uint64_t u64AttackId,
        std::string strRoundId,
        std::string strTargetSenderId,
        std::uint64_t u64ChainId,
        AttackPlanDetails varPlanDetails
    );

    std::uint64_t u64AttackId() const noexcept;
    const std::string& strRoundId() const noexcept;
    const std::string& strTargetSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    AttackType typeAttack() const noexcept;
    const AttackPlanDetails& varPlanDetails() const noexcept;

private:
    std::uint64_t    m_u64AttackId;
    std::string      m_strRoundId;
    std::string      m_strTargetSenderId;
    std::uint64_t    m_u64ChainId;
    AttackPlanDetails m_varPlanDetails;
};

/** @brief 管理端对攻击计划的明确接收结果。 */
class AttackPlanAcceptedControlDetails final
{
public:
    AttackPlanAcceptedControlDetails(
        std::uint64_t u64AttackId,
        std::string strRoundId,
        bool bAccepted,
        std::string strErrorCode,
        std::string strMessage
    );

    std::uint64_t u64AttackId() const noexcept;
    const std::string& strRoundId() const noexcept;
    bool bAccepted() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::uint64_t m_u64AttackId;
    std::string   m_strRoundId;
    bool          m_bAccepted;
    std::string   m_strErrorCode;
    std::string   m_strMessage;
};

/** @brief 攻击端完成组播监听、捕获过滤和执行资源准备后的确认。 */
class AttackReadyControlDetails final
{
public:
    AttackReadyControlDetails(
        std::uint64_t u64AttackId,
        std::string strRoundId,
        std::uint64_t u64TimestampMilliseconds
    );

    std::uint64_t u64AttackId() const noexcept;
    const std::string& strRoundId() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;

private:
    std::uint64_t m_u64AttackId;
    std::string   m_strRoundId;
    std::uint64_t m_u64TimestampMilliseconds;
};

/** @brief ROUND_START、ATTACK_STOP和紧急停止共用的轮次命令。 */
class AttackRoundCommandControlDetails final
{
public:
    AttackRoundCommandControlDetails(
        AttackControlMessageType typeMessage,
        std::uint64_t u64AttackId,
        std::string strRoundId,
        std::uint64_t u64ExecutionTimestampMilliseconds
    );

    AttackControlMessageType typeMessage() const noexcept;
    std::uint64_t u64AttackId() const noexcept;
    const std::string& strRoundId() const noexcept;
    std::uint64_t u64ExecutionTimestampMilliseconds() const noexcept;

private:
    AttackControlMessageType m_typeMessage;
    std::uint64_t            m_u64AttackId;
    std::string              m_strRoundId;
    std::uint64_t            m_u64ExecutionTimestampMilliseconds;
};

class TamperAttackStatusDetails final
{
public:
    TamperAttackStatusDetails(
        std::uint64_t u64CapturedPacketCount,
        std::uint64_t u64InjectedPacketCount,
        std::uint64_t u64LastInjectionDelayMicroseconds
    );

    std::uint64_t u64CapturedPacketCount() const noexcept;
    std::uint64_t u64InjectedPacketCount() const noexcept;
    std::uint64_t u64LastInjectionDelayMicroseconds() const noexcept;

private:
    std::uint64_t m_u64CapturedPacketCount;
    std::uint64_t m_u64InjectedPacketCount;
    std::uint64_t m_u64LastInjectionDelayMicroseconds;
};

class ReplayAttackStatusDetails final
{
public:
    ReplayAttackStatusDetails(
        std::uint64_t u64CapturedPacketCount,
        std::uint64_t u64ReplayedPacketCount
    );

    std::uint64_t u64CapturedPacketCount() const noexcept;
    std::uint64_t u64ReplayedPacketCount() const noexcept;

private:
    std::uint64_t m_u64CapturedPacketCount;
    std::uint64_t m_u64ReplayedPacketCount;
};

class DosAttackStatusDetails final
{
public:
    DosAttackStatusDetails(
        std::uint64_t u64SentPacketCount,
        std::uint64_t u64SentByteCount,
        double dActualPacketsPerSecond
    );

    std::uint64_t u64SentPacketCount() const noexcept;
    std::uint64_t u64SentByteCount() const noexcept;
    double dActualPacketsPerSecond() const noexcept;

private:
    std::uint64_t m_u64SentPacketCount;
    std::uint64_t m_u64SentByteCount;
    double        m_dActualPacketsPerSecond;
};

using AttackExecutionStatusDetails = std::variant<
    TamperAttackStatusDetails,
    ReplayAttackStatusDetails,
    DosAttackStatusDetails
>;

/** @brief 执行状态公共字段与模式专用统计，避免无关字段平铺。 */
class AttackExecutionStatusControlDetails final
{
public:
    AttackExecutionStatusControlDetails(
        std::uint64_t u64AttackId,
        std::string strRoundId,
        AttackExecutionState stateExecution,
        AttackExecutionStatusDetails varStatusDetails,
        std::uint64_t u64SendErrorCount,
        std::uint64_t u64TimestampMilliseconds,
        std::string strMessage
    );

    std::uint64_t u64AttackId() const noexcept;
    const std::string& strRoundId() const noexcept;
    AttackExecutionState stateExecution() const noexcept;
    AttackType typeAttack() const noexcept;
    const AttackExecutionStatusDetails& varStatusDetails() const noexcept;
    std::uint64_t u64SendErrorCount() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::uint64_t                m_u64AttackId;
    std::string                  m_strRoundId;
    AttackExecutionState         m_stateExecution;
    AttackExecutionStatusDetails m_varStatusDetails;
    std::uint64_t                m_u64SendErrorCount;
    std::uint64_t                m_u64TimestampMilliseconds;
    std::string                  m_strMessage;
};

/** @brief 攻击控制服务向管理端返回的稳定错误码和可读说明。 */
class AttackErrorControlDetails final
{
public:
    AttackErrorControlDetails(
        std::string strRequestId,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string m_strRequestId;
    std::string m_strErrorCode;
    std::string m_strMessage;
};

using AttackControlMessageDetails = std::variant<
    AttackClientHelloDetails,
    AttackRequestControlDetails,
    AttackStatusControlDetails,
    AttackRoundContextControlDetails,
    AttackPlanControlDetails,
    AttackPlanAcceptedControlDetails,
    AttackReadyControlDetails,
    AttackRoundCommandControlDetails,
    AttackExecutionStatusControlDetails,
    AttackErrorControlDetails
>;

/** @brief 独立攻击控制面的强类型消息，不混入NodeAgent配置协议。 */
class AttackControlMessage final
{
public:
    explicit AttackControlMessage(AttackControlMessageDetails varDetails);

    AttackControlMessageType typeMessage() const noexcept;
    const AttackControlMessageDetails& varDetails() const noexcept;

private:
    AttackControlMessageDetails m_varDetails;
};

using AttackControlDecodeResult = std::variant<
    AttackControlMessage,
    ProtocolDecodeError
>;

/** @brief 编解码攻击测试端JSON控制载荷；TCP长度前缀由TcpFrame模块处理。 */
class AttackControlJsonCodec final
{
public:
    static std::string strEncode(const AttackControlMessage& msgMessage);
    static AttackControlDecodeResult resDecode(const std::string& strJson);

private:
    AttackControlJsonCodec() = delete;
};
}

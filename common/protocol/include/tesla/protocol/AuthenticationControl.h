#pragma once

#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tesla::protocol
{
/** @brief 控制面可选择的固定32字节摘要与HMAC算法。 */
enum class AuthenticationCryptoAlgorithm
{
    Sha256,
    Sm3,
    Sha3_256
};

/** @brief Sender和Receiver配置确认消息中的目标类型。 */
enum class AuthenticationConfigTarget
{
    Sender,
    Receiver,
    TextPayload
};

/** @brief 可信TCP认证上下文中的载荷类型，UDP报文不重复携带。 */
enum class AuthenticationPayloadMode
{
    Text,
    File
};

/** @brief 改进TESLA控制配置中的分组大小和检测门限。 */
class ImprovedTeslaControlParameters final
{
public:
    ImprovedTeslaControlParameters(
        std::uint32_t u32GroupSize,
        std::uint32_t u32DetectionThreshold
    );

    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;

private:
    std::uint32_t m_u32GroupSize;
    std::uint32_t m_u32DetectionThreshold;
};

/**
 * @brief CA、Sender和Receiver共享的一轮认证算法及调度参数。
 *
 * chainLength作为控制面校验值保留，NodeAgent会与本地公式重新计算的结果比较。
 */
class AuthenticationRoundControlParameters final
{
public:
    AuthenticationRoundControlParameters(
        AuthenticationCryptoAlgorithm algCryptoAlgorithm,
        UdpAuthenticationMode modeAuthentication,
        std::uint32_t u32TotalPacketCount,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32IntervalMilliseconds,
        std::uint64_t u64StartTimestampMilliseconds,
        std::uint32_t u32ChainLength,
        std::optional<ImprovedTeslaControlParameters> optImprovedParameters = std::nullopt,
        AuthenticationPayloadMode modePayload = AuthenticationPayloadMode::Text
    );

    AuthenticationCryptoAlgorithm algCryptoAlgorithm() const noexcept;
    UdpAuthenticationMode modeAuthentication() const noexcept;
    std::uint32_t u32TotalPacketCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    std::uint64_t u64StartTimestampMilliseconds() const noexcept;
    std::uint32_t u32ChainLength() const noexcept;
    AuthenticationPayloadMode modePayload() const noexcept;
    const std::optional<ImprovedTeslaControlParameters>&
        optImprovedParameters() const noexcept;

private:
    AuthenticationCryptoAlgorithm                  m_algCryptoAlgorithm;
    UdpAuthenticationMode                         m_modeAuthentication;
    std::uint32_t                                 m_u32TotalPacketCount;
    std::uint32_t                                 m_u32PacketsPerInterval;
    std::uint32_t                                 m_u32DisclosureDelay;
    std::uint32_t                                 m_u32IntervalMilliseconds;
    std::uint64_t                                 m_u64StartTimestampMilliseconds;
    std::uint32_t                                 m_u32ChainLength;
    std::optional<ImprovedTeslaControlParameters> m_optImprovedParameters;
    AuthenticationPayloadMode                    m_modePayload;
};

/** @brief 只向Sender下发的配置详情，包含密钥链种子。 */
class SenderAuthenticationConfigControlDetails final
{
public:
    SenderAuthenticationConfigControlDetails(
        std::string strRequestId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        BinaryBlock arrChainSeed,
        BinaryBlock arrCommitmentKey,
        AuthenticationRoundControlParameters prmRoundParameters
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const BinaryBlock& arrChainSeed() const noexcept;
    const BinaryBlock& arrCommitmentKey() const noexcept;
    const AuthenticationRoundControlParameters& prmRoundParameters() const noexcept;

private:
    std::string                           m_strRequestId;
    std::string                           m_strSenderId;
    std::uint64_t                         m_u64ChainId;
    BinaryBlock                           m_arrChainSeed;
    BinaryBlock                           m_arrCommitmentKey;
    AuthenticationRoundControlParameters  m_prmRoundParameters;
};

/** @brief Receiver配置中的单个Sender公开上下文，不包含种子或完整密钥链。 */
class ReceiverAuthenticationContextControlDetails final
{
public:
    ReceiverAuthenticationContextControlDetails(
        std::string strSenderId,
        std::string strSenderIpAddress,
        std::uint64_t u64ChainId,
        BinaryBlock arrCommitmentKey,
        AuthenticationRoundControlParameters prmRoundParameters
    );

    const std::string& strSenderId() const noexcept;
    const std::string& strSenderIpAddress() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const BinaryBlock& arrCommitmentKey() const noexcept;
    const AuthenticationRoundControlParameters& prmRoundParameters() const noexcept;

private:
    std::string                           m_strSenderId;
    std::string                           m_strSenderIpAddress;
    std::uint64_t                         m_u64ChainId;
    BinaryBlock                           m_arrCommitmentKey;
    AuthenticationRoundControlParameters  m_prmRoundParameters;
};

/** @brief 一次性替换Receiver全部可信Sender上下文的控制消息。 */
class ReceiverAuthenticationContextsControlDetails final
{
public:
    ReceiverAuthenticationContextsControlDetails(
        std::string strRequestId,
        std::vector<ReceiverAuthenticationContextControlDetails> vecContexts
    );

    const std::string& strRequestId() const noexcept;
    const std::vector<ReceiverAuthenticationContextControlDetails>&
        vecContexts() const noexcept;

private:
    std::string                                               m_strRequestId;
    std::vector<ReceiverAuthenticationContextControlDetails>  m_vecContexts;
};

/** @brief NodeAgent对Sender或Receiver认证配置的明确接收结果。 */
class AuthenticationConfigAcknowledgementControlDetails final
{
public:
    AuthenticationConfigAcknowledgementControlDetails(
        std::string strRequestId,
        AuthenticationConfigTarget targetConfig,
        bool bAccepted,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    AuthenticationConfigTarget targetConfig() const noexcept;
    bool bAccepted() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string                 m_strRequestId;
    AuthenticationConfigTarget  m_targetConfig;
    bool                        m_bAccepted;
    std::string                 m_strErrorCode;
    std::string                 m_strMessage;
};

/** @brief 独立于算法配置下发给Sender的阶段6手动文本载荷。 */
class TextPayloadControlDetails final
{
public:
    TextPayloadControlDetails(
        std::string strRequestId,
        std::uint64_t u64ChainId,
        std::string strUtf8Text
    );

    const std::string& strRequestId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    const std::string& strUtf8Text() const noexcept;

private:
    std::string   m_strRequestId;
    std::uint64_t m_u64ChainId;
    std::string   m_strUtf8Text;
};

enum class AuthenticationRoundCommand
{
    Start,
    Pause,
    Resume,
    Stop
};

/**
 * @brief 一轮认证的统一控制命令。
 *
 * Pause在指定逻辑间隔结束后生效；Resume从指定逻辑间隔和新的未来时间继续，
 * 避免直接冻结系统时钟导致TESLA披露时间线含糊。
 */
class AuthenticationRoundCommandControlDetails final
{
public:
    AuthenticationRoundCommandControlDetails(
        std::string strRequestId,
        std::string strRoundId,
        AuthenticationRoundCommand cmdCommand,
        std::uint64_t u64ExecutionTimestampMilliseconds,
        std::uint32_t u32LogicalIntervalIndex
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    AuthenticationRoundCommand cmdCommand() const noexcept;
    std::uint64_t u64ExecutionTimestampMilliseconds() const noexcept;
    std::uint32_t u32LogicalIntervalIndex() const noexcept;

private:
    std::string                m_strRequestId;
    std::string                m_strRoundId;
    AuthenticationRoundCommand m_cmdCommand;
    std::uint64_t              m_u64ExecutionTimestampMilliseconds;
    std::uint32_t              m_u32LogicalIntervalIndex;
};

/** @brief 节点对开始、暂停、继续或停止命令的明确接收结果。 */
class AuthenticationRoundAcknowledgementControlDetails final
{
public:
    AuthenticationRoundAcknowledgementControlDetails(
        std::string strRequestId,
        std::string strRoundId,
        AuthenticationRoundCommand cmdCommand,
        bool bAccepted,
        std::string strErrorCode,
        std::string strMessage
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strRoundId() const noexcept;
    AuthenticationRoundCommand cmdCommand() const noexcept;
    bool bAccepted() const noexcept;
    const std::string& strErrorCode() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string                m_strRequestId;
    std::string                m_strRoundId;
    AuthenticationRoundCommand m_cmdCommand;
    bool                       m_bAccepted;
    std::string                m_strErrorCode;
    std::string                m_strMessage;
};

enum class AuthenticationRoundResultRole
{
    Sender,
    Receiver
};

enum class AuthenticationRoundResultStatus
{
    Completed,
    AuthenticationFailed,
    VerificationTimeout,
    InvalidSchedulingOverrun,
    Stopped,
    ProtocolIncomplete,
    TimeUnsynchronized
};

/** @brief Sender或Receiver通过原TCP连接上报的一轮阶段6最终结果。 */
class AuthenticationRoundResultControlDetails final
{
public:
    AuthenticationRoundResultControlDetails(
        std::string strRoundId,
        std::string strSenderId,
        std::uint64_t u64ChainId,
        AuthenticationRoundResultRole roleResult,
        AuthenticationRoundResultStatus statusResult,
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
    AuthenticationRoundResultRole roleResult() const noexcept;
    AuthenticationRoundResultStatus statusResult() const noexcept;
    std::uint32_t u32ExpectedPacketCount() const noexcept;
    std::uint32_t u32ReceivedPacketCount() const noexcept;
    std::uint32_t u32AuthenticatedPacketCount() const noexcept;
    std::uint32_t u32FailedPacketCount() const noexcept;
    std::uint32_t u32MissingPacketCount() const noexcept;
    const std::string& strRecoveredText() const noexcept;
    const std::string& strMessage() const noexcept;

private:
    std::string                     m_strRoundId;
    std::string                     m_strSenderId;
    std::uint64_t                   m_u64ChainId;
    AuthenticationRoundResultRole   m_roleResult;
    AuthenticationRoundResultStatus m_statusResult;
    std::uint32_t                   m_u32ExpectedPacketCount;
    std::uint32_t                   m_u32ReceivedPacketCount;
    std::uint32_t                   m_u32AuthenticatedPacketCount;
    std::uint32_t                   m_u32FailedPacketCount;
    std::uint32_t                   m_u32MissingPacketCount;
    std::string                     m_strRecoveredText;
    std::string                     m_strMessage;
};

/**
 * @brief 编解码认证控制消息中的固定长度十六进制值。
 *
 * 该Codec只服务本模块中的chainId、种子和K0字段，与认证控制详情共同变化。
 */
class AuthenticationControlValueCodec final
{
public:
    static std::string strEncodeChainId(std::uint64_t u64ChainId);
    static std::uint64_t u64DecodeChainId(const std::string& strChainId);

    static std::string strEncodeBlock(const BinaryBlock& arrBlock);
    static BinaryBlock arrDecodeBlock(const std::string& strBlock);

private:
    AuthenticationControlValueCodec() = delete;
};
}

#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <string>
#include <variant>

namespace tesla::protocol
{
/** @brief 集中管理GUI与独立攻击测试端之间的阶段5最小控制消息类型。 */
enum class AttackControlMessageType
{
    ClientHello,
    Ping,
    Pong,
    StatusRequest,
    StatusResponse,
    ErrorResponse
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

/** @brief 攻击测试端当前连接、监听和执行状态的最小快照。 */
class AttackStatusControlDetails final
{
public:
    AttackStatusControlDetails(
        std::string strRequestId,
        std::string strNodeName,
        bool bMulticastListening,
        bool bAttackRunning,
        std::uint64_t u64TimestampMilliseconds
    );

    const std::string& strRequestId() const noexcept;
    const std::string& strNodeName() const noexcept;
    bool bMulticastListening() const noexcept;
    bool bAttackRunning() const noexcept;
    std::uint64_t u64TimestampMilliseconds() const noexcept;

private:
    std::string   m_strRequestId;
    std::string   m_strNodeName;
    bool          m_bMulticastListening;
    bool          m_bAttackRunning;
    std::uint64_t m_u64TimestampMilliseconds;
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
    AttackErrorControlDetails
>;

/** @brief 独立攻击控制面的强类型消息，后续攻击计划不会混入NodeAgent配置协议。 */
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

/** @brief 编解码攻击测试端JSON控制载荷；TCP长度前缀继续由TcpFrame模块处理。 */
class AttackControlJsonCodec final
{
public:
    static std::string strEncode(const AttackControlMessage& msgMessage);
    static AttackControlDecodeResult resDecode(const std::string& strJson);

private:
    AttackControlJsonCodec() = delete;
};
}

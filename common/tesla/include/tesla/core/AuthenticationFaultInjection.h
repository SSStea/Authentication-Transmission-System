#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/protocol/ExperimentControl.h"
#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <memory>
#include <string>

namespace tesla::core
{
enum class DatagramFaultDisposition
{
    Send,
    Drop
};

/** @brief 故障策略对单个已编码TESLA UDP报文作出的发送决定。 */
class DatagramFaultDecision final
{
public:
    DatagramFaultDecision(
        DatagramFaultDisposition dspDisposition,
        std::uint32_t u32DelayMilliseconds,
        std::string strReason
    );

    DatagramFaultDisposition dspDisposition() const noexcept;
    std::uint32_t u32DelayMilliseconds() const noexcept;
    const std::string& strReason() const noexcept;

private:
    DatagramFaultDisposition m_dspDisposition;
    std::uint32_t            m_u32DelayMilliseconds;
    std::string              m_strReason;
};

/**
 * @brief Sender发送边界上的独立故障策略。
 *
 * 策略只决定丢弃或固定延迟，不修改认证报文字节；一个实例只服务一轮发送线程。
 */
class AuthenticationFaultPolicy
{
public:
    virtual ~AuthenticationFaultPolicy() = default;

    virtual DatagramFaultDecision decDecide(
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64PlannedSendTimestampMilliseconds
    ) = 0;
};

/** @brief 根据模式专用配置创建丢包、逻辑断链或固定延迟策略。 */
std::unique_ptr<AuthenticationFaultPolicy> ptrCreateAuthenticationFaultPolicy(
    const protocol::AuthenticationFaultDetails& varFaultDetails,
    const AuthenticationRoundParameters& prmRound
);
}

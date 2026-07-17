#pragma once

#include "tesla/core/AuthenticationRuntimeTypes.h"
#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/metrics/AuthenticationMetrics.h"
#include "tesla/protocol/MonitorControl.h"
#include "tesla/protocol/ExperimentControl.h"
#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace tesla::core
{
/**
 * @brief 负责有界接收、时间安全检查、延迟密钥验证和最终文本认证判定。
 *
 * UDP接收线程只执行固定头和上下文快速检查，完整解析与密码计算进入有上限的工作队列，
 * 防止高密度流量阻塞Socket线程或无限增长内存。
 */
class AuthenticationReceiverRuntime final
{
public:
    using ResultHandler = std::function<void(const AuthenticationRuntimeResult&)>;
    using ObservationHandler = std::function<void(
        const protocol::AuthenticationObservation&
    )>;
    using MetricHandler = std::function<void(
        const metrics::AuthenticationMetricRecord&
    )>;

    explicit AuthenticationReceiverRuntime(
        ResultHandler fnResultHandler,
        ObservationHandler fnObservationHandler = {},
        MetricHandler fnMetricHandler = {}
    );
    ~AuthenticationReceiverRuntime();

    AuthenticationReceiverRuntime(const AuthenticationReceiverRuntime&) = delete;
    AuthenticationReceiverRuntime& operator=(const AuthenticationReceiverRuntime&) = delete;

    void configure(std::vector<ReceiverAuthenticationContext> vecContexts);
    void start(
        std::string strRoundId,
        std::uint64_t u64StartTimestampMilliseconds,
        std::uint32_t u32ClockToleranceMilliseconds
    );
    void requestPause(
        const std::string& strRoundId,
        std::uint32_t u32PauseAfterInterval,
        std::uint64_t u64PauseTimestampMilliseconds
    );
    void resume(
        const std::string& strRoundId,
        std::uint32_t u32ResumeInterval,
        std::uint64_t u64ResumeTimestampMilliseconds
    );
    void stop() noexcept;

    /** @brief 安装或清除仅对当前轮次有效的攻击源映射。 */
    void applyAttackSourceMapping(
        const protocol::AttackSourceMappingControlDetails& detMapping
    );
    void clearAttackSourceMappings() noexcept;

    bool bEnqueueDatagram(
        const std::string& strSourceIpAddress,
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64ReceiveTimestampMilliseconds
    );

    bool bIsConfigured() const;
    bool bIsRunning() const;
    bool bIsPaused() const;
    std::size_t nContextCount() const;
    std::size_t nDroppedQueueDatagramCount() const;
    ReceiverAuthenticationContextLookupResult resFindContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> m_ptrImpl;
};
}

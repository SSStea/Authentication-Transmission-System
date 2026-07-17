#pragma once

#include "tesla/core/AuthenticationRuntimeTypes.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/workload/TextWorkload.h"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace tesla::core
{
/**
 * @brief 负责一轮TESLA数据报文生成、绝对时间调度和披露尾包发送。
 *
 * 工作线程始终可停止并在析构时等待结束，不使用detach。报文在开始前生成并执行
 * 调度可行性检查，运行中任何间隔超限都会立即停止并返回统一结果。
 */
class AuthenticationSenderRuntime final
{
public:
    using DatagramSender = std::function<bool(const protocol::ByteBuffer&)>;
    using ResultHandler = std::function<void(const AuthenticationRuntimeResult&)>;

    AuthenticationSenderRuntime(
        DatagramSender fnDatagramSender,
        ResultHandler fnResultHandler
    );
    ~AuthenticationSenderRuntime();

    AuthenticationSenderRuntime(const AuthenticationSenderRuntime&) = delete;
    AuthenticationSenderRuntime& operator=(const AuthenticationSenderRuntime&) = delete;

    void configure(
        SenderAuthenticationContext ctxSender,
        workload::TextWorkload wrkText
    );
    void start(
        std::string strRoundId,
        std::uint64_t u64StartTimestampMilliseconds
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

    bool bIsConfigured() const;
    bool bIsRunning() const;
    bool bIsPaused() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_ptrImpl;
};
}

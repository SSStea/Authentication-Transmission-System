#pragma once

#include "tesla/core/AuthenticationRuntimeTypes.h"
#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/ProtocolTypes.h"
#include "tesla/workload/FileWorkload.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace tesla::core
{
/**
 * @brief PC节点和Linux NodeAgent共用的认证配置、轮次控制与UDP处理入口。
 *
 * 平台层只负责真实Socket、Qt线程切换和时钟同步查询，算法与状态机不重复实现。
 */
class AuthenticationNodeRuntime final
{
public:
    using DatagramSender = std::function<bool(const protocol::ByteBuffer&)>;
    using ControlEventHandler = std::function<void(
        const protocol::NodeControlMessage&
    )>;
    using TimeSynchronizationProvider =
        std::function<TimeSynchronizationStatus()>;
    using RecoveredFileHandler = std::function<bool(
        const std::string&,
        const std::string&,
        std::uint64_t,
        const protocol::ByteBuffer&
    )>;

    AuthenticationNodeRuntime(
        std::string strNodeName,
        DatagramSender fnDatagramSender,
        ControlEventHandler fnControlEventHandler,
        TimeSynchronizationProvider fnTimeSynchronizationProvider,
        RecoveredFileHandler fnRecoveredFileHandler = {}
    );
    ~AuthenticationNodeRuntime();

    AuthenticationNodeRuntime(const AuthenticationNodeRuntime&) = delete;
    AuthenticationNodeRuntime& operator=(const AuthenticationNodeRuntime&) = delete;

    protocol::NodeControlMessage msgHandleControl(
        protocol::TcpClientRole roleClient,
        const protocol::NodeControlMessage& msgMessage
    );
    protocol::NodeControlMessage msgApplyFilePayload(
        protocol::TcpClientRole roleClient,
        const std::string& strRequestId,
        std::uint64_t u64ChainId,
        workload::FileWorkload wrkFile
    );

    bool bHandleDatagram(
        const std::string& strSourceIpAddress,
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64ReceiveTimestampMilliseconds
    );
    void stop() noexcept;

    bool bHasSenderContext() const;
    bool bSenderRunning() const;
    bool bReceiverRoundRunning() const;
    bool bRoundPaused() const;
    std::optional<std::uint64_t> optSenderChainId() const;
    std::size_t nReceiverContextCount() const;
    std::size_t nDroppedReceiverQueueDatagramCount() const;
    ReceiverAuthenticationContextLookupResult resFindReceiverContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;

private:
    class Impl;
    std::unique_ptr<Impl> m_ptrImpl;
};
}

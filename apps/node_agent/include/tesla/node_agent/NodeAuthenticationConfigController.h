#pragma once

#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/protocol/NodeControlMessage.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace tesla::node_agent
{
/**
 * @brief 将认证控制消息转换为核心模型，并以事务方式更新NodeAgent运行状态。
 *
 * Sender配置先重建完整密钥链并校验K0；Receiver配置先构造和校验全部上下文，
 * 任一步失败都保留原配置。
 */
class NodeAuthenticationConfigController final
{
public:
    explicit NodeAuthenticationConfigController(std::string strNodeName);

    protocol::NodeControlMessage msgHandle(
        protocol::TcpClientRole roleClient,
        const protocol::NodeControlMessage& msgMessage
    );

    bool bHasSenderContext() const;
    std::optional<std::uint64_t> optSenderChainId() const;
    std::size_t nReceiverContextCount() const;

    core::ReceiverAuthenticationContextLookupResult resFindReceiverContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;

private:
    protocol::NodeControlMessage msgApplySenderConfig(
        const protocol::SenderAuthenticationConfigControlDetails& detConfig
    );
    protocol::NodeControlMessage msgApplyReceiverConfig(
        const protocol::ReceiverAuthenticationContextsControlDetails& detConfig
    );

    std::string                                      m_strNodeName;
    mutable std::mutex                               m_mtxSenderContext;
    std::optional<core::SenderAuthenticationContext> m_optSenderContext;
    core::ReceiverAuthenticationContextStore         m_stoReceiverContexts;
};
}

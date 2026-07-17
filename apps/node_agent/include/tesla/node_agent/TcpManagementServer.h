#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/TcpFrame.h"
#include "tesla/workload/FileWorkload.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace tesla::node_agent
{
/** @brief 提供NodeAgent的TCP角色握手、状态查询和认证配置分发。 */
class TcpManagementServer final
{
public:
    using RuntimeStateProvider = std::function<std::pair<bool, bool>()>;
    using ControlMessageHandler = std::function<protocol::NodeControlMessage(
        protocol::TcpClientRole,
        const protocol::NodeControlMessage&
    )>;
    using FilePayloadHandler = std::function<protocol::NodeControlMessage(
        protocol::TcpClientRole,
        const std::string&,
        std::uint64_t,
        workload::FileWorkload
    )>;

    TcpManagementServer(
        std::string strBindAddress,
        std::uint16_t u16Port,
        std::string strNodeName,
        RuntimeStateProvider fnStateProvider,
        ControlMessageHandler fnControlMessageHandler,
        FilePayloadHandler fnFilePayloadHandler
    );
    ~TcpManagementServer();

    TcpManagementServer(const TcpManagementServer&) = delete;
    TcpManagementServer& operator=(const TcpManagementServer&) = delete;

    void start();
    void stop() noexcept;
    bool bIsRunning() const noexcept;
    std::size_t nConnectedClientCount() const noexcept;
    void broadcastControlMessage(
        const protocol::NodeControlMessage& msgMessage
    ) const noexcept;

private:
    struct ClientConnection;

    void acceptLoop();
    void clientLoop(const std::shared_ptr<ClientConnection>& ptrClient);
    bool bHandleFrame(
        const std::shared_ptr<ClientConnection>& ptrClient,
        bool& bHelloReceived,
        protocol::TcpClientRole& roleClient,
        const protocol::TcpFrame& frmFrame
    );
    bool bSendControlMessage(
        const std::shared_ptr<ClientConnection>& ptrClient,
        const protocol::NodeControlMessage& msgMessage
    ) const noexcept;

    std::string                      m_strBindAddress;
    std::uint16_t                    m_u16Port;
    std::string                      m_strNodeName;
    RuntimeStateProvider             m_fnStateProvider;
    ControlMessageHandler            m_fnControlMessageHandler;
    FilePayloadHandler               m_fnFilePayloadHandler;
    std::atomic<bool>                m_bRunning{false};
    std::atomic<int>                 m_nListenSocket{-1};
    std::thread                      m_thrAccept;
    mutable std::mutex               m_mtxClients;
    std::vector<std::shared_ptr<ClientConnection>> m_vecClients;
    std::vector<std::thread>         m_vecClientThreads;
};
}

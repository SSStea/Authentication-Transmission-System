#pragma once

#include "tesla/core/AuthenticationNodeRuntime.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/TcpFrame.h"

#include <QHostAddress>
#include <QHash>
#include <QObject>
#include <QString>

#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>

class QTcpServer;
class QTimer;
class QUdpSocket;

/** @brief PC广播节点GUI的Qt TCP管理服务和UDP发现生命周期。 */
class PcNodeNetworkController final : public QObject
{
    Q_OBJECT

public:
    explicit PcNodeNetworkController(
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16ManagementPort = 38020,
        std::chrono::milliseconds durHeartbeatInterval = std::chrono::milliseconds(1000),
        QObject* pParent = nullptr
    );
    ~PcNodeNetworkController() override;

    PcNodeNetworkController(const PcNodeNetworkController&) = delete;
    PcNodeNetworkController& operator=(const PcNodeNetworkController&) = delete;

    bool bStart();
    void stop() noexcept;

    bool bIsRunning() const noexcept;
    bool bReceiverRunning() const noexcept;
    bool bSenderRunning() const noexcept;
    std::size_t nConnectedClientCount() const noexcept;
    const QString& strNodeName() const noexcept;
    std::uint16_t u16ManagementPort() const noexcept;

signals:
    void stateChanged();
    void logMessage(const QString& strMessage);
    /** @brief 文件上传、Sender切片或Receiver恢复状态，供文件页单独展示。 */
    void fileStatusMessage(const QString& strMessage);

private:
    struct ClientState;

    void acceptPendingClients();
    void processClientTcp(const std::shared_ptr<ClientState>& ptrClient);
    bool bHandleClientFrame(
        const std::shared_ptr<ClientState>& ptrClient,
        const tesla::protocol::TcpFrame& frmFrame
    );
    bool bHandleJson(
        const std::shared_ptr<ClientState>& ptrClient,
        const std::string& strJson
    );
    bool bIsAuthenticationControl(
        tesla::protocol::NodeControlMessageType typeMessage
    ) const noexcept;
    bool bSendNodeControl(
        const std::shared_ptr<ClientState>& ptrClient,
        const tesla::protocol::NodeControlMessage& msgMessage
    );
    void broadcastNodeControl(
        const tesla::protocol::NodeControlMessage& msgMessage
    );
    void processAuthenticationRuntimeEvent(
        tesla::protocol::NodeControlMessage msgMessage
    );
    bool bQueueAuthenticationDatagram(
        const tesla::protocol::ByteBuffer& vecDatagram
    );
    void drainAuthenticationSendQueue();
    void processAuthenticationDatagrams();
    tesla::core::TimeSynchronizationStatus stsQueryTimeSynchronization() const;
    void processDiscoveryDatagrams();
    bool bSendPresence(
        tesla::protocol::NodeDiscoveryMessageType typeMessage,
        const QString& strRequestId,
        const class QHostAddress& adrTarget,
        std::uint16_t u16TargetPort
    );
    void sendHeartbeat();
    QString strCreateNodeName() const;
    void selectLocalNetwork();

    std::uint16_t m_u16DiscoveryPort;
    std::uint16_t m_u16ManagementPort;
    std::uint16_t m_u16AuthenticationPort;
    std::chrono::milliseconds m_durHeartbeatInterval;
    QString      m_strNodeName;
    QHostAddress m_adrLocalAddress;
    int          m_nLocalInterfaceIndex;
    QUdpSocket*  m_pDiscoverySocket;
    QUdpSocket*  m_pAuthenticationSocket;
    QTcpServer*  m_pManagementServer;
    QTimer*      m_pHeartbeatTimer;
    std::atomic<bool> m_bRunning;
    bool         m_bReceiverRunning;
    bool         m_bAuthenticationSendDrainScheduled;
    bool         m_bAuthenticationSendFault;
    mutable std::mutex m_mtxAuthenticationSendQueue;
    std::deque<tesla::protocol::ByteBuffer> m_deqAuthenticationSendQueue;
    std::unique_ptr<tesla::core::AuthenticationNodeRuntime>
        m_ptrAuthenticationRuntime;
    QHash<class QTcpSocket*, std::shared_ptr<ClientState>> m_mapClients;
};

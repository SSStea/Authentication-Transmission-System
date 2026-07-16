#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/TcpFrame.h"

#include <QHash>
#include <QObject>
#include <QString>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

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
    bool bSendNodeControl(
        const std::shared_ptr<ClientState>& ptrClient,
        const tesla::protocol::NodeControlMessage& msgMessage
    );
    void processDiscoveryDatagrams();
    bool bSendPresence(
        tesla::protocol::NodeDiscoveryMessageType typeMessage,
        const QString& strRequestId,
        const class QHostAddress& adrTarget,
        std::uint16_t u16TargetPort
    );
    void sendHeartbeat();
    QString strCreateNodeName() const;

    std::uint16_t m_u16DiscoveryPort;
    std::uint16_t m_u16ManagementPort;
    std::chrono::milliseconds m_durHeartbeatInterval;
    QString      m_strNodeName;
    QUdpSocket*  m_pDiscoverySocket;
    QTcpServer*  m_pManagementServer;
    QTimer*      m_pHeartbeatTimer;
    bool         m_bRunning;
    bool         m_bSenderRunning;
    bool         m_bReceiverRunning;
    QHash<class QTcpSocket*, std::shared_ptr<ClientState>> m_mapClients;
};

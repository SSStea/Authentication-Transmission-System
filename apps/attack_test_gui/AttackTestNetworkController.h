#pragma once

#include "tesla/protocol/AttackControl.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/TcpFrame.h"

#include <QHash>
#include <QObject>
#include <QString>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>

class QHostAddress;
class QTcpServer;
class QTimer;
class QUdpSocket;

/**
 * @brief 攻击测试端的独立发现、控制服务和只读TESLA组播监听。
 *
 * 阶段5只确认连接边界和监听状态，不保存合法载荷、不修改报文且不发送攻击流量。
 */
class AttackTestNetworkController final : public QObject
{
    Q_OBJECT

public:
    explicit AttackTestNetworkController(
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16ControlPort = 38030,
        QString strMulticastAddress = QStringLiteral("239.10.10.10"),
        std::uint16_t u16MulticastPort = 39020,
        std::chrono::milliseconds durHeartbeatInterval = std::chrono::milliseconds(1000),
        QObject* pParent = nullptr
    );
    ~AttackTestNetworkController() override;

    AttackTestNetworkController(const AttackTestNetworkController&) = delete;
    AttackTestNetworkController& operator=(const AttackTestNetworkController&) = delete;

    bool bStart();
    void stop() noexcept;

    bool bIsRunning() const noexcept;
    bool bMulticastListening() const noexcept;
    bool bAttackRunning() const noexcept;
    std::size_t nConnectedClientCount() const noexcept;
    const QString& strNodeName() const noexcept;
    std::uint16_t u16ControlPort() const noexcept;

signals:
    void stateChanged();
    void logMessage(const QString& strMessage);

private:
    struct ClientState;

    void acceptPendingClients();
    void processClientTcp(const std::shared_ptr<ClientState>& ptrClient);
    bool bHandleFrame(
        const std::shared_ptr<ClientState>& ptrClient,
        const tesla::protocol::TcpFrame& frmFrame
    );
    bool bSendControl(
        const std::shared_ptr<ClientState>& ptrClient,
        const tesla::protocol::AttackControlMessage& msgMessage
    );
    void processDiscoveryDatagrams();
    bool bSendPresence(
        tesla::protocol::NodeDiscoveryMessageType typeMessage,
        const QString& strRequestId,
        const QHostAddress& adrTarget,
        std::uint16_t u16TargetPort
    );
    void sendHeartbeat();
    void drainMulticastDatagrams();
    bool bJoinMulticastGroups();
    QString strCreateNodeName() const;

    std::uint16_t m_u16DiscoveryPort;
    std::uint16_t m_u16ControlPort;
    QString       m_strMulticastAddress;
    std::uint16_t m_u16MulticastPort;
    std::chrono::milliseconds m_durHeartbeatInterval;
    QString      m_strNodeName;
    QUdpSocket*  m_pDiscoverySocket;
    QUdpSocket*  m_pMulticastSocket;
    QTcpServer*  m_pControlServer;
    QTimer*      m_pHeartbeatTimer;
    bool         m_bRunning;
    bool         m_bMulticastListening;
    bool         m_bAttackRunning;
    QHash<class QTcpSocket*, std::shared_ptr<ClientState>> m_mapClients;
};

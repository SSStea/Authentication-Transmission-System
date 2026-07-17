#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"

#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>

#include <chrono>
#include <cstdint>
#include <memory>

class QTimer;
class QUdpSocket;

/** @brief 集中管理GUI展示的节点TCP连接状态。 */
enum class ManagerConnectionState
{
    Disconnected,
    Connecting,
    Connected
};

/** @brief GUI读取的不可变节点状态快照，攻击端与正常广播节点使用同一发现列表。 */
class ManagerNodeSnapshot final
{
public:
    ManagerNodeSnapshot(
        QString strEndpointKey,
        QString strNodeName,
        QString strIpAddress,
        tesla::protocol::NodeRole roleNode,
        std::uint16_t u16ManagementPort,
        ManagerConnectionState stateConnection,
        bool bSenderRunning,
        bool bReceiverRunning,
        bool bMulticastListening,
        bool bAttackRunning,
        qint64 nHeartbeatAgeMilliseconds
    );

    const QString& strEndpointKey() const noexcept;
    const QString& strNodeName() const noexcept;
    const QString& strIpAddress() const noexcept;
    tesla::protocol::NodeRole roleNode() const noexcept;
    std::uint16_t u16ManagementPort() const noexcept;
    ManagerConnectionState stateConnection() const noexcept;
    bool bSenderRunning() const noexcept;
    bool bReceiverRunning() const noexcept;
    bool bMulticastListening() const noexcept;
    bool bAttackRunning() const noexcept;
    qint64 nHeartbeatAgeMilliseconds() const noexcept;

private:
    QString                   m_strEndpointKey;
    QString                   m_strNodeName;
    QString                   m_strIpAddress;
    tesla::protocol::NodeRole m_roleNode;
    std::uint16_t             m_u16ManagementPort;
    ManagerConnectionState    m_stateConnection;
    bool                      m_bSenderRunning;
    bool                      m_bReceiverRunning;
    bool                      m_bMulticastListening;
    bool                      m_bAttackRunning;
    qint64                    m_nHeartbeatAgeMilliseconds;
};

/**
 * @brief 管理GUI的UDP发现、心跳跟踪和MANAGER TCP连接控制。
 *
 * 一个节点端点拥有一条持久TCP连接；NodeAgent/PC节点使用节点控制协议，
 * 攻击测试端使用独立攻击控制协议，避免两类权限边界混用。
 */
class ManagerNetworkController final : public QObject
{
    Q_OBJECT

public:
    explicit ManagerNetworkController(
        std::uint16_t u16DiscoveryPort = 37020,
        std::chrono::milliseconds durOfflineTimeout = std::chrono::milliseconds(3000),
        QObject* pParent = nullptr
    );
    ~ManagerNetworkController() override;

    ManagerNetworkController(const ManagerNetworkController&) = delete;
    ManagerNetworkController& operator=(const ManagerNetworkController&) = delete;

    void start();
    void stop() noexcept;
    void scanNodes();
    void connectAll();
    void disconnectAll();
    void refreshStatus();
    bool bSendNodeControl(
        const QString& strEndpointKey,
        const tesla::protocol::NodeControlMessage& msgMessage
    );

    QVector<ManagerNodeSnapshot> vecNodeSnapshots() const;

signals:
    void nodesChanged();
    void nodeControlJsonReceived(
        const QString& strEndpointKey,
        const QString& strJson
    );
    void logMessage(const QString& strMessage);

private:
    struct EndpointState;

    void processPendingDiscoveryDatagrams(QUdpSocket* pSocket);
    void processPresence(
        const tesla::protocol::NodePresenceDetails& detPresence,
        const QString& strSourceAddress
    );
    void connectEndpoint(const std::shared_ptr<EndpointState>& ptrEndpoint);
    void processEndpointTcp(const std::shared_ptr<EndpointState>& ptrEndpoint);
    void processNodeControlFrame(
        const std::shared_ptr<EndpointState>& ptrEndpoint,
        const std::string& strJson
    );
    void processAttackControlFrame(
        const std::shared_ptr<EndpointState>& ptrEndpoint,
        const std::string& strJson
    );
    void sendHelloAndStatus(const std::shared_ptr<EndpointState>& ptrEndpoint);
    void sendStatusRequest(const std::shared_ptr<EndpointState>& ptrEndpoint);
    void checkOfflineNodes();
    QString strEndpointKey(
        tesla::protocol::NodeRole roleNode,
        const QString& strNodeName,
        std::uint16_t u16ManagementPort
    ) const;

    std::uint16_t m_u16DiscoveryPort;
    std::chrono::milliseconds m_durOfflineTimeout;
    QUdpSocket* m_pScanSocket;
    QUdpSocket* m_pHeartbeatSocket;
    QTimer*     m_pOfflineTimer;
    QHash<QString, std::shared_ptr<EndpointState>> m_mapEndpoints;
};

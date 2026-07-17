#pragma once

#include "AttackExecutionController.h"
#include "tesla/protocol/AttackControl.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/TcpFrame.h"

#include <QHash>
#include <QObject>
#include <QString>
#include <QVector>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>

class QHostAddress;
class QTcpServer;
class QTimer;
class QUdpSocket;

/**
 * @brief 认证鲁棒性测试端的独立发现、控制服务和TESLA组播监听。
 *
 * 公开上下文、模式专用计划与本地执行器均受固定内部组播和有界缓存约束。
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
    /** @brief 由测试端GUI提交模式专用计划，网络层关联当前公开上下文后发送。 */
    bool bSubmitPlan(
        tesla::protocol::AttackPlanDetails varPlanDetails,
        bool bConfirmThresholdExceeded,
        QString& strError
    );
    void stopLocalExecution(bool bEmergency) noexcept;
    tesla::protocol::AttackExecutionState stateAttackExecution() const noexcept;
    std::optional<tesla::protocol::AttackRoundContextControlDetails>
        optRoundContextSnapshot() const;
    std::optional<tesla::protocol::AttackPlanControlDetails>
        optPlanSnapshot() const;
    std::optional<tesla::protocol::AttackExecutionStatusControlDetails>
        optExecutionStatusSnapshot() const;
    QVector<AttackExecutionRecord> vecAttackRecordSnapshot() const;
    std::size_t nConnectedClientCount() const noexcept;
    const QString& strNodeName() const noexcept;
    /** @brief 返回当前优选的局域网IPv4，供实验导出记录发送源接口候选值。 */
    QString strLocalIpv4Address() const;
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
    bool bSendError(
        const std::shared_ptr<ClientState>& ptrClient,
        const std::string& strRequestId,
        const std::string& strErrorCode,
        const QString& strMessage
    );
    bool bSendExecutionStatus(const std::shared_ptr<ClientState>& ptrClient);
    void broadcastExecutionStatus(bool bForce = false);
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
    AttackExecutionController m_ctlExecution;
    QUdpSocket*  m_pDiscoverySocket;
    QUdpSocket*  m_pMulticastSocket;
    QTcpServer*  m_pControlServer;
    QTimer*      m_pHeartbeatTimer;
    bool         m_bRunning;
    bool         m_bMulticastListening;
    bool         m_bAttackRunning;
    std::uint64_t m_u64NextAttackId;
    std::uint64_t m_u64LastStatusBroadcastMilliseconds;
    QHash<class QTcpSocket*, std::shared_ptr<ClientState>> m_mapClients;
};

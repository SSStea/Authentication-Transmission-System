#pragma once

#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/TcpFrame.h"

#include <QObject>
#include <QString>

#include <chrono>
#include <cstdint>

class QTcpSocket;
class QTimer;

/** @brief 无人机监控GUI的MONITOR TCP连接状态。 */
enum class UavMonitorConnectionState
{
    Disconnected,
    Connecting,
    Connected
};

/** @brief 维护一条到指定NodeAgent或PC节点的MONITOR连接和状态查询。 */
class UavMonitorNetworkController final : public QObject
{
    Q_OBJECT

public:
    explicit UavMonitorNetworkController(
        std::chrono::milliseconds durResponseTimeout = std::chrono::milliseconds(3000),
        QObject* pParent = nullptr
    );

    void connectToNode(const QString& strHostAddress, std::uint16_t u16Port);
    void disconnectFromNode();
    void refreshStatus();

    UavMonitorConnectionState stateConnection() const noexcept;
    const QString& strHostAddress() const noexcept;
    const QString& strNodeName() const noexcept;
    bool bSenderRunning() const noexcept;
    bool bReceiverRunning() const noexcept;
    qint64 nLastResponseAgeMilliseconds() const noexcept;

signals:
    void stateChanged();
    void statusUpdated();
    void logMessage(const QString& strMessage);
    void fileStatusMessage(const QString& strMessage);

private:
    void processTcpData();
    void sendHello();
    void sendPing();
    bool bSendControl(const tesla::protocol::NodeControlMessage& msgMessage);
    void checkConnection();

    std::chrono::milliseconds m_durResponseTimeout;
    QTcpSocket*               m_pSocket;
    QTimer*                   m_pPollTimer;
    tesla::protocol::TcpFrameStreamDecoder m_decStream;
    UavMonitorConnectionState m_stateConnection;
    QString                   m_strHostAddress;
    QString                   m_strNodeName;
    bool                      m_bSenderRunning;
    bool                      m_bReceiverRunning;
    qint64                    m_nLastResponseMilliseconds;
};

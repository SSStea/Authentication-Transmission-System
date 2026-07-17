#include "UavMonitorNetworkController.h"

#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeControlMessage.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QNetworkProxy>
#include <QTcpSocket>
#include <QTimer>
#include <QUuid>

#include <algorithm>
#include <variant>

namespace
{
using namespace tesla::protocol;

ByteBuffer vecFromByteArray(const QByteArray& arrBytes)
{
    return ByteBuffer(
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData())
            + arrBytes.size()
    );
}

QByteArray arrToByteArray(const ByteBuffer& vecBytes)
{
    return QByteArray(
        reinterpret_cast<const char*>(vecBytes.data()),
        static_cast<qsizetype>(vecBytes.size())
    );
}

std::string strRequestId(const QString& strPrefix)
{
    return (
        strPrefix
        + QStringLiteral("-")
        + QUuid::createUuid().toString(QUuid::WithoutBraces)
    ).toStdString();
}
}

UavMonitorNetworkController::UavMonitorNetworkController(
    std::chrono::milliseconds durResponseTimeout,
    QObject* pParent
)
    : QObject(pParent),
      m_durResponseTimeout(durResponseTimeout),
      m_pSocket(new QTcpSocket(this)),
      m_pPollTimer(new QTimer(this)),
      m_stateConnection(UavMonitorConnectionState::Disconnected),
      m_bSenderRunning(false),
      m_bReceiverRunning(false),
      m_nLastResponseMilliseconds(0)
{
    m_pSocket->setProxy(QNetworkProxy::NoProxy);
    m_pPollTimer->setInterval(1000);

    connect(
        m_pSocket,
        &QTcpSocket::connected,
        this,
        [this]()
        {
            m_stateConnection = UavMonitorConnectionState::Connected;
            m_nLastResponseMilliseconds = QDateTime::currentMSecsSinceEpoch();
            emit logMessage(QStringLiteral("MONITOR连接已建立"));
            emit stateChanged();
            sendHello();
            refreshStatus();
            m_pPollTimer->start();
        }
    );
    connect(
        m_pSocket,
        &QTcpSocket::readyRead,
        this,
        &UavMonitorNetworkController::processTcpData
    );
    connect(
        m_pSocket,
        &QTcpSocket::disconnected,
        this,
        [this]()
        {
            m_pPollTimer->stop();
            m_decStream.reset();
            m_stateConnection = UavMonitorConnectionState::Disconnected;
            m_strNodeName.clear();
            m_bSenderRunning = false;
            m_bReceiverRunning = false;
            m_nLastResponseMilliseconds = 0;
            emit logMessage(QStringLiteral("MONITOR连接已断开"));
            emit stateChanged();
        }
    );
    connect(
        m_pSocket,
        &QTcpSocket::errorOccurred,
        this,
        [this](QAbstractSocket::SocketError)
        {
            emit logMessage(QStringLiteral("MONITOR连接错误：")
                + m_pSocket->errorString());

            // 连接建立前失败时不一定触发disconnected，主动清理状态避免界面停留在“连接中”。
            if (m_pSocket->state() == QAbstractSocket::UnconnectedState)
            {
                m_pPollTimer->stop();
                m_decStream.reset();
                m_stateConnection = UavMonitorConnectionState::Disconnected;
                m_strNodeName.clear();
                m_bSenderRunning = false;
                m_bReceiverRunning = false;
                m_nLastResponseMilliseconds = 0;
                emit stateChanged();
            }
        }
    );
    connect(
        m_pPollTimer,
        &QTimer::timeout,
        this,
        &UavMonitorNetworkController::checkConnection
    );
}

void UavMonitorNetworkController::connectToNode(
    const QString& strHostAddress,
    std::uint16_t u16Port
)
{
    if (strHostAddress.trimmed().isEmpty() || u16Port == 0)
    {
        emit logMessage(QStringLiteral("NodeAgent地址或端口无效"));
        return;
    }

    m_pSocket->abort();
    m_decStream.reset();
    m_strHostAddress = strHostAddress.trimmed();
    m_strNodeName.clear();
    m_bSenderRunning = false;
    m_bReceiverRunning = false;
    m_nLastResponseMilliseconds = 0;
    m_stateConnection = UavMonitorConnectionState::Connecting;
    emit stateChanged();

    m_pSocket->connectToHost(m_strHostAddress, u16Port);
}

void UavMonitorNetworkController::disconnectFromNode()
{
    m_pSocket->abort();
    m_pPollTimer->stop();
    m_decStream.reset();
    m_stateConnection = UavMonitorConnectionState::Disconnected;
    m_strNodeName.clear();
    m_bSenderRunning = false;
    m_bReceiverRunning = false;
    m_nLastResponseMilliseconds = 0;
    emit stateChanged();
}

void UavMonitorNetworkController::refreshStatus()
{
    bSendControl(NodeControlMessage(RequestControlDetails(
        NodeControlMessageType::StatusRequest,
        strRequestId(QStringLiteral("monitor-status"))
    )));
}

UavMonitorConnectionState
UavMonitorNetworkController::stateConnection() const noexcept
{
    return m_stateConnection;
}

const QString& UavMonitorNetworkController::strHostAddress() const noexcept
{
    return m_strHostAddress;
}

const QString& UavMonitorNetworkController::strNodeName() const noexcept
{
    return m_strNodeName;
}

bool UavMonitorNetworkController::bSenderRunning() const noexcept
{
    return m_bSenderRunning;
}

bool UavMonitorNetworkController::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

qint64 UavMonitorNetworkController::nLastResponseAgeMilliseconds() const noexcept
{
    if (m_nLastResponseMilliseconds <= 0)
    {
        return -1;
    }

    return std::max<qint64>(
        0,
        QDateTime::currentMSecsSinceEpoch() - m_nLastResponseMilliseconds
    );
}

void UavMonitorNetworkController::processTcpData()
{
    const TcpFrameStreamDecodeBatch batFrames = m_decStream.batConsume(
        vecFromByteArray(m_pSocket->readAll())
    );
    if (batFrames.optError().has_value())
    {
        emit logMessage(QStringLiteral("MONITOR TCP帧无效：")
            + QString::fromStdString(batFrames.optError()->strMessage()));
        m_pSocket->abort();
        return;
    }

    for (const TcpFrame& frmFrame : batFrames.vecFrames())
    {
        if (!std::holds_alternative<JsonControlFramePayload>(frmFrame.varPayload()))
        {
            emit logMessage(QStringLiteral("MONITOR拒绝非JSON事件帧"));
            m_pSocket->abort();
            return;
        }

        const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(
            std::get<JsonControlFramePayload>(frmFrame.varPayload()).strJson()
        );
        if (!std::holds_alternative<NodeControlMessage>(resMessage))
        {
            emit logMessage(QStringLiteral("MONITOR控制JSON解析失败"));
            continue;
        }

        m_nLastResponseMilliseconds = QDateTime::currentMSecsSinceEpoch();
        const NodeControlMessage& msgMessage =
            std::get<NodeControlMessage>(resMessage);
        if (msgMessage.typeMessage() == NodeControlMessageType::StatusResponse)
        {
            const StatusResponseControlDetails& detStatus =
                std::get<StatusResponseControlDetails>(msgMessage.varDetails());
            m_strNodeName = QString::fromStdString(detStatus.strNodeName());
            m_bSenderRunning = detStatus.bSenderRunning();
            m_bReceiverRunning = detStatus.bReceiverRunning();
            emit statusUpdated();
            emit stateChanged();
        }
        else if (msgMessage.typeMessage() == NodeControlMessageType::ErrorResponse)
        {
            const ErrorResponseControlDetails& detError =
                std::get<ErrorResponseControlDetails>(msgMessage.varDetails());
            emit logMessage(QStringLiteral("NodeAgent返回错误 %1：%2")
                .arg(
                    QString::fromStdString(detError.strErrorCode()),
                    QString::fromStdString(detError.strMessage())
                ));
        }
        else if (msgMessage.typeMessage() == NodeControlMessageType::RoundResult)
        {
            const AuthenticationRoundResultControlDetails& detResult =
                std::get<AuthenticationRoundResultControlDetails>(
                    msgMessage.varDetails()
                );
            emit logMessage(
                QStringLiteral(
                    "认证结果 %1 / chainId=%2：通过 %3/%4，失败 %5，"
                    "缺失 %6，恢复文本“%7”；%8"
                )
                    .arg(QString::fromStdString(detResult.strSenderId()))
                    .arg(detResult.u64ChainId())
                    .arg(detResult.u32AuthenticatedPacketCount())
                    .arg(detResult.u32ExpectedPacketCount())
                    .arg(detResult.u32FailedPacketCount())
                    .arg(detResult.u32MissingPacketCount())
                    .arg(QString::fromStdString(detResult.strRecoveredText()))
                    .arg(QString::fromStdString(detResult.strMessage()))
            );
        }
    }
}

void UavMonitorNetworkController::sendHello()
{
    bSendControl(NodeControlMessage(
        ClientHelloControlDetails(TcpClientRole::Monitor)
    ));
}

void UavMonitorNetworkController::sendPing()
{
    bSendControl(NodeControlMessage(RequestControlDetails(
        NodeControlMessageType::Ping,
        strRequestId(QStringLiteral("monitor-ping"))
    )));
}

bool UavMonitorNetworkController::bSendControl(
    const NodeControlMessage& msgMessage
)
{
    if (m_pSocket->state() != QAbstractSocket::ConnectedState)
    {
        return false;
    }

    const ByteBuffer vecFrame = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(NodeControlJsonCodec::strEncode(msgMessage))
    ));
    return m_pSocket->write(arrToByteArray(vecFrame))
        == static_cast<qint64>(vecFrame.size());
}

void UavMonitorNetworkController::checkConnection()
{
    if (m_stateConnection != UavMonitorConnectionState::Connected)
    {
        return;
    }

    if (nLastResponseAgeMilliseconds() >= m_durResponseTimeout.count())
    {
        emit logMessage(QStringLiteral("NodeAgent响应超时，MONITOR连接已关闭"));
        m_pSocket->abort();
        return;
    }

    sendPing();
    refreshStatus();
}

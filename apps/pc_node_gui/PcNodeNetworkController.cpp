#include "PcNodeNetworkController.h"

#include "tesla/protocol/NodeControlJsonCodec.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QHostAddress>
#include <QMetaObject>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QProcess>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>
#include <QTimer>
#include <QUdpSocket>

#include <algorithm>
#include <utility>
#include <variant>
#include <vector>

namespace
{
using namespace tesla::protocol;

const QHostAddress AUTHENTICATION_MULTICAST_ADDRESS(
    QStringLiteral("239.10.10.10")
);
constexpr std::uint16_t AUTHENTICATION_MULTICAST_PORT = 39020;
constexpr std::size_t MAX_AUTHENTICATION_SEND_QUEUE_SIZE = 8192;
constexpr std::size_t MAX_AUTHENTICATION_SEND_BATCH_SIZE = 256;

bool bIsPrivateIpv4(const QHostAddress& adrAddress)
{
    const quint32 u32Address = adrAddress.toIPv4Address();
    const quint8 u8First = static_cast<quint8>((u32Address >> 24U) & 0xFFU);
    const quint8 u8Second = static_cast<quint8>((u32Address >> 16U) & 0xFFU);
    return u8First == 10
        || (u8First == 172 && u8Second >= 16 && u8Second <= 31)
        || (u8First == 192 && u8Second == 168);
}

int nInterfaceScore(
    const QNetworkInterface& infNetwork,
    const QHostAddress& adrAddress
)
{
    int nScore = bIsPrivateIpv4(adrAddress) ? 100 : 0;
    if (infNetwork.type() == QNetworkInterface::Wifi)
    {
        nScore += 60;
    }
    else if (infNetwork.type() == QNetworkInterface::Ethernet)
    {
        nScore += 50;
    }
    else if (infNetwork.type() == QNetworkInterface::Virtual)
    {
        nScore -= 80;
    }

    const QString strInterfaceText = (
        infNetwork.name() + QStringLiteral(" ") + infNetwork.humanReadableName()
    ).toLower();
    if (strInterfaceText.contains(QStringLiteral("vmware"))
        || strInterfaceText.contains(QStringLiteral("virtual"))
        || strInterfaceText.contains(QStringLiteral("hyper-v"))
        || strInterfaceText.contains(QStringLiteral("wsl"))
        || strInterfaceText.contains(QStringLiteral("vpn"))
        || strInterfaceText.contains(QStringLiteral("tailscale"))
        || strInterfaceText.contains(QStringLiteral("zerotier")))
    {
        nScore -= 100;
    }
    return nScore;
}

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

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
}
}

struct PcNodeNetworkController::ClientState final
{
    QTcpSocket*           pSocket = nullptr;
    TcpFrameStreamDecoder decStream;
    bool                  bHelloReceived = false;
    TcpClientRole         roleClient = TcpClientRole::Monitor;
};

PcNodeNetworkController::PcNodeNetworkController(
    std::uint16_t u16DiscoveryPort,
    std::uint16_t u16ManagementPort,
    std::chrono::milliseconds durHeartbeatInterval,
    QObject* pParent
)
    : QObject(pParent),
      m_u16DiscoveryPort(u16DiscoveryPort),
      m_u16ManagementPort(u16ManagementPort),
      m_u16AuthenticationPort(AUTHENTICATION_MULTICAST_PORT),
      m_durHeartbeatInterval(durHeartbeatInterval),
      m_strNodeName(strCreateNodeName()),
      m_nLocalInterfaceIndex(0),
      m_pDiscoverySocket(new QUdpSocket(this)),
      m_pAuthenticationSocket(new QUdpSocket(this)),
      m_pManagementServer(new QTcpServer(this)),
      m_pHeartbeatTimer(new QTimer(this)),
      m_bRunning(false),
      m_bReceiverRunning(false),
      m_bAuthenticationSendDrainScheduled(false),
      m_bAuthenticationSendFault(false)
{
    selectLocalNetwork();
    m_ptrAuthenticationRuntime =
        std::make_unique<tesla::core::AuthenticationNodeRuntime>(
            m_strNodeName.toStdString(),
            [this](const ByteBuffer& vecDatagram)
            {
                return bQueueAuthenticationDatagram(vecDatagram);
            },
            [this](const NodeControlMessage& msgMessage)
            {
                // 算法结果来自工作线程，所有Qt对象访问统一排队回主线程。
                QMetaObject::invokeMethod(
                    this,
                    [this, msgMessage]()
                    {
                        processAuthenticationRuntimeEvent(msgMessage);
                    },
                    Qt::QueuedConnection
                );
            },
            [this]()
            {
                return stsQueryTimeSynchronization();
            }
        );

    m_pHeartbeatTimer->setInterval(
        static_cast<int>(m_durHeartbeatInterval.count())
    );

    connect(
        m_pDiscoverySocket,
        &QUdpSocket::readyRead,
        this,
        &PcNodeNetworkController::processDiscoveryDatagrams
    );
    connect(
        m_pAuthenticationSocket,
        &QUdpSocket::readyRead,
        this,
        &PcNodeNetworkController::processAuthenticationDatagrams
    );
    connect(
        m_pManagementServer,
        &QTcpServer::newConnection,
        this,
        &PcNodeNetworkController::acceptPendingClients
    );
    connect(
        m_pHeartbeatTimer,
        &QTimer::timeout,
        this,
        &PcNodeNetworkController::sendHeartbeat
    );
}

PcNodeNetworkController::~PcNodeNetworkController()
{
    stop();
}

bool PcNodeNetworkController::bStart()
{
    if (m_bRunning)
    {
        return true;
    }

    const bool bAuthenticationBound = m_pAuthenticationSocket->bind(
        QHostAddress::AnyIPv4,
        m_u16AuthenticationPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    const QNetworkInterface infLocal =
        QNetworkInterface::interfaceFromIndex(m_nLocalInterfaceIndex);
    const bool bAuthenticationJoined = bAuthenticationBound
        && infLocal.isValid()
        && m_pAuthenticationSocket->joinMulticastGroup(
            AUTHENTICATION_MULTICAST_ADDRESS,
            infLocal
        );
    if (!bAuthenticationJoined)
    {
        emit logMessage(QStringLiteral("PC节点认证组播加入失败：")
            + m_pAuthenticationSocket->errorString());
        m_pAuthenticationSocket->close();
        return false;
    }

    const bool bDiscoveryBound = m_pDiscoverySocket->bind(
        QHostAddress::AnyIPv4,
        m_u16DiscoveryPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    if (!bDiscoveryBound)
    {
        emit logMessage(QStringLiteral("PC节点发现端口绑定失败：")
            + m_pDiscoverySocket->errorString());
        m_pAuthenticationSocket->close();
        return false;
    }

    if (!m_pManagementServer->listen(
            QHostAddress::AnyIPv4,
            m_u16ManagementPort
        ))
    {
        emit logMessage(QStringLiteral("PC节点管理端口监听失败：")
            + m_pManagementServer->errorString());
        m_pDiscoverySocket->close();
        m_pAuthenticationSocket->close();
        return false;
    }

    m_bRunning = true;
    m_bReceiverRunning = true;
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxAuthenticationSendQueue);
        m_bAuthenticationSendFault = false;
    }
    m_pHeartbeatTimer->start();
    sendHeartbeat();
    emit logMessage(QStringLiteral("%1 已启动，管理端口 %2")
        .arg(m_strNodeName)
        .arg(m_u16ManagementPort));
    emit stateChanged();
    return true;
}

void PcNodeNetworkController::stop() noexcept
{
    m_bRunning = false;

    // 先等待认证工作线程退出，再关闭Qt Socket，避免生命周期交叉。
    if (m_ptrAuthenticationRuntime)
    {
        m_ptrAuthenticationRuntime->stop();
    }

    {
        std::lock_guard<std::mutex> lckQueue(m_mtxAuthenticationSendQueue);
        m_deqAuthenticationSendQueue.clear();
        m_bAuthenticationSendDrainScheduled = false;
        m_bAuthenticationSendFault = false;
    }

    m_bReceiverRunning = false;
    m_pHeartbeatTimer->stop();
    m_pDiscoverySocket->close();
    m_pAuthenticationSocket->close();
    m_pManagementServer->close();

    const QList<QTcpSocket*> listSockets = m_mapClients.keys();
    for (QTcpSocket* pSocket : listSockets)
    {
        pSocket->abort();
        pSocket->deleteLater();
    }
    m_mapClients.clear();
    emit stateChanged();
}

bool PcNodeNetworkController::bIsRunning() const noexcept
{
    return m_bRunning.load();
}

bool PcNodeNetworkController::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

bool PcNodeNetworkController::bSenderRunning() const noexcept
{
    return m_ptrAuthenticationRuntime
        && m_ptrAuthenticationRuntime->bSenderRunning();
}

std::size_t PcNodeNetworkController::nConnectedClientCount() const noexcept
{
    return static_cast<std::size_t>(m_mapClients.size());
}

const QString& PcNodeNetworkController::strNodeName() const noexcept
{
    return m_strNodeName;
}

std::uint16_t PcNodeNetworkController::u16ManagementPort() const noexcept
{
    return m_u16ManagementPort;
}

void PcNodeNetworkController::acceptPendingClients()
{
    constexpr qsizetype MAX_CLIENT_COUNT = 32;
    while (m_pManagementServer->hasPendingConnections())
    {
        QTcpSocket* pSocket = m_pManagementServer->nextPendingConnection();
        if (pSocket == nullptr)
        {
            continue;
        }

        if (m_mapClients.size() >= MAX_CLIENT_COUNT)
        {
            pSocket->disconnectFromHost();
            pSocket->deleteLater();
            continue;
        }

        std::shared_ptr<ClientState> ptrClient = std::make_shared<ClientState>();
        ptrClient->pSocket = pSocket;
        m_mapClients.insert(pSocket, ptrClient);

        connect(
            pSocket,
            &QTcpSocket::readyRead,
            this,
            [this, ptrClient]()
            {
                processClientTcp(ptrClient);
            }
        );
        connect(
            pSocket,
            &QTcpSocket::disconnected,
            this,
            [this, pSocket]()
            {
                m_mapClients.remove(pSocket);
                pSocket->deleteLater();
                emit stateChanged();
            }
        );

        emit logMessage(QStringLiteral("管理客户端已连接：")
            + pSocket->peerAddress().toString());
        emit stateChanged();
    }
}

void PcNodeNetworkController::processClientTcp(
    const std::shared_ptr<ClientState>& ptrClient
)
{
    const TcpFrameStreamDecodeBatch batFrames = ptrClient->decStream.batConsume(
        vecFromByteArray(ptrClient->pSocket->readAll())
    );
    if (batFrames.optError().has_value())
    {
        bSendNodeControl(
            ptrClient,
            NodeControlMessage(ErrorResponseControlDetails(
                "",
                "MALFORMED_FRAME",
                batFrames.optError()->strMessage()
            ))
        );
        ptrClient->pSocket->disconnectFromHost();
        return;
    }

    for (const TcpFrame& frmFrame : batFrames.vecFrames())
    {
        if (!bHandleClientFrame(ptrClient, frmFrame))
        {
            ptrClient->pSocket->disconnectFromHost();
            return;
        }
    }
}

bool PcNodeNetworkController::bHandleClientFrame(
    const std::shared_ptr<ClientState>& ptrClient,
    const TcpFrame& frmFrame
)
{
    if (!std::holds_alternative<JsonControlFramePayload>(frmFrame.varPayload()))
    {
        bSendNodeControl(
            ptrClient,
            NodeControlMessage(ErrorResponseControlDetails(
                "",
                "STAGE5_FILE_UNAVAILABLE",
                "PC node file upload is implemented in stage 7"
            ))
        );
        return true;
    }

    return bHandleJson(
        ptrClient,
        std::get<JsonControlFramePayload>(frmFrame.varPayload()).strJson()
    );
}

bool PcNodeNetworkController::bHandleJson(
    const std::shared_ptr<ClientState>& ptrClient,
    const std::string& strJson
)
{
    const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(strJson);
    if (!std::holds_alternative<NodeControlMessage>(resMessage))
    {
        bSendNodeControl(
            ptrClient,
            NodeControlMessage(ErrorResponseControlDetails(
                "",
                "INVALID_CONTROL_JSON",
                std::get<ProtocolDecodeError>(resMessage).strMessage()
            ))
        );
        return false;
    }

    const NodeControlMessage& msgMessage = std::get<NodeControlMessage>(resMessage);
    if (!ptrClient->bHelloReceived)
    {
        if (msgMessage.typeMessage() != NodeControlMessageType::ClientHello)
        {
            bSendNodeControl(
                ptrClient,
                NodeControlMessage(ErrorResponseControlDetails(
                    "",
                    "HELLO_REQUIRED",
                    "The first PC node control message must be CLIENT_HELLO"
                ))
            );
            return false;
        }

        ptrClient->roleClient = std::get<ClientHelloControlDetails>(
            msgMessage.varDetails()
        ).roleClient();
        ptrClient->bHelloReceived = true;
        return true;
    }

    if (msgMessage.typeMessage() == NodeControlMessageType::Ping)
    {
        const RequestControlDetails& detRequest =
            std::get<RequestControlDetails>(msgMessage.varDetails());
        return bSendNodeControl(
            ptrClient,
            NodeControlMessage(RequestControlDetails(
                NodeControlMessageType::Pong,
                detRequest.strRequestId()
            ))
        );
    }

    if (msgMessage.typeMessage() == NodeControlMessageType::StatusRequest)
    {
        const RequestControlDetails& detRequest =
            std::get<RequestControlDetails>(msgMessage.varDetails());
        return bSendNodeControl(
            ptrClient,
            NodeControlMessage(StatusResponseControlDetails(
                detRequest.strRequestId(),
                m_strNodeName.toStdString(),
                bSenderRunning(),
                m_bReceiverRunning,
                u64NowMilliseconds()
            ))
        );
    }

    if (bIsAuthenticationControl(msgMessage.typeMessage()))
    {
        if (msgMessage.typeMessage() == NodeControlMessageType::RoundStart)
        {
            std::lock_guard<std::mutex> lckQueue(
                m_mtxAuthenticationSendQueue
            );
            if (m_deqAuthenticationSendQueue.empty())
            {
                m_bAuthenticationSendFault = false;
            }
        }

        const NodeControlMessage msgResponse =
            m_ptrAuthenticationRuntime->msgHandleControl(
                ptrClient->roleClient,
                msgMessage
            );
        const bool bSent = bSendNodeControl(ptrClient, msgResponse);
        emit stateChanged();
        sendHeartbeat();
        return bSent;
    }

    return bSendNodeControl(
        ptrClient,
        NodeControlMessage(ErrorResponseControlDetails(
            "",
            ptrClient->roleClient == TcpClientRole::Monitor
                ? "MONITOR_CONTROL_FORBIDDEN"
                : "UNEXPECTED_CONTROL_DIRECTION",
            "This control message type is not accepted by the PC node"
        ))
    );
}

bool PcNodeNetworkController::bIsAuthenticationControl(
    NodeControlMessageType typeMessage
) const noexcept
{
    return typeMessage == NodeControlMessageType::SenderAuthenticationConfig
        || typeMessage == NodeControlMessageType::ReceiverAuthenticationContexts
        || typeMessage == NodeControlMessageType::TextPayloadConfig
        || typeMessage == NodeControlMessageType::RoundStart
        || typeMessage == NodeControlMessageType::RoundPause
        || typeMessage == NodeControlMessageType::RoundResume
        || typeMessage == NodeControlMessageType::RoundStop;
}

bool PcNodeNetworkController::bSendNodeControl(
    const std::shared_ptr<ClientState>& ptrClient,
    const NodeControlMessage& msgMessage
)
{
    if (ptrClient->pSocket == nullptr
        || ptrClient->pSocket->state() != QAbstractSocket::ConnectedState)
    {
        return false;
    }

    const ByteBuffer vecFrame = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(NodeControlJsonCodec::strEncode(msgMessage))
    ));
    return ptrClient->pSocket->write(arrToByteArray(vecFrame))
        == static_cast<qint64>(vecFrame.size());
}

void PcNodeNetworkController::broadcastNodeControl(
    const NodeControlMessage& msgMessage
)
{
    const QList<std::shared_ptr<ClientState>> listClients =
        m_mapClients.values();
    for (const std::shared_ptr<ClientState>& ptrClient : listClients)
    {
        if (ptrClient->bHelloReceived)
        {
            bSendNodeControl(ptrClient, msgMessage);
        }
    }
}

void PcNodeNetworkController::processAuthenticationRuntimeEvent(
    NodeControlMessage msgMessage
)
{
    if (msgMessage.typeMessage() == NodeControlMessageType::RoundResult)
    {
        const auto& detResult = std::get<
            AuthenticationRoundResultControlDetails
        >(msgMessage.varDetails());
        if (detResult.roleResult() == AuthenticationRoundResultRole::Sender
            && detResult.statusResult()
                == AuthenticationRoundResultStatus::Completed)
        {
            bool bPendingSend = false;
            bool bSendFault = false;
            {
                std::lock_guard<std::mutex> lckQueue(
                    m_mtxAuthenticationSendQueue
                );
                bPendingSend = m_bAuthenticationSendDrainScheduled
                    || !m_deqAuthenticationSendQueue.empty();
                bSendFault = m_bAuthenticationSendFault;
            }

            if (bPendingSend)
            {
                // 完成结果排在发送队列之后，防止高密度批次尚未写入Socket就误报成功。
                QMetaObject::invokeMethod(
                    this,
                    [this, msgMessage]()
                    {
                        processAuthenticationRuntimeEvent(msgMessage);
                    },
                    Qt::QueuedConnection
                );
                return;
            }

            if (bSendFault)
            {
                msgMessage = NodeControlMessage(
                    AuthenticationRoundResultControlDetails(
                        detResult.strRoundId(),
                        detResult.strSenderId(),
                        detResult.u64ChainId(),
                        detResult.roleResult(),
                        AuthenticationRoundResultStatus::
                            InvalidSchedulingOverrun,
                        detResult.u32ExpectedPacketCount(),
                        detResult.u32ReceivedPacketCount(),
                        detResult.u32AuthenticatedPacketCount(),
                        detResult.u32FailedPacketCount(),
                        detResult.u32MissingPacketCount(),
                        detResult.strRecoveredText(),
                        "Qt multicast send queue reported a socket failure"
                    )
                );
            }
        }
    }

    broadcastNodeControl(msgMessage);
    if (msgMessage.typeMessage() == NodeControlMessageType::RoundResult)
    {
        const auto& detResult = std::get<
            AuthenticationRoundResultControlDetails
        >(msgMessage.varDetails());
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
    emit stateChanged();
}

bool PcNodeNetworkController::bQueueAuthenticationDatagram(
    const ByteBuffer& vecDatagram
)
{
    bool bScheduleDrain = false;
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxAuthenticationSendQueue);
        if (!m_bRunning.load() || m_bAuthenticationSendFault
            || m_deqAuthenticationSendQueue.size()
                >= MAX_AUTHENTICATION_SEND_QUEUE_SIZE)
        {
            m_bAuthenticationSendFault =
                m_bAuthenticationSendFault
                || m_deqAuthenticationSendQueue.size()
                    >= MAX_AUTHENTICATION_SEND_QUEUE_SIZE;
            return false;
        }

        m_deqAuthenticationSendQueue.push_back(vecDatagram);
        if (!m_bAuthenticationSendDrainScheduled)
        {
            m_bAuthenticationSendDrainScheduled = true;
            bScheduleDrain = true;
        }
    }

    if (bScheduleDrain
        && !QMetaObject::invokeMethod(
            this,
            &PcNodeNetworkController::drainAuthenticationSendQueue,
            Qt::QueuedConnection
        ))
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxAuthenticationSendQueue);
        m_bAuthenticationSendDrainScheduled = false;
        m_bAuthenticationSendFault = true;
        return false;
    }

    return true;
}

void PcNodeNetworkController::drainAuthenticationSendQueue()
{
    std::vector<ByteBuffer> vecBatch;
    bool bHasMore = false;
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxAuthenticationSendQueue);
        const std::size_t nBatchSize = std::min(
            MAX_AUTHENTICATION_SEND_BATCH_SIZE,
            m_deqAuthenticationSendQueue.size()
        );
        vecBatch.reserve(nBatchSize);
        for (std::size_t nIndex = 0; nIndex < nBatchSize; ++nIndex)
        {
            vecBatch.push_back(std::move(
                m_deqAuthenticationSendQueue.front()
            ));
            m_deqAuthenticationSendQueue.pop_front();
        }

        bHasMore = !m_deqAuthenticationSendQueue.empty();
        if (!bHasMore)
        {
            m_bAuthenticationSendDrainScheduled = false;
        }
    }

    for (const ByteBuffer& vecDatagram : vecBatch)
    {
        const qint64 nSent = m_pAuthenticationSocket->writeDatagram(
            arrToByteArray(vecDatagram),
            AUTHENTICATION_MULTICAST_ADDRESS,
            m_u16AuthenticationPort
        );
        if (nSent != static_cast<qint64>(vecDatagram.size()))
        {
            std::lock_guard<std::mutex> lckQueue(
                m_mtxAuthenticationSendQueue
            );
            m_bAuthenticationSendFault = true;
            m_deqAuthenticationSendQueue.clear();
            m_bAuthenticationSendDrainScheduled = false;
            emit logMessage(QStringLiteral("认证组播发送失败：")
                + m_pAuthenticationSocket->errorString());
            return;
        }
    }

    if (bHasMore)
    {
        QMetaObject::invokeMethod(
            this,
            &PcNodeNetworkController::drainAuthenticationSendQueue,
            Qt::QueuedConnection
        );
    }
}

void PcNodeNetworkController::processAuthenticationDatagrams()
{
    while (m_pAuthenticationSocket->hasPendingDatagrams())
    {
        QHostAddress adrSource;
        QByteArray   arrDatagram;
        arrDatagram.resize(static_cast<qsizetype>(
            m_pAuthenticationSocket->pendingDatagramSize()
        ));
        const qint64 nReceived = m_pAuthenticationSocket->readDatagram(
            arrDatagram.data(),
            arrDatagram.size(),
            &adrSource
        );
        if (nReceived <= 0 || adrSource == m_adrLocalAddress)
        {
            continue;
        }

        arrDatagram.resize(static_cast<qsizetype>(nReceived));
        m_ptrAuthenticationRuntime->bHandleDatagram(
            adrSource.toString().toStdString(),
            vecFromByteArray(arrDatagram),
            u64NowMilliseconds()
        );
    }
}

tesla::core::TimeSynchronizationStatus
PcNodeNetworkController::stsQueryTimeSynchronization() const
{
    QProcess prcQuery;
#ifdef Q_OS_WIN
    prcQuery.start(
        QStringLiteral("w32tm"),
        {QStringLiteral("/query"), QStringLiteral("/status")}
    );
#else
    prcQuery.start(
        QStringLiteral("timedatectl"),
        {
            QStringLiteral("show"),
            QStringLiteral("--property=NTPSynchronized"),
            QStringLiteral("--value")
        }
    );
#endif

    if (!prcQuery.waitForStarted(1000) || !prcQuery.waitForFinished(3000)
        || prcQuery.exitStatus() != QProcess::NormalExit
        || prcQuery.exitCode() != 0)
    {
        return tesla::core::TimeSynchronizationStatus(
            false,
            0,
            "Operating-system time synchronization is unavailable"
        );
    }

#ifndef Q_OS_WIN
    if (QString::fromUtf8(prcQuery.readAllStandardOutput()).trimmed()
        != QStringLiteral("yes"))
    {
        return tesla::core::TimeSynchronizationStatus(
            false,
            0,
            "Operating-system clock is not synchronized"
        );
    }
#endif

    return tesla::core::TimeSynchronizationStatus(
        true,
        5,
        "Operating-system time synchronization is active"
    );
}

void PcNodeNetworkController::processDiscoveryDatagrams()
{
    while (m_pDiscoverySocket->hasPendingDatagrams())
    {
        QHostAddress adrSource;
        quint16      u16SourcePort = 0;
        QByteArray   arrDatagram;
        arrDatagram.resize(
            static_cast<qsizetype>(m_pDiscoverySocket->pendingDatagramSize())
        );
        const qint64 nReceived = m_pDiscoverySocket->readDatagram(
            arrDatagram.data(),
            arrDatagram.size(),
            &adrSource,
            &u16SourcePort
        );
        if (nReceived <= 0)
        {
            continue;
        }

        arrDatagram.resize(static_cast<qsizetype>(nReceived));
        const NodeDiscoveryDecodeResult resMessage =
            NodeDiscoveryJsonCodec::resDecode(arrDatagram.toStdString());
        if (!std::holds_alternative<NodeDiscoveryMessage>(resMessage))
        {
            continue;
        }

        const NodeDiscoveryMessage& msgMessage =
            std::get<NodeDiscoveryMessage>(resMessage);
        if (msgMessage.typeMessage() != NodeDiscoveryMessageType::DiscoverRequest)
        {
            continue;
        }

        bSendPresence(
            NodeDiscoveryMessageType::NodeAnnouncement,
            QString::fromStdString(std::get<DiscoveryRequestDetails>(
                msgMessage.varDetails()
            ).strRequestId()),
            adrSource,
            u16SourcePort
        );
    }
}

bool PcNodeNetworkController::bSendPresence(
    NodeDiscoveryMessageType typeMessage,
    const QString& strRequestId,
    const QHostAddress& adrTarget,
    std::uint16_t u16TargetPort
)
{
    const NodeDiscoveryMessage msgPresence(NodePresenceDetails(
        typeMessage,
        strRequestId.toStdString(),
        m_strNodeName.toStdString(),
        NodeRole::PcBroadcast,
        m_u16ManagementPort,
        bSenderRunning(),
        m_bReceiverRunning,
        u64NowMilliseconds()
    ));
    const QByteArray arrDatagram = QByteArray::fromStdString(
        NodeDiscoveryJsonCodec::strEncode(msgPresence)
    );
    return m_pDiscoverySocket->writeDatagram(
        arrDatagram,
        adrTarget,
        u16TargetPort
    ) == arrDatagram.size();
}

void PcNodeNetworkController::sendHeartbeat()
{
    if (!m_bRunning.load())
    {
        return;
    }

    QSet<QHostAddress> setTargets;
    setTargets.insert(QHostAddress::Broadcast);
    const QList<QNetworkInterface> listInterfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& infNetwork : listInterfaces)
    {
        const QNetworkInterface::InterfaceFlags flgInterface = infNetwork.flags();
        if (!flgInterface.testFlag(QNetworkInterface::IsUp)
            || !flgInterface.testFlag(QNetworkInterface::IsRunning)
            || flgInterface.testFlag(QNetworkInterface::IsLoopBack))
        {
            continue;
        }

        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            if (entAddress.ip().protocol() == QAbstractSocket::IPv4Protocol
                && !entAddress.broadcast().isNull())
            {
                setTargets.insert(entAddress.broadcast());
            }
        }
    }

    for (const QHostAddress& adrTarget : setTargets)
    {
        bSendPresence(
            NodeDiscoveryMessageType::Heartbeat,
            QString(),
            adrTarget,
            m_u16DiscoveryPort
        );
    }
}

QString PcNodeNetworkController::strCreateNodeName() const
{
    int     nBestScore = -10000;
    QString strBestAddress;
    const QList<QNetworkInterface> listInterfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& infNetwork : listInterfaces)
    {
        const QNetworkInterface::InterfaceFlags flgInterface = infNetwork.flags();
        if (!flgInterface.testFlag(QNetworkInterface::IsUp)
            || !flgInterface.testFlag(QNetworkInterface::IsRunning)
            || flgInterface.testFlag(QNetworkInterface::IsLoopBack))
        {
            continue;
        }

        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            if (entAddress.ip().protocol() != QAbstractSocket::IPv4Protocol)
            {
                continue;
            }

            const int nScore = nInterfaceScore(infNetwork, entAddress.ip());
            if (nScore > nBestScore)
            {
                nBestScore = nScore;
                strBestAddress = entAddress.ip().toString();
            }
        }
    }

    const QStringList listOctets = strBestAddress.split('.');
    if (listOctets.size() == 4)
    {
        return QStringLiteral("PC-%1").arg(listOctets.last());
    }

    return QStringLiteral("PC-LOCAL");
}

void PcNodeNetworkController::selectLocalNetwork()
{
    int nBestScore = -10000;
    const QList<QNetworkInterface> listInterfaces =
        QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& infNetwork : listInterfaces)
    {
        const QNetworkInterface::InterfaceFlags flgInterface =
            infNetwork.flags();
        if (!flgInterface.testFlag(QNetworkInterface::IsUp)
            || !flgInterface.testFlag(QNetworkInterface::IsRunning)
            || flgInterface.testFlag(QNetworkInterface::IsLoopBack))
        {
            continue;
        }

        for (const QNetworkAddressEntry& entAddress :
             infNetwork.addressEntries())
        {
            if (entAddress.ip().protocol()
                != QAbstractSocket::IPv4Protocol)
            {
                continue;
            }

            const int nScore = nInterfaceScore(infNetwork, entAddress.ip());
            if (nScore > nBestScore)
            {
                nBestScore = nScore;
                m_adrLocalAddress = entAddress.ip();
                m_nLocalInterfaceIndex = infNetwork.index();
            }
        }
    }
}

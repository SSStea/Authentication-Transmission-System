#include "PcNodeNetworkController.h"

#include "tesla/protocol/NodeControlJsonCodec.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QHostAddress>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QSet>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>

#include <utility>
#include <variant>

namespace
{
using namespace tesla::protocol;

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
      m_durHeartbeatInterval(durHeartbeatInterval),
      m_strNodeName(strCreateNodeName()),
      m_pDiscoverySocket(new QUdpSocket(this)),
      m_pManagementServer(new QTcpServer(this)),
      m_pHeartbeatTimer(new QTimer(this)),
      m_bRunning(false),
      m_bSenderRunning(false),
      m_bReceiverRunning(false)
{
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

    const bool bDiscoveryBound = m_pDiscoverySocket->bind(
        QHostAddress::AnyIPv4,
        m_u16DiscoveryPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    if (!bDiscoveryBound)
    {
        emit logMessage(QStringLiteral("PC节点发现端口绑定失败：")
            + m_pDiscoverySocket->errorString());
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
        return false;
    }

    m_bRunning = true;
    m_bReceiverRunning = true;
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
    m_bSenderRunning = false;
    m_bReceiverRunning = false;
    m_pHeartbeatTimer->stop();
    m_pDiscoverySocket->close();
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
    return m_bRunning;
}

bool PcNodeNetworkController::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

bool PcNodeNetworkController::bSenderRunning() const noexcept
{
    return m_bSenderRunning;
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
                m_bSenderRunning,
                m_bReceiverRunning,
                u64NowMilliseconds()
            ))
        );
    }

    const std::string strRequestId =
        msgMessage.typeMessage() == NodeControlMessageType::SenderAuthenticationConfig
        ? std::get<SenderAuthenticationConfigControlDetails>(
            msgMessage.varDetails()
        ).strRequestId()
        : "";
    return bSendNodeControl(
        ptrClient,
        NodeControlMessage(ErrorResponseControlDetails(
            strRequestId,
            ptrClient->roleClient == TcpClientRole::Monitor
                ? "MONITOR_CONTROL_FORBIDDEN"
                : "STAGE5_CONTROL_UNAVAILABLE",
            "PC node authentication control is implemented in stage 6"
        ))
    );
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
        m_bSenderRunning,
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
    if (!m_bRunning)
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

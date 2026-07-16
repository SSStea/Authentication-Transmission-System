#include "AttackTestNetworkController.h"

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

struct AttackTestNetworkController::ClientState final
{
    QTcpSocket*           pSocket = nullptr;
    TcpFrameStreamDecoder decStream;
    bool                  bHelloReceived = false;
};

AttackTestNetworkController::AttackTestNetworkController(
    std::uint16_t u16DiscoveryPort,
    std::uint16_t u16ControlPort,
    QString strMulticastAddress,
    std::uint16_t u16MulticastPort,
    std::chrono::milliseconds durHeartbeatInterval,
    QObject* pParent
)
    : QObject(pParent),
      m_u16DiscoveryPort(u16DiscoveryPort),
      m_u16ControlPort(u16ControlPort),
      m_strMulticastAddress(std::move(strMulticastAddress)),
      m_u16MulticastPort(u16MulticastPort),
      m_durHeartbeatInterval(durHeartbeatInterval),
      m_strNodeName(strCreateNodeName()),
      m_pDiscoverySocket(new QUdpSocket(this)),
      m_pMulticastSocket(new QUdpSocket(this)),
      m_pControlServer(new QTcpServer(this)),
      m_pHeartbeatTimer(new QTimer(this)),
      m_bRunning(false),
      m_bMulticastListening(false),
      m_bAttackRunning(false)
{
    m_pHeartbeatTimer->setInterval(
        static_cast<int>(m_durHeartbeatInterval.count())
    );

    connect(
        m_pDiscoverySocket,
        &QUdpSocket::readyRead,
        this,
        &AttackTestNetworkController::processDiscoveryDatagrams
    );
    connect(
        m_pMulticastSocket,
        &QUdpSocket::readyRead,
        this,
        &AttackTestNetworkController::drainMulticastDatagrams
    );
    connect(
        m_pControlServer,
        &QTcpServer::newConnection,
        this,
        &AttackTestNetworkController::acceptPendingClients
    );
    connect(
        m_pHeartbeatTimer,
        &QTimer::timeout,
        this,
        &AttackTestNetworkController::sendHeartbeat
    );
}

AttackTestNetworkController::~AttackTestNetworkController()
{
    stop();
}

bool AttackTestNetworkController::bStart()
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
        emit logMessage(QStringLiteral("攻击端发现端口绑定失败：")
            + m_pDiscoverySocket->errorString());
        return false;
    }

    if (!m_pControlServer->listen(QHostAddress::AnyIPv4, m_u16ControlPort))
    {
        emit logMessage(QStringLiteral("攻击端控制端口监听失败：")
            + m_pControlServer->errorString());
        m_pDiscoverySocket->close();
        return false;
    }

    const bool bMulticastBound = m_pMulticastSocket->bind(
        QHostAddress::AnyIPv4,
        m_u16MulticastPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    m_bMulticastListening = bMulticastBound && bJoinMulticastGroups();
    if (!m_bMulticastListening)
    {
        emit logMessage(QStringLiteral(
            "攻击端控制服务已启动，但TESLA组播监听不可用"
        ));
    }

    m_bRunning = true;
    m_pHeartbeatTimer->start();
    sendHeartbeat();
    emit logMessage(QStringLiteral("%1 已启动，独立控制端口 %2")
        .arg(m_strNodeName)
        .arg(m_u16ControlPort));
    emit stateChanged();
    return true;
}

void AttackTestNetworkController::stop() noexcept
{
    m_bRunning = false;
    m_bAttackRunning = false;
    m_bMulticastListening = false;
    m_pHeartbeatTimer->stop();
    m_pDiscoverySocket->close();
    m_pMulticastSocket->close();
    m_pControlServer->close();

    const QList<QTcpSocket*> listSockets = m_mapClients.keys();
    for (QTcpSocket* pSocket : listSockets)
    {
        pSocket->abort();
        pSocket->deleteLater();
    }
    m_mapClients.clear();
    emit stateChanged();
}

bool AttackTestNetworkController::bIsRunning() const noexcept
{
    return m_bRunning;
}

bool AttackTestNetworkController::bMulticastListening() const noexcept
{
    return m_bMulticastListening;
}

bool AttackTestNetworkController::bAttackRunning() const noexcept
{
    return m_bAttackRunning;
}

std::size_t AttackTestNetworkController::nConnectedClientCount() const noexcept
{
    return static_cast<std::size_t>(m_mapClients.size());
}

const QString& AttackTestNetworkController::strNodeName() const noexcept
{
    return m_strNodeName;
}

std::uint16_t AttackTestNetworkController::u16ControlPort() const noexcept
{
    return m_u16ControlPort;
}

void AttackTestNetworkController::acceptPendingClients()
{
    constexpr qsizetype MAX_CLIENT_COUNT = 8;
    while (m_pControlServer->hasPendingConnections())
    {
        QTcpSocket* pSocket = m_pControlServer->nextPendingConnection();
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

        emit logMessage(QStringLiteral("集中管理客户端已连接：")
            + pSocket->peerAddress().toString());
        emit stateChanged();
    }
}

void AttackTestNetworkController::processClientTcp(
    const std::shared_ptr<ClientState>& ptrClient
)
{
    const TcpFrameStreamDecodeBatch batFrames = ptrClient->decStream.batConsume(
        vecFromByteArray(ptrClient->pSocket->readAll())
    );
    if (batFrames.optError().has_value())
    {
        bSendControl(
            ptrClient,
            AttackControlMessage(AttackErrorControlDetails(
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
        if (!bHandleFrame(ptrClient, frmFrame))
        {
            ptrClient->pSocket->disconnectFromHost();
            return;
        }
    }
}

bool AttackTestNetworkController::bHandleFrame(
    const std::shared_ptr<ClientState>& ptrClient,
    const TcpFrame& frmFrame
)
{
    if (!std::holds_alternative<JsonControlFramePayload>(frmFrame.varPayload()))
    {
        bSendControl(
            ptrClient,
            AttackControlMessage(AttackErrorControlDetails(
                "",
                "FILE_FRAME_FORBIDDEN",
                "Attack control service accepts JSON control frames only"
            ))
        );
        return false;
    }

    const AttackControlDecodeResult resMessage = AttackControlJsonCodec::resDecode(
        std::get<JsonControlFramePayload>(frmFrame.varPayload()).strJson()
    );
    if (!std::holds_alternative<AttackControlMessage>(resMessage))
    {
        bSendControl(
            ptrClient,
            AttackControlMessage(AttackErrorControlDetails(
                "",
                "INVALID_ATTACK_CONTROL",
                std::get<ProtocolDecodeError>(resMessage).strMessage()
            ))
        );
        return false;
    }

    const AttackControlMessage& msgMessage =
        std::get<AttackControlMessage>(resMessage);
    if (!ptrClient->bHelloReceived)
    {
        if (msgMessage.typeMessage() != AttackControlMessageType::ClientHello)
        {
            bSendControl(
                ptrClient,
                AttackControlMessage(AttackErrorControlDetails(
                    "",
                    "HELLO_REQUIRED",
                    "The first attack control message must be ATTACK_CLIENT_HELLO"
                ))
            );
            return false;
        }

        ptrClient->bHelloReceived = true;
        emit logMessage(QStringLiteral("攻击控制管理握手已通过"));
        return true;
    }

    if (msgMessage.typeMessage() == AttackControlMessageType::Ping)
    {
        const AttackRequestControlDetails& detRequest =
            std::get<AttackRequestControlDetails>(msgMessage.varDetails());
        return bSendControl(
            ptrClient,
            AttackControlMessage(AttackRequestControlDetails(
                AttackControlMessageType::Pong,
                detRequest.strRequestId()
            ))
        );
    }

    if (msgMessage.typeMessage() == AttackControlMessageType::StatusRequest)
    {
        const AttackRequestControlDetails& detRequest =
            std::get<AttackRequestControlDetails>(msgMessage.varDetails());
        const bool bSent = bSendControl(
            ptrClient,
            AttackControlMessage(AttackStatusControlDetails(
                detRequest.strRequestId(),
                m_strNodeName.toStdString(),
                m_bMulticastListening,
                m_bAttackRunning,
                u64NowMilliseconds()
            ))
        );
        emit logMessage(
            bSent
                ? QStringLiteral("已返回攻击端状态")
                : QStringLiteral("攻击端状态返回失败")
        );
        return bSent;
    }

    return bSendControl(
        ptrClient,
        AttackControlMessage(AttackErrorControlDetails(
            "",
            "STAGE5_ATTACK_UNAVAILABLE",
            "Attack plans and execution are implemented in stage 10"
        ))
    );
}

bool AttackTestNetworkController::bSendControl(
    const std::shared_ptr<ClientState>& ptrClient,
    const AttackControlMessage& msgMessage
)
{
    if (ptrClient->pSocket == nullptr
        || ptrClient->pSocket->state() != QAbstractSocket::ConnectedState)
    {
        return false;
    }

    const ByteBuffer vecFrame = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(AttackControlJsonCodec::strEncode(msgMessage))
    ));
    return ptrClient->pSocket->write(arrToByteArray(vecFrame))
        == static_cast<qint64>(vecFrame.size());
}

void AttackTestNetworkController::processDiscoveryDatagrams()
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

bool AttackTestNetworkController::bSendPresence(
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
        NodeRole::Attacker,
        m_u16ControlPort,
        false,
        false,
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

void AttackTestNetworkController::sendHeartbeat()
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

void AttackTestNetworkController::drainMulticastDatagrams()
{
    while (m_pMulticastSocket->hasPendingDatagrams())
    {
        // 阶段5只维持组播监听，不保存或解析合法认证载荷，避免提前实现攻击捕获。
        QByteArray arrDatagram;
        arrDatagram.resize(
            static_cast<qsizetype>(m_pMulticastSocket->pendingDatagramSize())
        );
        m_pMulticastSocket->readDatagram(arrDatagram.data(), arrDatagram.size());
    }
}

bool AttackTestNetworkController::bJoinMulticastGroups()
{
    const QHostAddress adrGroup(m_strMulticastAddress);
    if (adrGroup.protocol() != QAbstractSocket::IPv4Protocol)
    {
        return false;
    }

    bool bJoined = false;
    const QList<QNetworkInterface> listInterfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& infNetwork : listInterfaces)
    {
        const QNetworkInterface::InterfaceFlags flgInterface = infNetwork.flags();
        if (!flgInterface.testFlag(QNetworkInterface::IsUp)
            || !flgInterface.testFlag(QNetworkInterface::IsRunning)
            || !flgInterface.testFlag(QNetworkInterface::CanMulticast))
        {
            continue;
        }

        bool bHasIpv4 = false;
        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            bHasIpv4 = bHasIpv4
                || entAddress.ip().protocol() == QAbstractSocket::IPv4Protocol;
        }

        if (bHasIpv4 && m_pMulticastSocket->joinMulticastGroup(adrGroup, infNetwork))
        {
            bJoined = true;
        }
    }

    if (!bJoined)
    {
        bJoined = m_pMulticastSocket->joinMulticastGroup(adrGroup);
    }

    if (!bJoined)
    {
        emit logMessage(QStringLiteral("加入TESLA组播组失败：")
            + m_pMulticastSocket->errorString());
    }
    return bJoined;
}

QString AttackTestNetworkController::strCreateNodeName() const
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
        return QStringLiteral("ATTACKER-%1").arg(listOctets.last());
    }

    return QStringLiteral("ATTACKER-LOCAL");
}

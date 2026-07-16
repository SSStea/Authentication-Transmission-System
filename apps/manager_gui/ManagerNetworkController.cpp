#include "ManagerNetworkController.h"

#include "tesla/protocol/AttackControl.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/TcpFrame.h"

#include <QAbstractSocket>
#include <QDateTime>
#include <QHostAddress>
#include <QNetworkAddressEntry>
#include <QNetworkInterface>
#include <QNetworkProxy>
#include <QSet>
#include <QTcpSocket>
#include <QTimer>
#include <QUdpSocket>
#include <QUuid>

#include <algorithm>
#include <utility>
#include <variant>

namespace
{
using namespace tesla::protocol;

QString strRoleName(NodeRole roleNode)
{
    switch (roleNode)
    {
    case NodeRole::PcBroadcast:
        return QStringLiteral("PC");
    case NodeRole::Uav:
        return QStringLiteral("UAV");
    case NodeRole::Attacker:
        return QStringLiteral("ATTACKER");
    }

    return QStringLiteral("UNKNOWN");
}

bool bIsPrivateIpv4(const QHostAddress& adrAddress)
{
    const quint32 u32Address = adrAddress.toIPv4Address();
    const quint8 u8First = static_cast<quint8>((u32Address >> 24U) & 0xFFU);
    const quint8 u8Second = static_cast<quint8>((u32Address >> 16U) & 0xFFU);
    return u8First == 10
        || (u8First == 172 && u8Second >= 16 && u8Second <= 31)
        || (u8First == 192 && u8Second == 168);
}

int nAddressScore(const QString& strIpAddress)
{
    const QHostAddress adrAddress(strIpAddress);
    int nScore = bIsPrivateIpv4(adrAddress) ? 100 : 0;
    if ((adrAddress.toIPv4Address() & 0xFFFF0000U) == 0xC6120000U)
    {
        nScore -= 80;
    }

    const QList<QNetworkInterface> listInterfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& infNetwork : listInterfaces)
    {
        bool bMatches = false;
        for (const QNetworkAddressEntry& entAddress : infNetwork.addressEntries())
        {
            bMatches = bMatches || entAddress.ip() == adrAddress;
        }
        if (!bMatches)
        {
            continue;
        }

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
        break;
    }

    return nScore;
}

QString strCreateRequestId(const QString& strPrefix)
{
    return strPrefix + QStringLiteral("-")
        + QUuid::createUuid().toString(QUuid::WithoutBraces);
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

bool bSendJsonFrame(QTcpSocket* pSocket, const std::string& strJson)
{
    if (pSocket == nullptr
        || pSocket->state() != QAbstractSocket::ConnectedState)
    {
        return false;
    }

    const ByteBuffer vecFrame = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(strJson)
    ));
    return pSocket->write(arrToByteArray(vecFrame))
        == static_cast<qint64>(vecFrame.size());
}
}

struct ManagerNetworkController::EndpointState final
{
    QString                strKey;
    QString                strNodeName;
    QString                strIpAddress;
    NodeRole               roleNode = NodeRole::Uav;
    std::uint16_t          u16ManagementPort = 0;
    ManagerConnectionState stateConnection = ManagerConnectionState::Disconnected;
    bool                   bSenderRunning = false;
    bool                   bReceiverRunning = false;
    bool                   bMulticastListening = false;
    bool                   bAttackRunning = false;
    qint64                 nLastPresenceMilliseconds = 0;
    int                    nAddressScore = -10000;
    QTcpSocket*            pSocket = nullptr;
    TcpFrameStreamDecoder  decStream;
};

ManagerNodeSnapshot::ManagerNodeSnapshot(
    QString strEndpointKey,
    QString strNodeName,
    QString strIpAddress,
    NodeRole roleNode,
    std::uint16_t u16ManagementPort,
    ManagerConnectionState stateConnection,
    bool bSenderRunning,
    bool bReceiverRunning,
    bool bMulticastListening,
    bool bAttackRunning,
    qint64 nHeartbeatAgeMilliseconds
)
    : m_strEndpointKey(std::move(strEndpointKey)),
      m_strNodeName(std::move(strNodeName)),
      m_strIpAddress(std::move(strIpAddress)),
      m_roleNode(roleNode),
      m_u16ManagementPort(u16ManagementPort),
      m_stateConnection(stateConnection),
      m_bSenderRunning(bSenderRunning),
      m_bReceiverRunning(bReceiverRunning),
      m_bMulticastListening(bMulticastListening),
      m_bAttackRunning(bAttackRunning),
      m_nHeartbeatAgeMilliseconds(nHeartbeatAgeMilliseconds)
{
}

const QString& ManagerNodeSnapshot::strEndpointKey() const noexcept
{
    return m_strEndpointKey;
}

const QString& ManagerNodeSnapshot::strNodeName() const noexcept
{
    return m_strNodeName;
}

const QString& ManagerNodeSnapshot::strIpAddress() const noexcept
{
    return m_strIpAddress;
}

NodeRole ManagerNodeSnapshot::roleNode() const noexcept
{
    return m_roleNode;
}

std::uint16_t ManagerNodeSnapshot::u16ManagementPort() const noexcept
{
    return m_u16ManagementPort;
}

ManagerConnectionState ManagerNodeSnapshot::stateConnection() const noexcept
{
    return m_stateConnection;
}

bool ManagerNodeSnapshot::bSenderRunning() const noexcept
{
    return m_bSenderRunning;
}

bool ManagerNodeSnapshot::bReceiverRunning() const noexcept
{
    return m_bReceiverRunning;
}

bool ManagerNodeSnapshot::bMulticastListening() const noexcept
{
    return m_bMulticastListening;
}

bool ManagerNodeSnapshot::bAttackRunning() const noexcept
{
    return m_bAttackRunning;
}

qint64 ManagerNodeSnapshot::nHeartbeatAgeMilliseconds() const noexcept
{
    return m_nHeartbeatAgeMilliseconds;
}

ManagerNetworkController::ManagerNetworkController(
    std::uint16_t u16DiscoveryPort,
    std::chrono::milliseconds durOfflineTimeout,
    QObject* pParent
)
    : QObject(pParent),
      m_u16DiscoveryPort(u16DiscoveryPort),
      m_durOfflineTimeout(durOfflineTimeout),
      m_pScanSocket(new QUdpSocket(this)),
      m_pHeartbeatSocket(new QUdpSocket(this)),
      m_pOfflineTimer(new QTimer(this))
{
    m_pOfflineTimer->setInterval(500);

    connect(
        m_pScanSocket,
        &QUdpSocket::readyRead,
        this,
        [this]()
        {
            processPendingDiscoveryDatagrams(m_pScanSocket);
        }
    );
    connect(
        m_pHeartbeatSocket,
        &QUdpSocket::readyRead,
        this,
        [this]()
        {
            processPendingDiscoveryDatagrams(m_pHeartbeatSocket);
        }
    );
    connect(
        m_pOfflineTimer,
        &QTimer::timeout,
        this,
        &ManagerNetworkController::checkOfflineNodes
    );
}

ManagerNetworkController::~ManagerNetworkController()
{
    stop();
}

void ManagerNetworkController::start()
{
    if (m_pScanSocket->state() == QAbstractSocket::BoundState)
    {
        return;
    }

    const bool bScanBound = m_pScanSocket->bind(
        QHostAddress::AnyIPv4,
        0,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );
    const bool bHeartbeatBound = m_pHeartbeatSocket->bind(
        QHostAddress::AnyIPv4,
        m_u16DiscoveryPort,
        QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint
    );

    if (!bScanBound)
    {
        emit logMessage(QStringLiteral("节点扫描Socket绑定失败：")
            + m_pScanSocket->errorString());
    }

    if (!bHeartbeatBound)
    {
        emit logMessage(QStringLiteral("心跳监听端口绑定失败：")
            + m_pHeartbeatSocket->errorString());
    }

    m_pOfflineTimer->start();
}

void ManagerNetworkController::stop() noexcept
{
    m_pOfflineTimer->stop();
    disconnectAll();
    m_pScanSocket->close();
    m_pHeartbeatSocket->close();
}

void ManagerNetworkController::scanNodes()
{
    start();
    if (m_pScanSocket->state() != QAbstractSocket::BoundState)
    {
        emit logMessage(QStringLiteral("扫描未执行：发现Socket不可用"));
        return;
    }

    const NodeDiscoveryMessage msgRequest(DiscoveryRequestDetails(
        strCreateRequestId(QStringLiteral("scan")).toStdString()
    ));
    const QByteArray arrDatagram = QByteArray::fromStdString(
        NodeDiscoveryJsonCodec::strEncode(msgRequest)
    );

    QSet<QHostAddress> setTargets;
    setTargets.insert(QHostAddress::Broadcast);
    setTargets.insert(QHostAddress::LocalHost);

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

    int nSentTargetCount = 0;
    for (const QHostAddress& adrTarget : setTargets)
    {
        if (m_pScanSocket->writeDatagram(
                arrDatagram,
                adrTarget,
                m_u16DiscoveryPort
            ) == arrDatagram.size())
        {
            ++nSentTargetCount;
        }
    }

    emit logMessage(QStringLiteral("已向 %1 个IPv4目标发送节点扫描")
        .arg(nSentTargetCount));
}

void ManagerNetworkController::connectAll()
{
    for (const std::shared_ptr<EndpointState>& ptrEndpoint : m_mapEndpoints)
    {
        connectEndpoint(ptrEndpoint);
    }
}

void ManagerNetworkController::disconnectAll()
{
    for (const std::shared_ptr<EndpointState>& ptrEndpoint : m_mapEndpoints)
    {
        if (ptrEndpoint->pSocket != nullptr)
        {
            // abort()可能同步触发disconnected回调；先解除端点关联，避免回调重入后空指针访问。
            QTcpSocket* pSocket = ptrEndpoint->pSocket;
            ptrEndpoint->pSocket = nullptr;
            pSocket->abort();
            pSocket->deleteLater();
        }

        ptrEndpoint->decStream.reset();
        ptrEndpoint->stateConnection = ManagerConnectionState::Disconnected;
    }

    if (!m_mapEndpoints.isEmpty())
    {
        emit nodesChanged();
    }
}

void ManagerNetworkController::refreshStatus()
{
    for (const std::shared_ptr<EndpointState>& ptrEndpoint : m_mapEndpoints)
    {
        if (ptrEndpoint->stateConnection == ManagerConnectionState::Connected)
        {
            sendStatusRequest(ptrEndpoint);
        }
    }
}

QVector<ManagerNodeSnapshot> ManagerNetworkController::vecNodeSnapshots() const
{
    QVector<ManagerNodeSnapshot> vecSnapshots;
    vecSnapshots.reserve(m_mapEndpoints.size());
    const qint64 nNowMilliseconds = QDateTime::currentMSecsSinceEpoch();

    for (const std::shared_ptr<EndpointState>& ptrEndpoint : m_mapEndpoints)
    {
        const qint64 nHeartbeatAge = ptrEndpoint->nLastPresenceMilliseconds > 0
            ? std::max<qint64>(
                0,
                nNowMilliseconds - ptrEndpoint->nLastPresenceMilliseconds
            )
            : -1;
        vecSnapshots.emplaceBack(
            ptrEndpoint->strKey,
            ptrEndpoint->strNodeName,
            ptrEndpoint->strIpAddress,
            ptrEndpoint->roleNode,
            ptrEndpoint->u16ManagementPort,
            ptrEndpoint->stateConnection,
            ptrEndpoint->bSenderRunning,
            ptrEndpoint->bReceiverRunning,
            ptrEndpoint->bMulticastListening,
            ptrEndpoint->bAttackRunning,
            nHeartbeatAge
        );
    }

    std::sort(
        vecSnapshots.begin(),
        vecSnapshots.end(),
        [](const ManagerNodeSnapshot& snpLeft, const ManagerNodeSnapshot& snpRight)
        {
            if (snpLeft.roleNode() != snpRight.roleNode())
            {
                return static_cast<int>(snpLeft.roleNode())
                    < static_cast<int>(snpRight.roleNode());
            }

            return snpLeft.strIpAddress() < snpRight.strIpAddress();
        }
    );
    return vecSnapshots;
}

void ManagerNetworkController::processPendingDiscoveryDatagrams(QUdpSocket* pSocket)
{
    while (pSocket->hasPendingDatagrams())
    {
        QHostAddress adrSource;
        QByteArray   arrDatagram;
        arrDatagram.resize(static_cast<qsizetype>(pSocket->pendingDatagramSize()));
        const qint64 nReceived = pSocket->readDatagram(
            arrDatagram.data(),
            arrDatagram.size(),
            &adrSource
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
        if (msgMessage.typeMessage() == NodeDiscoveryMessageType::DiscoverRequest)
        {
            continue;
        }

        processPresence(
            std::get<NodePresenceDetails>(msgMessage.varDetails()),
            adrSource.toString()
        );
    }
}

void ManagerNetworkController::processPresence(
    const NodePresenceDetails& detPresence,
    const QString& strSourceAddress
)
{
    const QString strKey = strEndpointKey(
        detPresence.roleNode(),
        QString::fromStdString(detPresence.strNodeName()),
        detPresence.u16ManagementPort()
    );
    std::shared_ptr<EndpointState> ptrEndpoint = m_mapEndpoints.value(strKey);
    const bool bNewEndpoint = !ptrEndpoint;
    if (bNewEndpoint)
    {
        ptrEndpoint = std::make_shared<EndpointState>();
        ptrEndpoint->strKey = strKey;
        ptrEndpoint->roleNode = detPresence.roleNode();
        ptrEndpoint->u16ManagementPort = detPresence.u16ManagementPort();
        m_mapEndpoints.insert(strKey, ptrEndpoint);
    }

    ptrEndpoint->strNodeName = QString::fromStdString(detPresence.strNodeName());
    const int nCandidateAddressScore = nAddressScore(strSourceAddress);
    if (ptrEndpoint->strIpAddress.isEmpty()
        || (ptrEndpoint->stateConnection == ManagerConnectionState::Disconnected
            && nCandidateAddressScore > ptrEndpoint->nAddressScore))
    {
        ptrEndpoint->strIpAddress = strSourceAddress;
        ptrEndpoint->nAddressScore = nCandidateAddressScore;
    }
    ptrEndpoint->bSenderRunning = detPresence.bSenderRunning();
    ptrEndpoint->bReceiverRunning = detPresence.bReceiverRunning();
    ptrEndpoint->nLastPresenceMilliseconds = QDateTime::currentMSecsSinceEpoch();

    if (bNewEndpoint)
    {
        emit logMessage(QStringLiteral("发现%1节点 %2 (%3:%4)")
            .arg(
                strRoleName(ptrEndpoint->roleNode),
                ptrEndpoint->strNodeName,
                ptrEndpoint->strIpAddress
            )
            .arg(ptrEndpoint->u16ManagementPort));
    }

    emit nodesChanged();
}

void ManagerNetworkController::connectEndpoint(
    const std::shared_ptr<EndpointState>& ptrEndpoint
)
{
    if (ptrEndpoint->stateConnection != ManagerConnectionState::Disconnected)
    {
        return;
    }

    QTcpSocket* pSocket = new QTcpSocket(this);
    pSocket->setProxy(QNetworkProxy::NoProxy);
    ptrEndpoint->pSocket = pSocket;
    ptrEndpoint->stateConnection = ManagerConnectionState::Connecting;
    ptrEndpoint->decStream.reset();

    connect(
        pSocket,
        &QTcpSocket::connected,
        this,
        [this, ptrEndpoint]()
        {
            ptrEndpoint->stateConnection = ManagerConnectionState::Connected;
            emit logMessage(QStringLiteral("已连接 %1 (%2:%3)")
                .arg(ptrEndpoint->strNodeName, ptrEndpoint->strIpAddress)
                .arg(ptrEndpoint->u16ManagementPort));
            emit nodesChanged();
            sendHelloAndStatus(ptrEndpoint);
        }
    );
    connect(
        pSocket,
        &QTcpSocket::readyRead,
        this,
        [this, ptrEndpoint]()
        {
            processEndpointTcp(ptrEndpoint);
        }
    );
    connect(
        pSocket,
        &QTcpSocket::disconnected,
        this,
        [this, ptrEndpoint, pSocket]()
        {
            if (ptrEndpoint->pSocket == pSocket)
            {
                ptrEndpoint->pSocket = nullptr;
                ptrEndpoint->decStream.reset();
                ptrEndpoint->stateConnection = ManagerConnectionState::Disconnected;
                emit nodesChanged();
            }
            pSocket->deleteLater();
        }
    );
    connect(
        pSocket,
        &QTcpSocket::errorOccurred,
        this,
        [this, ptrEndpoint, pSocket](QAbstractSocket::SocketError)
        {
            if (ptrEndpoint->pSocket == pSocket)
            {
                emit logMessage(QStringLiteral("连接 %1 失败：%2")
                    .arg(
                        ptrEndpoint->strNodeName,
                        pSocket->errorString()
                    ));
                ptrEndpoint->pSocket = nullptr;
                ptrEndpoint->stateConnection =
                    ManagerConnectionState::Disconnected;
                ptrEndpoint->decStream.reset();
                pSocket->abort();
                pSocket->deleteLater();
                emit nodesChanged();
            }
        }
    );

    pSocket->connectToHost(
        ptrEndpoint->strIpAddress,
        ptrEndpoint->u16ManagementPort
    );
    emit nodesChanged();
}

void ManagerNetworkController::processEndpointTcp(
    const std::shared_ptr<EndpointState>& ptrEndpoint
)
{
    if (ptrEndpoint->pSocket == nullptr)
    {
        return;
    }

    const TcpFrameStreamDecodeBatch batFrames = ptrEndpoint->decStream.batConsume(
        vecFromByteArray(ptrEndpoint->pSocket->readAll())
    );
    if (batFrames.optError().has_value())
    {
        emit logMessage(QStringLiteral("来自 %1 的TCP帧无效：%2")
            .arg(
                ptrEndpoint->strNodeName,
                QString::fromStdString(batFrames.optError()->strMessage())
            ));
        ptrEndpoint->pSocket->abort();
        return;
    }

    for (const TcpFrame& frmFrame : batFrames.vecFrames())
    {
        if (!std::holds_alternative<JsonControlFramePayload>(frmFrame.varPayload()))
        {
            emit logMessage(QStringLiteral("阶段5管理GUI拒绝非JSON响应帧"));
            ptrEndpoint->pSocket->abort();
            return;
        }

        const std::string& strJson = std::get<JsonControlFramePayload>(
            frmFrame.varPayload()
        ).strJson();
        if (ptrEndpoint->roleNode == NodeRole::Attacker)
        {
            processAttackControlFrame(ptrEndpoint, strJson);
        }
        else
        {
            processNodeControlFrame(ptrEndpoint, strJson);
        }
    }
}

void ManagerNetworkController::processNodeControlFrame(
    const std::shared_ptr<EndpointState>& ptrEndpoint,
    const std::string& strJson
)
{
    const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(strJson);
    if (!std::holds_alternative<NodeControlMessage>(resMessage))
    {
        emit logMessage(QStringLiteral("节点控制JSON解析失败"));
        return;
    }

    const NodeControlMessage& msgMessage = std::get<NodeControlMessage>(resMessage);
    if (msgMessage.typeMessage() == NodeControlMessageType::StatusResponse)
    {
        const StatusResponseControlDetails& detStatus =
            std::get<StatusResponseControlDetails>(msgMessage.varDetails());
        ptrEndpoint->strNodeName = QString::fromStdString(detStatus.strNodeName());
        ptrEndpoint->bSenderRunning = detStatus.bSenderRunning();
        ptrEndpoint->bReceiverRunning = detStatus.bReceiverRunning();
        emit nodesChanged();
    }
    else if (msgMessage.typeMessage() == NodeControlMessageType::ErrorResponse)
    {
        const ErrorResponseControlDetails& detError =
            std::get<ErrorResponseControlDetails>(msgMessage.varDetails());
        emit logMessage(QStringLiteral("节点返回错误 %1：%2")
            .arg(
                QString::fromStdString(detError.strErrorCode()),
                QString::fromStdString(detError.strMessage())
            ));
    }
}

void ManagerNetworkController::processAttackControlFrame(
    const std::shared_ptr<EndpointState>& ptrEndpoint,
    const std::string& strJson
)
{
    const AttackControlDecodeResult resMessage =
        AttackControlJsonCodec::resDecode(strJson);
    if (!std::holds_alternative<AttackControlMessage>(resMessage))
    {
        emit logMessage(QStringLiteral("攻击控制JSON解析失败"));
        return;
    }

    const AttackControlMessage& msgMessage =
        std::get<AttackControlMessage>(resMessage);
    if (msgMessage.typeMessage() == AttackControlMessageType::StatusResponse)
    {
        const AttackStatusControlDetails& detStatus =
            std::get<AttackStatusControlDetails>(msgMessage.varDetails());
        ptrEndpoint->strNodeName = QString::fromStdString(detStatus.strNodeName());
        ptrEndpoint->bMulticastListening = detStatus.bMulticastListening();
        ptrEndpoint->bAttackRunning = detStatus.bAttackRunning();
        emit nodesChanged();
    }
    else if (msgMessage.typeMessage() == AttackControlMessageType::ErrorResponse)
    {
        const AttackErrorControlDetails& detError =
            std::get<AttackErrorControlDetails>(msgMessage.varDetails());
        emit logMessage(QStringLiteral("攻击端返回错误 %1：%2")
            .arg(
                QString::fromStdString(detError.strErrorCode()),
                QString::fromStdString(detError.strMessage())
            ));
    }
}

void ManagerNetworkController::sendHelloAndStatus(
    const std::shared_ptr<EndpointState>& ptrEndpoint
)
{
    if (ptrEndpoint->roleNode == NodeRole::Attacker)
    {
        bSendJsonFrame(
            ptrEndpoint->pSocket,
            AttackControlJsonCodec::strEncode(AttackControlMessage(
                AttackClientHelloDetails("TESLA Central Manager")
            ))
        );
    }
    else
    {
        bSendJsonFrame(
            ptrEndpoint->pSocket,
            NodeControlJsonCodec::strEncode(NodeControlMessage(
                ClientHelloControlDetails(TcpClientRole::Manager)
            ))
        );
    }

    sendStatusRequest(ptrEndpoint);
}

void ManagerNetworkController::sendStatusRequest(
    const std::shared_ptr<EndpointState>& ptrEndpoint
)
{
    const std::string strRequestId = strCreateRequestId(
        QStringLiteral("status")
    ).toStdString();
    if (ptrEndpoint->roleNode == NodeRole::Attacker)
    {
        bSendJsonFrame(
            ptrEndpoint->pSocket,
            AttackControlJsonCodec::strEncode(AttackControlMessage(
                AttackRequestControlDetails(
                    AttackControlMessageType::StatusRequest,
                    strRequestId
                )
            ))
        );
    }
    else
    {
        bSendJsonFrame(
            ptrEndpoint->pSocket,
            NodeControlJsonCodec::strEncode(NodeControlMessage(
                RequestControlDetails(
                    NodeControlMessageType::StatusRequest,
                    strRequestId
                )
            ))
        );
    }
}

void ManagerNetworkController::checkOfflineNodes()
{
    const qint64 nNowMilliseconds = QDateTime::currentMSecsSinceEpoch();
    bool bChanged = false;
    for (const std::shared_ptr<EndpointState>& ptrEndpoint : m_mapEndpoints)
    {
        if (ptrEndpoint->nLastPresenceMilliseconds <= 0
            || nNowMilliseconds - ptrEndpoint->nLastPresenceMilliseconds
                < m_durOfflineTimeout.count())
        {
            continue;
        }

        if (ptrEndpoint->stateConnection != ManagerConnectionState::Disconnected)
        {
            if (ptrEndpoint->pSocket != nullptr)
            {
                ptrEndpoint->pSocket->abort();
            }

            ptrEndpoint->stateConnection = ManagerConnectionState::Disconnected;
            ptrEndpoint->bSenderRunning = false;
            ptrEndpoint->bReceiverRunning = false;
            ptrEndpoint->bMulticastListening = false;
            ptrEndpoint->bAttackRunning = false;
            bChanged = true;
        }
    }

    if (bChanged)
    {
        emit logMessage(QStringLiteral("节点心跳超时，已关闭对应TCP连接"));
        emit nodesChanged();
    }
    else if (!m_mapEndpoints.isEmpty())
    {
        emit nodesChanged();
    }
}

QString ManagerNetworkController::strEndpointKey(
    NodeRole roleNode,
    const QString& strNodeName,
    std::uint16_t u16ManagementPort
) const
{
    return QStringLiteral("%1|%2|%3")
        .arg(static_cast<int>(roleNode))
        .arg(strNodeName)
        .arg(u16ManagementPort);
}

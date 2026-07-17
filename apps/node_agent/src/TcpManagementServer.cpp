#include "tesla/node_agent/TcpManagementServer.h"

#include "tesla/core/FileUploadSession.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/TcpFrame.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <condition_variable>
#include <deque>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>

namespace tesla::node_agent
{
namespace
{
constexpr int MAX_PENDING_CONNECTIONS = 32;
constexpr std::size_t MAX_CLIENTS = 32;
constexpr std::size_t MAX_MONITOR_EVENT_QUEUE = 4096;
constexpr std::size_t ABNORMAL_SNAPSHOT_BATCH_SIZE = 64;
constexpr std::size_t MAX_METRIC_EVENT_QUEUE = 8192;
constexpr std::size_t METRIC_BATCH_SIZE = 64;
constexpr std::chrono::milliseconds METRIC_BATCH_WAIT(25);

void closeSocket(std::atomic<int>& nSocket) noexcept
{
    const int nDescriptor = nSocket.exchange(-1);
    if (nDescriptor >= 0)
    {
        shutdown(nDescriptor, SHUT_RDWR);
        close(nDescriptor);
    }
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count());
}

bool bSendAll(int nSocket, const protocol::ByteBuffer& vecBytes) noexcept
{
    std::size_t nSent = 0;
    while (nSent < vecBytes.size())
    {
        const ssize_t nResult = send(
            nSocket,
            vecBytes.data() + nSent,
            vecBytes.size() - nSent,
            MSG_NOSIGNAL
        );
        if (nResult > 0)
        {
            nSent += static_cast<std::size_t>(nResult);
            continue;
        }

        if (nResult < 0 && errno == EINTR)
        {
            continue;
        }

        return false;
    }

    return true;
}
}

// 连接对象独立持有原子Socket句柄，使服务停止线程可以且只可以关闭一次。
class TcpManagementServer::ClientConnection final
{
public:
    explicit ClientConnection(int nDescriptor)
        : m_nSocket(nDescriptor)
    {
    }

    std::atomic<int>& atmSocket() noexcept
    {
        return m_nSocket;
    }

    const std::atomic<int>& atmSocket() const noexcept
    {
        return m_nSocket;
    }

    void setRole(protocol::TcpClientRole roleClient) noexcept
    {
        m_nRole = static_cast<int>(roleClient);
        m_bHelloReceived = true;
    }

    bool bHelloReceived() const noexcept
    {
        return m_bHelloReceived.load();
    }

    protocol::TcpClientRole roleClient() const noexcept
    {
        return static_cast<protocol::TcpClientRole>(m_nRole.load());
    }

    std::mutex& mtxSend() noexcept
    {
        return m_mtxSend;
    }

    core::FileUploadSession& uplFile() noexcept
    {
        return m_uplFile;
    }

private:
    std::atomic<int> m_nSocket;
    std::atomic<bool> m_bHelloReceived{false};
    std::atomic<int>  m_nRole{
        static_cast<int>(protocol::TcpClientRole::Monitor)
    };
    std::mutex        m_mtxSend;
    core::FileUploadSession m_uplFile;
};

TcpManagementServer::TcpManagementServer(
    std::string strBindAddress,
    std::uint16_t u16Port,
    std::string strNodeName,
    RuntimeStateProvider fnStateProvider,
    ControlMessageHandler fnControlMessageHandler,
    FilePayloadHandler fnFilePayloadHandler,
    AbnormalSnapshotProvider fnAbnormalSnapshotProvider,
    MetricSnapshotProvider fnMetricSnapshotProvider
)
    : m_strBindAddress(std::move(strBindAddress)),
      m_u16Port(u16Port),
      m_strNodeName(std::move(strNodeName)),
      m_fnStateProvider(std::move(fnStateProvider)),
      m_fnControlMessageHandler(std::move(fnControlMessageHandler)),
      m_fnFilePayloadHandler(std::move(fnFilePayloadHandler)),
      m_fnAbnormalSnapshotProvider(std::move(fnAbnormalSnapshotProvider)),
      m_fnMetricSnapshotProvider(std::move(fnMetricSnapshotProvider))
{
    if (!m_fnStateProvider)
    {
        throw std::invalid_argument("TCP management server requires a state provider");
    }

    if (!m_fnControlMessageHandler)
    {
        throw std::invalid_argument(
            "TCP management server requires a control message handler"
        );
    }

    if (!m_fnFilePayloadHandler)
    {
        throw std::invalid_argument(
            "TCP management server requires a file payload handler"
        );
    }

    if (!m_fnAbnormalSnapshotProvider)
    {
        throw std::invalid_argument(
            "TCP management server requires an abnormal snapshot provider"
        );
    }

    if (!m_fnMetricSnapshotProvider)
    {
        throw std::invalid_argument(
            "TCP management server requires a metric snapshot provider"
        );
    }
}

TcpManagementServer::~TcpManagementServer()
{
    stop();
}

void TcpManagementServer::start()
{
    bool bExpected = false;
    if (!m_bRunning.compare_exchange_strong(bExpected, true))
    {
        return;
    }

    const int nSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (nSocket < 0)
    {
        m_bRunning = false;
        throw std::runtime_error("Unable to create TCP management socket");
    }
    m_nListenSocket = nSocket;

    int nReuseAddress = 1;
    setsockopt(nSocket, SOL_SOCKET, SO_REUSEADDR, &nReuseAddress, sizeof(nReuseAddress));

    sockaddr_in adrServer{};
    adrServer.sin_family = AF_INET;
    adrServer.sin_port = htons(m_u16Port);
    if (inet_pton(AF_INET, m_strBindAddress.c_str(), &adrServer.sin_addr) != 1)
    {
        stop();
        throw std::invalid_argument("TCP management bind address is not valid IPv4");
    }

    if (bind(nSocket, reinterpret_cast<const sockaddr*>(&adrServer), sizeof(adrServer)) != 0
        || listen(nSocket, MAX_PENDING_CONNECTIONS) != 0)
    {
        const std::string strError = std::strerror(errno);
        stop();
        throw std::runtime_error("Unable to bind/listen TCP management socket: " + strError);
    }

    try
    {
        m_thrAccept = std::thread(&TcpManagementServer::acceptLoop, this);
        m_thrMonitorBroadcast = std::thread(
            &TcpManagementServer::monitorBroadcastLoop,
            this
        );
    }
    catch (...)
    {
        stop();
        throw;
    }
}

void TcpManagementServer::stop() noexcept
{
    m_bRunning = false;
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxMonitorQueue);
        m_deqMonitorQueue.clear();
        m_deqMetricQueue.clear();
    }
    m_cndMonitorQueue.notify_all();
    closeSocket(m_nListenSocket);

    if (m_thrAccept.joinable())
    {
        m_thrAccept.join();
    }

    if (m_thrMonitorBroadcast.joinable())
    {
        m_thrMonitorBroadcast.join();
    }

    {
        std::lock_guard<std::mutex> lckClients(m_mtxClients);
        for (const std::shared_ptr<ClientConnection>& ptrClient : m_vecClients)
        {
            closeSocket(ptrClient->atmSocket());
        }
    }

    for (std::thread& thrClient : m_vecClientThreads)
    {
        if (thrClient.joinable())
        {
            thrClient.join();
        }
    }

    std::lock_guard<std::mutex> lckClients(m_mtxClients);
    m_vecClientThreads.clear();
    m_vecClients.clear();
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxMonitorQueue);
        m_deqMonitorQueue.clear();
        m_deqMetricQueue.clear();
    }
}

bool TcpManagementServer::bIsRunning() const noexcept
{
    return m_bRunning.load();
}

std::size_t TcpManagementServer::nConnectedClientCount() const noexcept
{
    std::lock_guard<std::mutex> lckClients(m_mtxClients);
    std::size_t nConnected = 0;
    for (const std::shared_ptr<ClientConnection>& ptrClient : m_vecClients)
    {
        if (ptrClient->atmSocket().load() >= 0)
        {
            ++nConnected;
        }
    }

    return nConnected;
}

void TcpManagementServer::broadcastControlMessage(
    const protocol::NodeControlMessage& msgMessage
) const noexcept
{
    std::vector<std::shared_ptr<ClientConnection>> vecClients;
    {
        std::lock_guard<std::mutex> lckClients(m_mtxClients);
        vecClients = m_vecClients;
    }

    for (const std::shared_ptr<ClientConnection>& ptrClient : vecClients)
    {
        if (ptrClient->bHelloReceived())
        {
            bSendControlMessage(ptrClient, msgMessage);
        }
    }
}

void TcpManagementServer::enqueueMonitorObservation(
    const protocol::AuthenticationObservation& varObservation
) noexcept
{
    try
    {
        const protocol::NodeControlMessage msgObservation = std::visit(
            [](const auto& detObservation)
            {
                return protocol::NodeControlMessage(detObservation);
            },
            varObservation
        );

        std::lock_guard<std::mutex> lckQueue(m_mtxMonitorQueue);
        if (m_deqMonitorQueue.size() >= MAX_MONITOR_EVENT_QUEUE)
        {
            if (msgObservation.typeMessage()
                    == protocol::NodeControlMessageType::PacketFailureEvent)
            {
                // 队列拥塞时优先保留结构化失败；普通报文仍受服务端快照/缓存边界约束。
                const auto itNormalPacket = std::find_if(
                    m_deqMonitorQueue.begin(),
                    m_deqMonitorQueue.end(),
                    [](const protocol::NodeControlMessage& msgQueued)
                    {
                        return msgQueued.typeMessage()
                            == protocol::NodeControlMessageType::PacketObservationEvent;
                    }
                );
                if (itNormalPacket != m_deqMonitorQueue.end())
                {
                    m_deqMonitorQueue.erase(itNormalPacket);
                    m_deqMonitorQueue.push_back(msgObservation);
                    ++m_nDroppedMonitorEventCount;
                    m_cndMonitorQueue.notify_one();
                    return;
                }
            }

            ++m_nDroppedMonitorEventCount;
            return;
        }

        m_deqMonitorQueue.push_back(msgObservation);
        m_cndMonitorQueue.notify_one();
    }
    catch (...)
    {
        ++m_nDroppedMonitorEventCount;
    }
}

void TcpManagementServer::enqueueMonitorMetric(
    const metrics::AuthenticationMetricRecord& varMetric
) noexcept
{
    try
    {
        std::lock_guard<std::mutex> lckQueue(m_mtxMonitorQueue);
        if (m_deqMetricQueue.size() >= MAX_METRIC_EVENT_QUEUE)
        {
            ++m_nDroppedMonitorEventCount;
            return;
        }

        m_deqMetricQueue.push_back(varMetric);
        m_cndMonitorQueue.notify_one();
    }
    catch (...)
    {
        ++m_nDroppedMonitorEventCount;
    }
}

void TcpManagementServer::monitorBroadcastLoop()
{
    bool bPreferMetricBatch = true;
    while (true)
    {
        std::optional<protocol::NodeControlMessage> optMessage;
        {
            std::unique_lock<std::mutex> lckQueue(m_mtxMonitorQueue);
            m_cndMonitorQueue.wait(
                lckQueue,
                [this]()
                {
                    return !m_bRunning.load()
                        || !m_deqMonitorQueue.empty()
                        || !m_deqMetricQueue.empty();
                }
            );
            if (!m_bRunning.load()
                && m_deqMonitorQueue.empty()
                && m_deqMetricQueue.empty())
            {
                return;
            }

            const bool bHasMetrics = !m_deqMetricQueue.empty();
            const bool bHasObservations = !m_deqMonitorQueue.empty();
            const bool bSendMetricBatch = bHasMetrics
                && (!bHasObservations || bPreferMetricBatch);
            if (bHasMetrics && bHasObservations)
            {
                // 两类高频队列同时有数据时交替发送，避免指标或异常观测长期饥饿。
                bPreferMetricBatch = !bPreferMetricBatch;
            }

            if (bSendMetricBatch)
            {
                // 低速指标最多等待25 ms以合并同一TCP帧；达到批量上限、停止或有观测事件时立即发送。
                if (m_deqMetricQueue.size() < METRIC_BATCH_SIZE
                    && m_deqMonitorQueue.empty()
                    && m_bRunning.load())
                {
                    m_cndMonitorQueue.wait_for(
                        lckQueue,
                        METRIC_BATCH_WAIT,
                        [this]()
                        {
                            return !m_bRunning.load()
                                || m_deqMetricQueue.size()
                                    >= METRIC_BATCH_SIZE
                                || !m_deqMonitorQueue.empty();
                        }
                    );
                    if (!m_deqMonitorQueue.empty())
                    {
                        bPreferMetricBatch = false;
                    }
                }

                std::vector<metrics::AuthenticationMetricRecord> vecMetrics;
                const std::size_t nBatchSize = std::min(
                    METRIC_BATCH_SIZE,
                    m_deqMetricQueue.size()
                );
                vecMetrics.reserve(nBatchSize);
                for (std::size_t nIndex = 0; nIndex < nBatchSize; ++nIndex)
                {
                    vecMetrics.push_back(std::move(m_deqMetricQueue.front()));
                    m_deqMetricQueue.pop_front();
                }
                optMessage.emplace(protocol::MetricEventControlDetails(
                    std::move(vecMetrics)
                ));
            }
            else
            {
                optMessage = std::move(m_deqMonitorQueue.front());
                m_deqMonitorQueue.pop_front();
            }
        }

        std::vector<std::shared_ptr<ClientConnection>> vecClients;
        {
            std::lock_guard<std::mutex> lckClients(m_mtxClients);
            vecClients = m_vecClients;
        }

        for (const std::shared_ptr<ClientConnection>& ptrClient : vecClients)
        {
            if (!ptrClient->bHelloReceived()
                || ptrClient->roleClient() != protocol::TcpClientRole::Monitor)
            {
                continue;
            }

            if (!bSendControlMessage(ptrClient, optMessage.value()))
            {
                closeSocket(ptrClient->atmSocket());
            }
        }
    }
}

void TcpManagementServer::acceptLoop()
{
    while (m_bRunning.load())
    {
        sockaddr_in adrClient{};
        socklen_t nAddressLength = sizeof(adrClient);
        const int nClientSocket = accept(
            m_nListenSocket.load(),
            reinterpret_cast<sockaddr*>(&adrClient),
            &nAddressLength
        );

        if (nClientSocket < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            break;
        }

        if (!m_bRunning.load())
        {
            close(nClientSocket);
            break;
        }

        const timeval tvSendTimeout{0, 200000};
        setsockopt(
            nClientSocket,
            SOL_SOCKET,
            SO_SNDTIMEO,
            &tvSendTimeout,
            sizeof(tvSendTimeout)
        );

        std::lock_guard<std::mutex> lckClients(m_mtxClients);
        std::size_t nConnected = 0;
        for (const std::shared_ptr<ClientConnection>& ptrClient : m_vecClients)
        {
            nConnected += ptrClient->atmSocket().load() >= 0 ? 1U : 0U;
        }

        if (nConnected >= MAX_CLIENTS)
        {
            close(nClientSocket);
            continue;
        }

        std::shared_ptr<ClientConnection> ptrClient;
        try
        {
            // 连接对象和线程都由Server持有，stop()才能先关闭Socket再完整回收线程。
            ptrClient = std::make_shared<ClientConnection>(nClientSocket);
            m_vecClients.push_back(ptrClient);
            m_vecClientThreads.emplace_back(&TcpManagementServer::clientLoop, this, ptrClient);
        }
        catch (...)
        {
            if (ptrClient)
            {
                closeSocket(ptrClient->atmSocket());
                if (!m_vecClients.empty() && m_vecClients.back() == ptrClient)
                {
                    m_vecClients.pop_back();
                }
            }
            else
            {
                close(nClientSocket);
            }
        }
    }
}

void TcpManagementServer::clientLoop(const std::shared_ptr<ClientConnection>& ptrClient)
{
    protocol::TcpFrameStreamDecoder decStream;
    bool bHelloReceived = false;
    protocol::TcpClientRole roleClient = protocol::TcpClientRole::Monitor;
    std::array<std::uint8_t, 8192> arrReceiveBuffer{};

    while (m_bRunning.load() && ptrClient->atmSocket().load() >= 0)
    {
        const ssize_t nReceived = recv(
            ptrClient->atmSocket().load(),
            arrReceiveBuffer.data(),
            arrReceiveBuffer.size(),
            0
        );
        if (nReceived == 0)
        {
            break;
        }

        if (nReceived < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }

            break;
        }

        const protocol::ByteBuffer vecReceived(
            arrReceiveBuffer.begin(),
            arrReceiveBuffer.begin() + nReceived
        );
        const protocol::TcpFrameStreamDecodeBatch batDecoded = decStream.batConsume(vecReceived);
        if (batDecoded.optError().has_value())
        {
            bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                    "",
                    "MALFORMED_FRAME",
                    batDecoded.optError()->strMessage()
                ))
            );
            break;
        }

        bool bContinue = true;
        for (const protocol::TcpFrame& frmFrame : batDecoded.vecFrames())
        {
            if (!bHandleFrame(ptrClient, bHelloReceived, roleClient, frmFrame))
            {
                bContinue = false;
                break;
            }
        }

        if (!bContinue)
        {
            break;
        }
    }

    closeSocket(ptrClient->atmSocket());
}

bool TcpManagementServer::bHandleFrame(
    const std::shared_ptr<ClientConnection>& ptrClient,
    bool& bHelloReceived,
    protocol::TcpClientRole& roleClient,
    const protocol::TcpFrame& frmFrame
)
{
    if (frmFrame.type() != protocol::TcpFrameType::JsonControl)
    {
        if (!bHelloReceived)
        {
            bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                    "",
                    "HELLO_REQUIRED",
                    "CLIENT_HELLO must be the first control message"
                ))
            );
            return false;
        }

        if (roleClient == protocol::TcpClientRole::Monitor)
        {
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                    "",
                    "MONITOR_FILE_FORBIDDEN",
                    "Monitor clients cannot upload binary file chunks"
                ))
            );
        }

        try
        {
            ptrClient->uplFile().append(std::get<protocol::FileBinaryChunk>(
                frmFrame.varPayload()
            ));
            return true;
        }
        catch (const std::exception& exError)
        {
            ptrClient->uplFile().reset();
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                    "",
                    "INVALID_FILE_UPLOAD",
                    exError.what()
                ))
            );
        }
    }

    const std::string& strJson = std::get<protocol::JsonControlFramePayload>(
        frmFrame.varPayload()
    ).strJson();
    const protocol::NodeControlDecodeResult resMessage =
        protocol::NodeControlJsonCodec::resDecode(strJson);
    if (std::holds_alternative<protocol::ProtocolDecodeError>(resMessage))
    {
        bSendControlMessage(
            ptrClient,
            protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                "",
                "MALFORMED_CONTROL",
                std::get<protocol::ProtocolDecodeError>(resMessage).strMessage()
            ))
        );
        return false;
    }

    const protocol::NodeControlMessage& msgMessage = std::get<protocol::NodeControlMessage>(
        resMessage
    );
    if (!bHelloReceived)
    {
        if (msgMessage.typeMessage() != protocol::NodeControlMessageType::ClientHello)
        {
            bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                    "",
                    "HELLO_REQUIRED",
                    "CLIENT_HELLO must be the first control message"
                ))
            );
            return false;
        }

        roleClient = std::get<protocol::ClientHelloControlDetails>(
            msgMessage.varDetails()
        ).roleClient();
        bHelloReceived = true;
        ptrClient->setRole(roleClient);
        return true;
    }

    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::FileUploadBegin)
    {
        const protocol::FileUploadBeginControlDetails& detUpload = std::get<
            protocol::FileUploadBeginControlDetails
        >(msgMessage.varDetails());
        if (roleClient == protocol::TcpClientRole::Monitor)
        {
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(
                    protocol::AuthenticationConfigAcknowledgementControlDetails(
                        detUpload.strRequestId(),
                        protocol::AuthenticationConfigTarget::FilePayload,
                        false,
                        "MONITOR_FILE_FORBIDDEN",
                        "Monitor clients cannot begin a file upload"
                    )
                )
            );
        }

        try
        {
            ptrClient->uplFile().begin(
                detUpload.strRequestId(),
                detUpload.u64ChainId(),
                detUpload.u64OriginalByteCount()
            );
            return true;
        }
        catch (const std::exception& exError)
        {
            ptrClient->uplFile().reset();
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(
                    protocol::AuthenticationConfigAcknowledgementControlDetails(
                        detUpload.strRequestId(),
                        protocol::AuthenticationConfigTarget::FilePayload,
                        false,
                        "INVALID_FILE_UPLOAD",
                        exError.what()
                    )
                )
            );
        }
    }

    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::FileUploadEnd)
    {
        const protocol::FileUploadEndControlDetails& detUpload = std::get<
            protocol::FileUploadEndControlDetails
        >(msgMessage.varDetails());
        try
        {
            workload::FileWorkload wrkFile = ptrClient->uplFile().wrkComplete(
                detUpload.strRequestId(),
                detUpload.u64ChainId(),
                detUpload.u32ChunkCount(),
                detUpload.u64TransferredByteCount()
            );
            return bSendControlMessage(
                ptrClient,
                m_fnFilePayloadHandler(
                    roleClient,
                    detUpload.strRequestId(),
                    detUpload.u64ChainId(),
                    std::move(wrkFile)
                )
            );
        }
        catch (const std::exception& exError)
        {
            ptrClient->uplFile().reset();
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(
                    protocol::AuthenticationConfigAcknowledgementControlDetails(
                        detUpload.strRequestId(),
                        protocol::AuthenticationConfigTarget::FilePayload,
                        false,
                        "INVALID_FILE_UPLOAD",
                        exError.what()
                    )
                )
            );
        }
    }

    if (msgMessage.typeMessage() == protocol::NodeControlMessageType::Ping)
    {
        const std::string& strRequestId = std::get<protocol::RequestControlDetails>(
            msgMessage.varDetails()
        ).strRequestId();
        return bSendControlMessage(
            ptrClient,
            protocol::NodeControlMessage(protocol::RequestControlDetails(
                protocol::NodeControlMessageType::Pong,
                strRequestId
            ))
        );
    }

    if (msgMessage.typeMessage() == protocol::NodeControlMessageType::StatusRequest)
    {
        const std::string& strRequestId = std::get<protocol::RequestControlDetails>(
            msgMessage.varDetails()
        ).strRequestId();
        const std::pair<bool, bool> prState = m_fnStateProvider();
        return bSendControlMessage(
            ptrClient,
            protocol::NodeControlMessage(protocol::StatusResponseControlDetails(
                strRequestId,
                m_strNodeName,
                prState.first,
                prState.second,
                u64NowMilliseconds()
            ))
        );
    }

    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::AbnormalEventSnapshotRequest)
    {
        const std::string& strRequestId = std::get<
            protocol::RequestControlDetails
        >(msgMessage.varDetails()).strRequestId();
        if (roleClient != protocol::TcpClientRole::Monitor)
        {
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(
                    protocol::ErrorResponseControlDetails(
                        strRequestId,
                        "SNAPSHOT_MONITOR_ONLY",
                        "Only MONITOR clients may request abnormal snapshots"
                    )
                )
            );
        }

        const AbnormalSnapshot prSnapshot = m_fnAbnormalSnapshotProvider();
        const auto& vecPackets = prSnapshot.first;
        const auto& vecFailures = prSnapshot.second;
        const std::size_t nBatchCount = std::max<std::size_t>(
            1,
            std::max(
                (vecPackets.size() + ABNORMAL_SNAPSHOT_BATCH_SIZE - 1U)
                    / ABNORMAL_SNAPSHOT_BATCH_SIZE,
                (vecFailures.size() + ABNORMAL_SNAPSHOT_BATCH_SIZE - 1U)
                    / ABNORMAL_SNAPSHOT_BATCH_SIZE
            )
        );
        for (std::size_t nBatchIndex = 0;
             nBatchIndex < nBatchCount;
             ++nBatchIndex)
        {
            const std::size_t nFirst =
                nBatchIndex * ABNORMAL_SNAPSHOT_BATCH_SIZE;
            const std::size_t nPacketLast = std::min(
                vecPackets.size(),
                nFirst + ABNORMAL_SNAPSHOT_BATCH_SIZE
            );
            const std::size_t nLast = std::min(
                vecFailures.size(),
                nFirst + ABNORMAL_SNAPSHOT_BATCH_SIZE
            );
            std::vector<protocol::PacketObservationControlDetails> vecPacketBatch;
            if (nFirst < nPacketLast)
            {
                vecPacketBatch.assign(
                    vecPackets.begin() + static_cast<std::ptrdiff_t>(nFirst),
                    vecPackets.begin() + static_cast<std::ptrdiff_t>(nPacketLast)
                );
            }
            std::vector<protocol::PacketFailureControlDetails> vecBatch;
            if (nFirst < nLast)
            {
                vecBatch.assign(
                    vecFailures.begin() + static_cast<std::ptrdiff_t>(nFirst),
                    vecFailures.begin() + static_cast<std::ptrdiff_t>(nLast)
                );
            }

            if (!bSendControlMessage(
                    ptrClient,
                    protocol::NodeControlMessage(
                        protocol::AbnormalEventSnapshotControlDetails(
                            strRequestId,
                            static_cast<std::uint32_t>(nBatchIndex + 1U),
                            nBatchIndex + 1U == nBatchCount,
                            std::move(vecPacketBatch),
                            std::move(vecBatch)
                        )
                    )
                ))
            {
                return false;
            }
        }
        return true;
    }

    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::MetricSnapshotRequest)
    {
        const std::string& strRequestId = std::get<
            protocol::RequestControlDetails
        >(msgMessage.varDetails()).strRequestId();
        if (roleClient != protocol::TcpClientRole::Monitor)
        {
            return bSendControlMessage(
                ptrClient,
                protocol::NodeControlMessage(
                    protocol::ErrorResponseControlDetails(
                        strRequestId,
                        "METRIC_SNAPSHOT_MONITOR_ONLY",
                        "Only MONITOR clients may request metric snapshots"
                    )
                )
            );
        }

        const std::vector<metrics::AuthenticationMetricRecord> vecMetrics =
            m_fnMetricSnapshotProvider();
        const std::size_t nBatchCount = std::max<std::size_t>(
            1,
            (vecMetrics.size() + METRIC_BATCH_SIZE - 1U) / METRIC_BATCH_SIZE
        );
        for (std::size_t nBatchIndex = 0;
             nBatchIndex < nBatchCount;
             ++nBatchIndex)
        {
            const std::size_t nFirst = nBatchIndex * METRIC_BATCH_SIZE;
            const std::size_t nLast = std::min(
                vecMetrics.size(),
                nFirst + METRIC_BATCH_SIZE
            );
            std::vector<metrics::AuthenticationMetricRecord> vecBatch;
            if (nFirst < nLast)
            {
                vecBatch.assign(
                    vecMetrics.begin() + static_cast<std::ptrdiff_t>(nFirst),
                    vecMetrics.begin() + static_cast<std::ptrdiff_t>(nLast)
                );
            }

            if (!bSendControlMessage(
                    ptrClient,
                    protocol::NodeControlMessage(
                        protocol::MetricSnapshotControlDetails(
                            strRequestId,
                            static_cast<std::uint32_t>(nBatchIndex + 1U),
                            nBatchIndex + 1U == nBatchCount,
                            std::move(vecBatch)
                        )
                    )
                ))
            {
                return false;
            }
        }
        return true;
    }

    if (msgMessage.typeMessage()
            == protocol::NodeControlMessageType::SenderAuthenticationConfig
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::ReceiverAuthenticationContexts
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::TextPayloadConfig
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::RoundStart
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::RoundPause
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::RoundResume
        || msgMessage.typeMessage()
            == protocol::NodeControlMessageType::RoundStop)
    {
        return bSendControlMessage(
            ptrClient,
            m_fnControlMessageHandler(roleClient, msgMessage)
        );
    }

    return bSendControlMessage(
        ptrClient,
        protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
            "",
            "UNEXPECTED_CONTROL_DIRECTION",
            "This control message type is not accepted from a client"
        ))
    );
}

bool TcpManagementServer::bSendControlMessage(
    const std::shared_ptr<ClientConnection>& ptrClient,
    const protocol::NodeControlMessage& msgMessage
) const noexcept
{
    try
    {
        const protocol::TcpFrame frmResponse(protocol::JsonControlFramePayload(
            protocol::NodeControlJsonCodec::strEncode(msgMessage)
        ));
        const protocol::ByteBuffer vecResponse = protocol::TcpFrameCodec::vecEncode(frmResponse);
        std::lock_guard<std::mutex> lckSend(ptrClient->mtxSend());
        const int nSocket = ptrClient->atmSocket().load();
        return nSocket >= 0 && bSendAll(nSocket, vecResponse);
    }
    catch (...)
    {
        return false;
    }
}
}

#include "tesla/node_agent/TcpManagementServer.h"

#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/TcpFrameCodec.h"
#include "tesla/protocol/TcpFrameStreamDecoder.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <stdexcept>
#include <utility>
#include <variant>

namespace tesla::node_agent
{
namespace
{
constexpr int MAX_PENDING_CONNECTIONS = 32;
constexpr std::size_t MAX_CLIENTS = 32;

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

private:
    std::atomic<int> m_nSocket;
};

TcpManagementServer::TcpManagementServer(
    std::string strBindAddress,
    std::uint16_t u16Port,
    std::string strNodeName,
    RuntimeStateProvider fnStateProvider
)
    : m_strBindAddress(std::move(strBindAddress)),
      m_u16Port(u16Port),
      m_strNodeName(std::move(strNodeName)),
      m_fnStateProvider(std::move(fnStateProvider))
{
    if (!m_fnStateProvider)
    {
        throw std::invalid_argument("TCP management server requires a state provider");
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
    closeSocket(m_nListenSocket);

    if (m_thrAccept.joinable())
    {
        m_thrAccept.join();
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

        const std::string strErrorCode = roleClient == protocol::TcpClientRole::Monitor
            ? "MONITOR_FILE_FORBIDDEN"
            : "FILE_HANDLER_NOT_READY";
        return bSendControlMessage(
            ptrClient,
            protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
                "",
                strErrorCode,
                "Binary file chunks are not handled in phase 3"
            ))
        );
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
        return true;
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
        const int nSocket = ptrClient->atmSocket().load();
        return nSocket >= 0 && bSendAll(nSocket, vecResponse);
    }
    catch (...)
    {
        return false;
    }
}
}

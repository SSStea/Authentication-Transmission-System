#include <iostream>

#if defined(__linux__)

#include "tesla/node_agent/NodeAgentConfig.h"
#include "tesla/node_agent/NodeAgentService.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeDiscoveryJsonCodec.h"
#include "tesla/protocol/TcpFrameCodec.h"
#include "tesla/protocol/TcpFrameStreamDecoder.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace
{
using namespace tesla::protocol;

class TestSocket final
{
public:
    explicit TestSocket(int nSocket)
        : m_nSocket(nSocket)
    {
        if (m_nSocket < 0)
        {
            throw std::runtime_error("Unable to create integration-test socket");
        }
    }

    ~TestSocket()
    {
        if (m_nSocket >= 0)
        {
            close(m_nSocket);
        }
    }

    TestSocket(const TestSocket&) = delete;
    TestSocket& operator=(const TestSocket&) = delete;

    int nDescriptor() const noexcept
    {
        return m_nSocket;
    }

private:
    int m_nSocket;
};

BinaryBlock arrCreateBlock(std::uint8_t u8Base)
{
    BinaryBlock arrBlock{};
    for (std::size_t nIndex = 0; nIndex < arrBlock.size(); ++nIndex)
    {
        arrBlock[nIndex] = static_cast<std::uint8_t>(u8Base + nIndex);
    }

    return arrBlock;
}

bool bSendAll(int nSocket, const ByteBuffer& vecBytes)
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
        if (nResult <= 0)
        {
            return false;
        }

        nSent += static_cast<std::size_t>(nResult);
    }

    return true;
}

int nConnectTcp(const std::string& strAddress, std::uint16_t u16Port)
{
    const int nSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (nSocket < 0)
    {
        return -1;
    }

    sockaddr_in adrTarget{};
    adrTarget.sin_family = AF_INET;
    adrTarget.sin_port = htons(u16Port);
    if (inet_pton(AF_INET, strAddress.c_str(), &adrTarget.sin_addr) != 1
        || connect(
            nSocket,
            reinterpret_cast<const sockaddr*>(&adrTarget),
            sizeof(adrTarget)
        ) != 0)
    {
        close(nSocket);
        return -1;
    }

    return nSocket;
}

ByteBuffer vecEncodeControl(const NodeControlMessage& msgMessage)
{
    return TcpFrameCodec::vecEncode(TcpFrame(JsonControlFramePayload(
        NodeControlJsonCodec::strEncode(msgMessage)
    )));
}

bool bCheckTcpNode(
    const std::string& strAddress,
    std::uint16_t u16Port,
    const std::string& strExpectedNodeName
)
{
    TestSocket sckClient(nConnectTcp(strAddress, u16Port));
    ByteBuffer vecRequest = vecEncodeControl(NodeControlMessage(
        ClientHelloControlDetails(TcpClientRole::Manager)
    ));
    const ByteBuffer vecPing = vecEncodeControl(NodeControlMessage(RequestControlDetails(
        NodeControlMessageType::Ping,
        "ping-1"
    )));
    const ByteBuffer vecStatus = vecEncodeControl(NodeControlMessage(RequestControlDetails(
        NodeControlMessageType::StatusRequest,
        "status-1"
    )));
    vecRequest.insert(vecRequest.end(), vecPing.begin(), vecPing.end());
    vecRequest.insert(vecRequest.end(), vecStatus.begin(), vecStatus.end());

    // 故意把首个长度前缀拆开，其余帧粘连发送，验证真实Socket路径的流式处理。
    const ByteBuffer vecPrefix(vecRequest.begin(), vecRequest.begin() + 2);
    const ByteBuffer vecRemainder(vecRequest.begin() + 2, vecRequest.end());
    if (!bSendAll(sckClient.nDescriptor(), vecPrefix)
        || !bSendAll(sckClient.nDescriptor(), vecRemainder))
    {
        return false;
    }

    TcpFrameStreamDecoder decResponse;
    bool bReceivedPong = false;
    bool bReceivedStatus = false;
    const auto tpDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);

    while (std::chrono::steady_clock::now() < tpDeadline
        && (!bReceivedPong || !bReceivedStatus))
    {
        pollfd pfdSocket{};
        pfdSocket.fd = sckClient.nDescriptor();
        pfdSocket.events = POLLIN;
        if (poll(&pfdSocket, 1, 200) <= 0)
        {
            continue;
        }

        std::uint8_t arrBuffer[4096]{};
        const ssize_t nReceived = recv(
            sckClient.nDescriptor(),
            arrBuffer,
            sizeof(arrBuffer),
            0
        );
        if (nReceived <= 0)
        {
            break;
        }

        const TcpFrameStreamDecodeBatch batFrames = decResponse.batConsume(ByteBuffer(
            arrBuffer,
            arrBuffer + nReceived
        ));
        if (batFrames.optError().has_value())
        {
            return false;
        }

        for (const TcpFrame& frmFrame : batFrames.vecFrames())
        {
            const std::string& strJson = std::get<JsonControlFramePayload>(
                frmFrame.varPayload()
            ).strJson();
            const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(strJson);
            if (!std::holds_alternative<NodeControlMessage>(resMessage))
            {
                return false;
            }

            const NodeControlMessage& msgMessage = std::get<NodeControlMessage>(resMessage);
            if (msgMessage.typeMessage() == NodeControlMessageType::Pong)
            {
                bReceivedPong = std::get<RequestControlDetails>(
                    msgMessage.varDetails()
                ).strRequestId() == "ping-1";
            }
            else if (msgMessage.typeMessage() == NodeControlMessageType::StatusResponse)
            {
                const StatusResponseControlDetails& detStatus =
                    std::get<StatusResponseControlDetails>(msgMessage.varDetails());
                bReceivedStatus = detStatus.strRequestId() == "status-1"
                    && detStatus.strNodeName() == strExpectedNodeName
                    && !detStatus.bSenderRunning()
                    && detStatus.bReceiverRunning();
            }
        }
    }

    return bReceivedPong && bReceivedStatus;
}

bool bDiscoverTwoNodes(
    std::uint16_t u16DiscoveryPort,
    const std::vector<std::string>& vecNodeAddresses
)
{
    TestSocket sckDiscovery(socket(AF_INET, SOCK_DGRAM, 0));
    int nBroadcastEnabled = 1;
    if (setsockopt(
            sckDiscovery.nDescriptor(),
            SOL_SOCKET,
            SO_BROADCAST,
            &nBroadcastEnabled,
            sizeof(nBroadcastEnabled)
        ) != 0)
    {
        return false;
    }

    sockaddr_in adrLocal{};
    adrLocal.sin_family = AF_INET;
    adrLocal.sin_port = 0;
    inet_pton(AF_INET, "127.0.0.1", &adrLocal.sin_addr);
    if (bind(
            sckDiscovery.nDescriptor(),
            reinterpret_cast<const sockaddr*>(&adrLocal),
            sizeof(adrLocal)
        ) != 0)
    {
        return false;
    }

    const std::string strRequest = NodeDiscoveryJsonCodec::strEncode(
        NodeDiscoveryMessage(DiscoveryRequestDetails("scan-two-nodes"))
    );
    for (const std::string& strAddress : vecNodeAddresses)
    {
        sockaddr_in adrTarget{};
        adrTarget.sin_family = AF_INET;
        adrTarget.sin_port = htons(u16DiscoveryPort);
        inet_pton(AF_INET, strAddress.c_str(), &adrTarget.sin_addr);
        if (sendto(
                sckDiscovery.nDescriptor(),
                strRequest.data(),
                strRequest.size(),
                MSG_NOSIGNAL,
                reinterpret_cast<const sockaddr*>(&adrTarget),
                sizeof(adrTarget)
            ) != static_cast<ssize_t>(strRequest.size()))
        {
            return false;
        }
    }

    std::set<std::string> setNodeNames;
    const auto tpDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < tpDeadline && setNodeNames.size() < 2)
    {
        pollfd pfdSocket{};
        pfdSocket.fd = sckDiscovery.nDescriptor();
        pfdSocket.events = POLLIN;
        if (poll(&pfdSocket, 1, 200) <= 0)
        {
            continue;
        }

        char arrBuffer[4096]{};
        const ssize_t nReceived = recvfrom(
            sckDiscovery.nDescriptor(),
            arrBuffer,
            sizeof(arrBuffer),
            0,
            nullptr,
            nullptr
        );
        if (nReceived <= 0)
        {
            continue;
        }

        const NodeDiscoveryDecodeResult resMessage = NodeDiscoveryJsonCodec::resDecode(
            std::string(arrBuffer, static_cast<std::size_t>(nReceived))
        );
        if (!std::holds_alternative<NodeDiscoveryMessage>(resMessage))
        {
            continue;
        }

        const NodeDiscoveryMessage& msgMessage = std::get<NodeDiscoveryMessage>(resMessage);
        if (msgMessage.typeMessage() != NodeDiscoveryMessageType::NodeAnnouncement)
        {
            continue;
        }

        const NodePresenceDetails& detPresence = std::get<NodePresenceDetails>(
            msgMessage.varDetails()
        );
        if (detPresence.strRequestId() == "scan-two-nodes"
            && detPresence.roleNode() == NodeRole::Uav
            && detPresence.bReceiverRunning())
        {
            setNodeNames.insert(detPresence.strNodeName());
        }
    }

    return setNodeNames == std::set<std::string>{"UAV-102", "UAV-103"};
}

bool bTestTwoNodeNetwork()
{
    const std::uint16_t u16PortBase = static_cast<std::uint16_t>(
        45000 + (getpid() % 1000) * 10
    );
    const std::uint16_t u16DiscoveryPort = u16PortBase;
    const std::uint16_t u16ManagementPort = static_cast<std::uint16_t>(u16PortBase + 1);
    const std::uint16_t u16MulticastPort = static_cast<std::uint16_t>(u16PortBase + 2);
    const std::string strMulticastAddress = "239.10.10.33";

    std::mutex mtxReceived;
    std::condition_variable cndReceived;
    bool bNodeTwoReceived = false;
    ByteBuffer vecNodeTwoDatagram;
    std::string strNodeTwoSource;

    tesla::node_agent::NodeAgentService svcNodeOne(
        tesla::node_agent::NodeAgentConfig(
            "UAV-102",
            "127.0.0.2",
            u16DiscoveryPort,
            u16ManagementPort,
            strMulticastAddress,
            u16MulticastPort,
            "127.255.255.255",
            std::chrono::milliseconds(200)
        )
    );
    tesla::node_agent::NodeAgentService svcNodeTwo(
        tesla::node_agent::NodeAgentConfig(
            "UAV-103",
            "127.0.0.3",
            u16DiscoveryPort,
            u16ManagementPort,
            strMulticastAddress,
            u16MulticastPort,
            "127.255.255.255",
            std::chrono::milliseconds(200)
        ),
        [&](const std::string& strSourceAddress, const ByteBuffer& vecDatagram)
        {
            std::lock_guard<std::mutex> lckReceived(mtxReceived);
            bNodeTwoReceived = true;
            strNodeTwoSource = strSourceAddress;
            vecNodeTwoDatagram = vecDatagram;
            cndReceived.notify_all();
        }
    );

    svcNodeOne.start();
    svcNodeTwo.start();

    bool bPassed = bDiscoverTwoNodes(
        u16DiscoveryPort,
        {"127.255.255.255"}
    );
    bPassed = bCheckTcpNode("127.0.0.2", u16ManagementPort, "UAV-102") && bPassed;
    bPassed = bCheckTcpNode("127.0.0.3", u16ManagementPort, "UAV-103") && bPassed;

    const UdpAuthenticationPacketContext ctxNative(
        UdpAuthenticationMode::Native,
        2,
        1,
        2
    );
    const ByteBuffer vecAuthenticationDatagram = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(UdpDataPacket(
            101,
            1,
            1,
            arrCreateBlock(0x10),
            std::nullopt,
            NativeUdpAuthenticationDetails(arrCreateBlock(0x80))
        )),
        ctxNative
    );
    bPassed = svcNodeOne.bSendAuthenticationDatagram(vecAuthenticationDatagram) && bPassed;

    {
        std::unique_lock<std::mutex> lckReceived(mtxReceived);
        cndReceived.wait_for(
            lckReceived,
            std::chrono::seconds(2),
            [&]()
            {
                return bNodeTwoReceived;
            }
        );
        bPassed = bNodeTwoReceived
            && strNodeTwoSource == "127.0.0.2"
            && vecNodeTwoDatagram == vecAuthenticationDatagram
            && bPassed;
    }

    svcNodeTwo.stop();
    svcNodeOne.stop();
    return bPassed;
}
}

int main()
{
    try
    {
        if (!bTestTwoNodeNetwork())
        {
            std::cerr << "FAILED: PC client and two NodeAgents did not complete phase 3 traffic."
                      << std::endl;
            return 1;
        }

        std::cout << "PC client and two NodeAgents completed TCP, discovery, and multicast traffic."
                  << std::endl;
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "FAILED: " << exError.what() << std::endl;
        return 1;
    }
}

#else

int main()
{
    std::cout << "NodeAgent network integration test runs on Linux." << std::endl;
    return 0;
}

#endif

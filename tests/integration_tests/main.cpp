#include <iostream>

#if defined(__linux__)

#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/node_agent/NodeAgentConfig.h"
#include "tesla/node_agent/NodeAgentService.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeDiscoveryMessage.h"
#include "tesla/protocol/TcpFrame.h"
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

NodeControlMessage msgExchangeControl(
    const std::string& strAddress,
    std::uint16_t u16Port,
    TcpClientRole roleClient,
    const NodeControlMessage& msgRequest
)
{
    TestSocket sckClient(nConnectTcp(strAddress, u16Port));
    ByteBuffer vecRequest = vecEncodeControl(NodeControlMessage(
        ClientHelloControlDetails(roleClient)
    ));
    const ByteBuffer vecMessage = vecEncodeControl(msgRequest);
    vecRequest.insert(vecRequest.end(), vecMessage.begin(), vecMessage.end());

    if (!bSendAll(sckClient.nDescriptor(), vecRequest))
    {
        throw std::runtime_error("Unable to send authentication control request");
    }

    TcpFrameStreamDecoder decResponse;
    const auto tpDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < tpDeadline)
    {
        pollfd pfdSocket{};
        pfdSocket.fd = sckClient.nDescriptor();
        pfdSocket.events = POLLIN;
        if (poll(&pfdSocket, 1, 200) <= 0)
        {
            continue;
        }

        std::uint8_t arrBuffer[8192]{};
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
            throw std::runtime_error("Authentication response frame is malformed");
        }

        for (const TcpFrame& frmFrame : batFrames.vecFrames())
        {
            const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(
                std::get<JsonControlFramePayload>(frmFrame.varPayload()).strJson()
            );
            if (std::holds_alternative<NodeControlMessage>(resMessage))
            {
                return std::get<NodeControlMessage>(resMessage);
            }
        }
    }

    throw std::runtime_error("Timed out waiting for authentication control response");
}

BinaryBlock arrFromDigest(const tesla::crypto::Digest& digValue)
{
    BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

BinaryBlock arrFromSeed(const tesla::crypto::ByteBuffer& vecSeed)
{
    if (vecSeed.size() != BINARY_BLOCK_SIZE)
    {
        throw std::runtime_error("Integration-test sender seed has an invalid size");
    }

    BinaryBlock arrResult{};
    std::copy(vecSeed.begin(), vecSeed.end(), arrResult.begin());
    return arrResult;
}

AuthenticationRoundControlParameters prmCreateControlRound(
    const tesla::core::AuthenticationRoundParameters& prmRound
)
{
    return AuthenticationRoundControlParameters(
        AuthenticationCryptoAlgorithm::Sha256,
        UdpAuthenticationMode::Native,
        prmRound.u32TotalPacketCount(),
        prmRound.u32PacketsPerInterval(),
        prmRound.u32DisclosureDelay(),
        prmRound.u32IntervalMilliseconds(),
        prmRound.u64StartTimestampMilliseconds(),
        prmRound.u32ChainLength()
    );
}

SenderAuthenticationConfigControlDetails detCreateSenderConfig(
    const std::string& strRequestId,
    const tesla::core::SenderAuthenticationMaterial& matMaterial,
    BinaryBlock arrCommitmentKey
)
{
    return SenderAuthenticationConfigControlDetails(
        strRequestId,
        matMaterial.strSenderId(),
        matMaterial.u64ChainId(),
        arrFromSeed(matMaterial.vecChainSeed()),
        std::move(arrCommitmentKey),
        prmCreateControlRound(matMaterial.prmRoundParameters())
    );
}

ReceiverAuthenticationContextControlDetails detCreateReceiverContext(
    const tesla::core::SenderAuthenticationMaterial& matMaterial,
    const std::string& strSenderIpAddress
)
{
    return ReceiverAuthenticationContextControlDetails(
        matMaterial.strSenderId(),
        strSenderIpAddress,
        matMaterial.u64ChainId(),
        arrFromDigest(matMaterial.digCommitmentKey()),
        prmCreateControlRound(matMaterial.prmRoundParameters())
    );
}

bool bAcknowledgementAccepted(
    const NodeControlMessage& msgMessage,
    AuthenticationConfigTarget targetConfig
)
{
    if (msgMessage.typeMessage()
        != NodeControlMessageType::AuthenticationConfigAcknowledgement)
    {
        return false;
    }

    const AuthenticationConfigAcknowledgementControlDetails& detAcknowledgement =
        std::get<AuthenticationConfigAcknowledgementControlDetails>(
            msgMessage.varDetails()
        );
    return detAcknowledgement.bAccepted()
        && detAcknowledgement.targetConfig() == targetConfig;
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

    const tesla::crypto::OpenSslSecureRandomProvider rngProvider;
    tesla::core::AuthenticationAuthority autAuthority(rngProvider);
    const tesla::core::AuthenticationRoundParameters prmRound(
        tesla::crypto::CryptoAlgorithm::Sha256,
        tesla::core::TeslaAuthenticationMode::Native,
        8,
        2,
        1,
        100,
        1'700'000'000'000ULL
    );
    const tesla::core::SenderAuthenticationMaterial matNodeOne =
        autAuthority.matIssueSenderMaterial("UAV-102", prmRound);
    const tesla::core::SenderAuthenticationMaterial matNodeTwo =
        autAuthority.matIssueSenderMaterial("UAV-103", prmRound);

    const NodeControlMessage msgNodeOneSenderResponse = msgExchangeControl(
        "127.0.0.2",
        u16ManagementPort,
        TcpClientRole::Manager,
        NodeControlMessage(detCreateSenderConfig(
            "sender-uav-102",
            matNodeOne,
            arrFromDigest(matNodeOne.digCommitmentKey())
        ))
    );
    const NodeControlMessage msgNodeTwoSenderResponse = msgExchangeControl(
        "127.0.0.3",
        u16ManagementPort,
        TcpClientRole::Manager,
        NodeControlMessage(detCreateSenderConfig(
            "sender-uav-103",
            matNodeTwo,
            arrFromDigest(matNodeTwo.digCommitmentKey())
        ))
    );
    bPassed = bAcknowledgementAccepted(
        msgNodeOneSenderResponse,
        AuthenticationConfigTarget::Sender
    ) && bPassed;
    bPassed = bAcknowledgementAccepted(
        msgNodeTwoSenderResponse,
        AuthenticationConfigTarget::Sender
    ) && bPassed;

    const NodeControlMessage msgReceiverResponse = msgExchangeControl(
        "127.0.0.3",
        u16ManagementPort,
        TcpClientRole::Manager,
        NodeControlMessage(ReceiverAuthenticationContextsControlDetails(
            "receiver-uav-103",
            {
                detCreateReceiverContext(matNodeOne, "127.0.0.2"),
                detCreateReceiverContext(matNodeTwo, "127.0.0.3")
            }
        ))
    );
    bPassed = bAcknowledgementAccepted(
        msgReceiverResponse,
        AuthenticationConfigTarget::Receiver
    ) && bPassed;
    bPassed = svcNodeOne.bHasSenderAuthenticationContext()
        && svcNodeTwo.bHasSenderAuthenticationContext()
        && svcNodeTwo.nReceiverAuthenticationContextCount() == 2
        && bPassed;

    const tesla::core::ReceiverAuthenticationContextLookupResult resKnownSender =
        svcNodeTwo.resFindReceiverAuthenticationContext(
            "127.0.0.2",
            matNodeOne.u64ChainId()
        );
    const tesla::core::ReceiverAuthenticationContextLookupResult resUnknownSource =
        svcNodeTwo.resFindReceiverAuthenticationContext(
            "127.0.0.99",
            matNodeOne.u64ChainId()
        );
    const tesla::core::ReceiverAuthenticationContextLookupResult resWrongSenderChain =
        svcNodeTwo.resFindReceiverAuthenticationContext(
            "127.0.0.2",
            matNodeTwo.u64ChainId()
        );
    bPassed = std::holds_alternative<tesla::core::ReceiverAuthenticationContext>(
        resKnownSender
    ) && std::get<tesla::core::ReceiverAuthenticationContext>(
        resKnownSender
    ).strSenderId() == "UAV-102" && bPassed;
    bPassed = std::get<tesla::core::ReceiverAuthenticationContextLookupError>(
        resUnknownSource
    ) == tesla::core::ReceiverAuthenticationContextLookupError::UnknownSourceIp
        && bPassed;
    bPassed = std::get<tesla::core::ReceiverAuthenticationContextLookupError>(
        resWrongSenderChain
    ) == tesla::core::ReceiverAuthenticationContextLookupError::UnknownChainId
        && bPassed;

    // 篡改K0的Sender配置必须被拒绝，并保留此前已经验证通过的链。
    BinaryBlock arrTamperedCommitment = arrFromDigest(matNodeOne.digCommitmentKey());
    arrTamperedCommitment[0] ^= 0x01;
    const NodeControlMessage msgInvalidSenderResponse = msgExchangeControl(
        "127.0.0.2",
        u16ManagementPort,
        TcpClientRole::Manager,
        NodeControlMessage(detCreateSenderConfig(
            "sender-uav-102-invalid",
            matNodeOne,
            arrTamperedCommitment
        ))
    );
    const AuthenticationConfigAcknowledgementControlDetails& detInvalidSenderAck =
        std::get<AuthenticationConfigAcknowledgementControlDetails>(
            msgInvalidSenderResponse.varDetails()
        );
    bPassed = !detInvalidSenderAck.bAccepted()
        && svcNodeOne.optSenderAuthenticationChainId().value_or(0)
            == matNodeOne.u64ChainId()
        && bPassed;

    // 冲突IP映射的Receiver批量更新必须整体失败，旧的两个上下文继续可查。
    const NodeControlMessage msgInvalidReceiverResponse = msgExchangeControl(
        "127.0.0.3",
        u16ManagementPort,
        TcpClientRole::Manager,
        NodeControlMessage(ReceiverAuthenticationContextsControlDetails(
            "receiver-uav-103-invalid",
            {
                detCreateReceiverContext(matNodeOne, "127.0.0.2"),
                detCreateReceiverContext(matNodeTwo, "127.0.0.2")
            }
        ))
    );
    const AuthenticationConfigAcknowledgementControlDetails& detInvalidReceiverAck =
        std::get<AuthenticationConfigAcknowledgementControlDetails>(
            msgInvalidReceiverResponse.varDetails()
        );
    bPassed = !detInvalidReceiverAck.bAccepted()
        && svcNodeTwo.nReceiverAuthenticationContextCount() == 2
        && std::holds_alternative<tesla::core::ReceiverAuthenticationContext>(
            svcNodeTwo.resFindReceiverAuthenticationContext(
                "127.0.0.2",
                matNodeOne.u64ChainId()
            )
        )
        && bPassed;

    // MONITOR即使提交合法配置也只能获得拒绝确认，不能改变Sender状态。
    const NodeControlMessage msgMonitorResponse = msgExchangeControl(
        "127.0.0.2",
        u16ManagementPort,
        TcpClientRole::Monitor,
        NodeControlMessage(detCreateSenderConfig(
            "sender-uav-102-monitor",
            matNodeOne,
            arrFromDigest(matNodeOne.digCommitmentKey())
        ))
    );
    const AuthenticationConfigAcknowledgementControlDetails& detMonitorAck =
        std::get<AuthenticationConfigAcknowledgementControlDetails>(
            msgMonitorResponse.varDetails()
        );
    bPassed = !detMonitorAck.bAccepted()
        && detMonitorAck.strErrorCode() == "MONITOR_CONFIG_FORBIDDEN"
        && svcNodeOne.optSenderAuthenticationChainId().value_or(0)
            == matNodeOne.u64ChainId()
        && bPassed;

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
            std::cerr << "FAILED: Two NodeAgents did not complete phase 4 provisioning traffic."
                      << std::endl;
            return 1;
        }

        std::cout << "Two NodeAgents completed phase 4 provisioning and network traffic."
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

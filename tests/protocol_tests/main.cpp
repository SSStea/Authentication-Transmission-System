#include "tesla/core/UdpAuthenticationInputMapper.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeDiscoveryJsonCodec.h"
#include "tesla/protocol/TcpFrameCodec.h"
#include "tesla/protocol/TcpFrameStreamDecoder.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

namespace
{
using namespace tesla::protocol;

BinaryBlock arrCreateBlock(std::uint8_t u8Base)
{
    BinaryBlock arrBlock{};
    for (std::size_t nIndex = 0; nIndex < arrBlock.size(); ++nIndex)
    {
        arrBlock[nIndex] = static_cast<std::uint8_t>(u8Base + nIndex);
    }

    return arrBlock;
}

bool bExpect(bool bCondition, const std::string& strDescription)
{
    if (!bCondition)
    {
        std::cerr << "FAILED: " << strDescription << std::endl;
        return false;
    }

    return true;
}

bool bTestTcpFrameRoundTrips()
{
    // 同时覆盖可读JSON控制帧和包含0字节的原始文件分块，防止错误采用字符串传输文件。
    const TcpFrame frmJson(JsonControlFramePayload(R"({"type":"PING","requestId":"42"})"));
    const ByteBuffer vecJson = TcpFrameCodec::vecEncode(frmJson);
    TcpFrameDecodeResult resJson = TcpFrameCodec::resDecode(vecJson);

    bool bPassed = bExpect(
        std::holds_alternative<TcpFrame>(resJson),
        "JSON TCP frame round trip"
    );
    if (std::holds_alternative<TcpFrame>(resJson))
    {
        bPassed = bExpect(
            std::get<JsonControlFramePayload>(
                std::get<TcpFrame>(resJson).varPayload()
            ).strJson() == R"({"type":"PING","requestId":"42"})",
            "JSON TCP payload is unchanged"
        ) && bPassed;
    }

    const FileBinaryChunk chkOriginal(
        0x0102030405060708ULL,
        7,
        ByteBuffer{0x00, 0xFF, 0x10, 0x20}
    );
    const ByteBuffer vecChunk = TcpFrameCodec::vecEncode(TcpFrame(chkOriginal));
    bPassed = bExpect(
        vecChunk[5] == 0x01 && vecChunk[12] == 0x08,
        "File chunk chain ID uses network byte order"
    ) && bPassed;

    TcpFrameDecodeResult resChunk = TcpFrameCodec::resDecode(vecChunk);
    bPassed = bExpect(
        std::holds_alternative<TcpFrame>(resChunk),
        "File TCP frame round trip"
    ) && bPassed;
    if (std::holds_alternative<TcpFrame>(resChunk))
    {
        const FileBinaryChunk& chkDecoded = std::get<FileBinaryChunk>(
            std::get<TcpFrame>(resChunk).varPayload()
        );
        bPassed = bExpect(
            chkDecoded.u64ChainId() == chkOriginal.u64ChainId()
                && chkDecoded.u32ChunkIndex() == chkOriginal.u32ChunkIndex()
                && chkDecoded.vecData() == chkOriginal.vecData(),
            "File chunk fields are preserved"
        ) && bPassed;
    }

    return bPassed;
}

bool bTestTcpStreamSegmentation()
{
    // TCP一次输入先给出不完整长度前缀，第二次再粘连两个完整帧。
    const ByteBuffer vecFirst = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(R"({"type":"PING","requestId":"first"})")
    ));
    const ByteBuffer vecSecond = TcpFrameCodec::vecEncode(TcpFrame(
        JsonControlFramePayload(R"({"type":"PING","requestId":"second"})")
    ));
    TcpFrameStreamDecoder decStream;

    const ByteBuffer vecFragment(vecFirst.begin(), vecFirst.begin() + 3);
    TcpFrameStreamDecodeBatch batFirst = decStream.batConsume(vecFragment);
    bool bPassed = bExpect(
        batFirst.vecFrames().empty() && !batFirst.optError().has_value(),
        "TCP partial prefix waits for more data"
    );

    ByteBuffer vecCoalesced(vecFirst.begin() + 3, vecFirst.end());
    vecCoalesced.insert(vecCoalesced.end(), vecSecond.begin(), vecSecond.end());
    TcpFrameStreamDecodeBatch batSecond = decStream.batConsume(vecCoalesced);
    bPassed = bExpect(
        batSecond.vecFrames().size() == 2 && !batSecond.optError().has_value(),
        "TCP fragmentation and coalescing yield two frames"
    ) && bPassed;

    TcpFrameStreamDecoder decLimited(8);
    const ByteBuffer vecOversize{0x00, 0x00, 0x00, 0x09};
    TcpFrameStreamDecodeBatch batOversize = decLimited.batConsume(vecOversize);
    bPassed = bExpect(
        batOversize.optError().has_value()
            && batOversize.optError()->errCode() == ProtocolDecodeErrorCode::FrameTooLarge,
        "TCP oversized frame is rejected before allocation"
    ) && bPassed;

    return bPassed;
}

bool bTestControlJsonMessages()
{
    const NodeDiscoveryMessage msgRequest(DiscoveryRequestDetails("scan-17"));
    const NodeDiscoveryDecodeResult resRequest = NodeDiscoveryJsonCodec::resDecode(
        NodeDiscoveryJsonCodec::strEncode(msgRequest)
    );
    bool bPassed = bExpect(
        std::holds_alternative<NodeDiscoveryMessage>(resRequest)
            && std::get<NodeDiscoveryMessage>(resRequest).typeMessage()
                == NodeDiscoveryMessageType::DiscoverRequest,
        "Discovery request JSON round trip"
    );

    const NodeControlMessage msgHello{
        ClientHelloControlDetails(TcpClientRole::Manager)
    };
    const NodeControlDecodeResult resHello = NodeControlJsonCodec::resDecode(
        NodeControlJsonCodec::strEncode(msgHello)
    );
    bPassed = bExpect(
        std::holds_alternative<NodeControlMessage>(resHello)
            && std::get<NodeControlMessage>(resHello).typeMessage()
                == NodeControlMessageType::ClientHello,
        "Manager hello JSON round trip"
    ) && bPassed;

    const NodeControlDecodeResult resInvalid = NodeControlJsonCodec::resDecode(
        R"({"type":"UNSUPPORTED"})"
    );
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resInvalid),
        "Unsupported control JSON is rejected"
    ) && bPassed;

    return bPassed;
}

// 验证阶段4认证配置的强类型JSON、uint64无损编码和秘密字段隔离。
bool bTestAuthenticationControlJson()
{
    const AuthenticationRoundControlParameters prmRound(
        AuthenticationCryptoAlgorithm::Sha256,
        UdpAuthenticationMode::Native,
        10,
        4,
        3,
        100,
        1'700'000'000'000ULL,
        4
    );
    const std::uint64_t u64LargeChainId = 0xFEDCBA9876543210ULL;
    const NodeControlMessage msgSender(SenderAuthenticationConfigControlDetails(
        "sender-config-1",
        "UAV-301",
        u64LargeChainId,
        arrCreateBlock(0x10),
        arrCreateBlock(0x80),
        prmRound
    ));
    const std::string strSenderJson = NodeControlJsonCodec::strEncode(msgSender);
    const NodeControlDecodeResult resSender = NodeControlJsonCodec::resDecode(strSenderJson);

    bool bPassed = bExpect(
        strSenderJson.find(R"("chainId":"fedcba9876543210")") != std::string::npos,
        "Authentication chain ID is encoded as fixed 16-character hex"
    );
    bPassed = bExpect(
        std::holds_alternative<NodeControlMessage>(resSender)
            && std::get<SenderAuthenticationConfigControlDetails>(
                std::get<NodeControlMessage>(resSender).varDetails()
            ).u64ChainId() == u64LargeChainId,
        "Large uint64 chain ID survives control JSON round trip"
    ) && bPassed;

    const NodeControlMessage msgReceiver(
        ReceiverAuthenticationContextsControlDetails(
            "receiver-config-1",
            {
                ReceiverAuthenticationContextControlDetails(
                    "UAV-301",
                    "127.0.0.31",
                    u64LargeChainId,
                    arrCreateBlock(0x80),
                    prmRound
                )
            }
        )
    );
    const std::string strReceiverJson = NodeControlJsonCodec::strEncode(msgReceiver);
    const NodeControlDecodeResult resReceiver = NodeControlJsonCodec::resDecode(
        strReceiverJson
    );
    bPassed = bExpect(
        strReceiverJson.find("chainSeed") == std::string::npos
            && std::holds_alternative<NodeControlMessage>(resReceiver),
        "Receiver control JSON contains no key-chain seed"
    ) && bPassed;

    const NodeControlMessage msgAcknowledgement(
        AuthenticationConfigAcknowledgementControlDetails(
            "sender-config-1",
            AuthenticationConfigTarget::Sender,
            true,
            "",
            "accepted"
        )
    );
    const NodeControlDecodeResult resAcknowledgement = NodeControlJsonCodec::resDecode(
        NodeControlJsonCodec::strEncode(msgAcknowledgement)
    );
    bPassed = bExpect(
        std::holds_alternative<NodeControlMessage>(resAcknowledgement)
            && std::get<NodeControlMessage>(resAcknowledgement).typeMessage()
                == NodeControlMessageType::AuthenticationConfigAcknowledgement,
        "Authentication configuration acknowledgement round trip"
    ) && bPassed;

    const NodeControlDecodeResult resNumericChainId = NodeControlJsonCodec::resDecode(
        R"({"type":"SENDER_AUTH_CONFIG","requestId":"bad","senderId":"UAV-301","chainId":18446744073709551615,"chainSeed":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","commitmentKey":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","round":{"cryptoAlgorithm":"SHA256","authMode":"NATIVE","totalPacketCount":10,"packetsPerInterval":4,"disclosureDelay":3,"intervalMs":100,"startTimestampMs":1700000000000,"chainLength":4}})"
    );
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resNumericChainId),
        "Numeric chain ID is rejected to prevent JSON precision loss"
    ) && bPassed;

    const NodeControlDecodeResult resReceiverSecret = NodeControlJsonCodec::resDecode(
        R"({"type":"RECEIVER_AUTH_CONTEXTS","requestId":"bad-secret","contexts":[{"senderId":"UAV-301","senderIp":"127.0.0.31","chainId":"fedcba9876543210","chainSeed":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","commitmentKey":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","round":{"cryptoAlgorithm":"SHA256","authMode":"NATIVE","totalPacketCount":10,"packetsPerInterval":4,"disclosureDelay":3,"intervalMs":100,"startTimestampMs":1700000000000,"chainLength":4}}]})"
    );
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resReceiverSecret),
        "Receiver control JSON explicitly rejects a leaked chain seed"
    ) && bPassed;

    return bPassed;
}

bool bTestNativeUdpPackets()
{
    // 原生模式分别验证无披露Key和间隔首包携带Key的两种固定长度。
    const UdpAuthenticationPacketContext ctxNative(
        UdpAuthenticationMode::Native,
        2,
        1,
        5
    );
    const UdpDataPacket udpFirst(
        0x0102030405060708ULL,
        1,
        1,
        arrCreateBlock(0x10),
        std::nullopt,
        NativeUdpAuthenticationDetails(arrCreateBlock(0x80))
    );
    const ByteBuffer vecFirst = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(udpFirst),
        ctxNative
    );

    bool bPassed = bExpect(vecFirst.size() == 80, "Native packet without key length");
    bPassed = bExpect(
        vecFirst[0] == 0x01 && vecFirst[7] == 0x08
            && vecFirst[11] == 0x01 && vecFirst[15] == 0x01,
        "UDP fixed header uses network byte order"
    ) && bPassed;

    UdpAuthenticationPacketDecodeResult resFirst =
        UdpAuthenticationPacketCodec::resDecode(vecFirst, ctxNative);
    bPassed = bExpect(
        std::holds_alternative<UdpAuthenticationPacket>(resFirst),
        "Native UDP packet round trip"
    ) && bPassed;

    const UdpDataPacket udpWithKey(
        0x0102030405060708ULL,
        2,
        3,
        arrCreateBlock(0x20),
        arrCreateBlock(0x40),
        NativeUdpAuthenticationDetails(arrCreateBlock(0xA0))
    );
    const ByteBuffer vecWithKey = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(udpWithKey),
        ctxNative
    );
    bPassed = bExpect(vecWithKey.size() == 112, "Native interval-first packet carries one key")
        && bPassed;

    ByteBuffer vecExtra = vecWithKey;
    vecExtra.push_back(0);
    const UdpAuthenticationPacketDecodeResult resExtra =
        UdpAuthenticationPacketCodec::resDecode(vecExtra, ctxNative);
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resExtra)
            && std::get<ProtocolDecodeError>(resExtra).errCode()
                == ProtocolDecodeErrorCode::DatagramLengthMismatch,
        "UDP packet with an extra byte is rejected"
    ) && bPassed;

    ByteBuffer vecWrongInterval = vecFirst;
    vecWrongInterval[11] = 2;
    const UdpAuthenticationPacketDecodeResult resWrongInterval =
        UdpAuthenticationPacketCodec::resDecode(vecWrongInterval, ctxNative);
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resWrongInterval)
            && std::get<ProtocolDecodeError>(resWrongInterval).errCode()
                == ProtocolDecodeErrorCode::InvalidIntervalIndex,
        "UDP packet with inconsistent interval is rejected"
    ) && bPassed;

    return bPassed;
}

bool bTestImprovedAndDisclosurePackets()
{
    // 覆盖完整组末、最后不足组大小的尾组以及packetIndex=0的披露尾包。
    const UdpAuthenticationPacketContext ctxImproved(
        UdpAuthenticationMode::Improved,
        2,
        1,
        5,
        2,
        2
    );
    const std::vector<BinaryBlock> vecTau{arrCreateBlock(0x50), arrCreateBlock(0x70)};
    const ImprovedUdpGroupAuthenticationDetails detGroup(
        vecTau,
        arrCreateBlock(0x90)
    );
    const UdpDataPacket udpGroupEnd(
        9,
        1,
        2,
        arrCreateBlock(0x10),
        std::nullopt,
        ImprovedUdpAuthenticationDetails(detGroup)
    );
    const ByteBuffer vecGroupEnd = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(udpGroupEnd),
        ctxImproved
    );

    bool bPassed = bExpect(vecGroupEnd.size() == 144, "Improved full group-end length");
    const UdpAuthenticationPacketDecodeResult resGroupEnd =
        UdpAuthenticationPacketCodec::resDecode(vecGroupEnd, ctxImproved);
    bPassed = bExpect(
        std::holds_alternative<UdpAuthenticationPacket>(resGroupEnd),
        "Improved group-end round trip"
    ) && bPassed;

    ByteBuffer vecMissingFastTag = vecGroupEnd;
    vecMissingFastTag.resize(vecMissingFastTag.size() - BINARY_BLOCK_SIZE);
    const UdpAuthenticationPacketDecodeResult resMissingFastTag =
        UdpAuthenticationPacketCodec::resDecode(vecMissingFastTag, ctxImproved);
    bPassed = bExpect(
        std::holds_alternative<ProtocolDecodeError>(resMissingFastTag)
            && std::get<ProtocolDecodeError>(resMissingFastTag).errCode()
                == ProtocolDecodeErrorCode::DatagramLengthMismatch,
        "Improved group-end missing FastGroupTag is rejected"
    ) && bPassed;

    const UdpDataPacket udpTailGroup(
        9,
        3,
        5,
        arrCreateBlock(0x20),
        arrCreateBlock(0x40),
        ImprovedUdpAuthenticationDetails(detGroup)
    );
    const ByteBuffer vecTailGroup = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(udpTailGroup),
        ctxImproved
    );
    bPassed = bExpect(
        vecTailGroup.size() == 176,
        "Improved partial tail group carries key and group details"
    ) && bPassed;

    const UdpDisclosurePacket udpDisclosure(9, 4, arrCreateBlock(0xB0));
    const ByteBuffer vecDisclosure = UdpAuthenticationPacketCodec::vecEncode(
        UdpAuthenticationPacket(udpDisclosure),
        ctxImproved
    );
    const UdpAuthenticationPacketDecodeResult resDisclosure =
        UdpAuthenticationPacketCodec::resDecode(vecDisclosure, ctxImproved);
    bPassed = bExpect(
        vecDisclosure.size() == 48
            && std::holds_alternative<UdpAuthenticationPacket>(resDisclosure)
            && !std::get<UdpAuthenticationPacket>(resDisclosure).bIsDataPacket(),
        "Disclosure tail packet round trip"
    ) && bPassed;

    return bPassed;
}

bool bTestContextSafetyLimits()
{
    // 上下文构造阶段阻止披露间隔溢出和不可能装入单个UDP报文的τ集合。
    bool bRejectedScheduleOverflow = false;
    try
    {
        const UdpAuthenticationPacketContext ctxInvalid(
            UdpAuthenticationMode::Native,
            1,
            std::numeric_limits<std::uint32_t>::max(),
            2
        );
        static_cast<void>(ctxInvalid);
    }
    catch (const std::invalid_argument&)
    {
        bRejectedScheduleOverflow = true;
    }

    bool bRejectedOversizeTau = false;
    try
    {
        const UdpAuthenticationPacketContext ctxInvalid(
            UdpAuthenticationMode::Improved,
            4,
            1,
            4,
            4,
            2044
        );
        static_cast<void>(ctxInvalid);
    }
    catch (const std::invalid_argument&)
    {
        bRejectedOversizeTau = true;
    }

    return bExpect(bRejectedScheduleOverflow, "Disclosure schedule overflow is rejected")
        && bExpect(bRejectedOversizeTau, "Oversized tau context is rejected");
}

bool bTestProtocolToAlgorithmMapping()
{
    // 映射只复制MAC逻辑输入字段，UDP中的Key和认证详情不会泄漏进算法输入对象。
    const UdpDataPacket udpData(
        77,
        2,
        3,
        arrCreateBlock(0x33),
        std::nullopt,
        NativeUdpAuthenticationDetails(arrCreateBlock(0x99))
    );
    const tesla::core::AuthenticationPacketInput pktInput =
        tesla::core::UdpAuthenticationInputMapper::pktMapDataPacket("UAV-101", udpData);

    return bExpect(pktInput.strSenderId() == "UAV-101", "Mapper uses trusted sender ID")
        && bExpect(pktInput.u64ChainId() == 77, "Mapper copies chain ID")
        && bExpect(pktInput.u32IntervalIndex() == 2, "Mapper copies interval index")
        && bExpect(pktInput.u32PacketIndex() == 3, "Mapper copies packet index")
        && bExpect(pktInput.arrMessage()[0] == 0x33, "Mapper copies fixed message bytes");
}
}

int main()
{
    bool bPassed = true;
    bPassed = bTestTcpFrameRoundTrips() && bPassed;
    bPassed = bTestTcpStreamSegmentation() && bPassed;
    bPassed = bTestControlJsonMessages() && bPassed;
    bPassed = bTestAuthenticationControlJson() && bPassed;
    bPassed = bTestNativeUdpPackets() && bPassed;
    bPassed = bTestImprovedAndDisclosurePackets() && bPassed;
    bPassed = bTestContextSafetyLimits() && bPassed;
    bPassed = bTestProtocolToAlgorithmMapping() && bPassed;

    if (!bPassed)
    {
        return 1;
    }

    std::cout << "All protocol tests passed." << std::endl;
    return 0;
}

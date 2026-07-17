#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include "BinaryCodecUtilities.h"

#include <stdexcept>
#include <string>
#include <variant>

namespace tesla::protocol
{
namespace
{
ProtocolDecodeError errCreate(
    ProtocolDecodeErrorCode errCode,
    const std::string& strMessage
)
{
    return ProtocolDecodeError(errCode, strMessage);
}

void validateDataPacketForEncoding(
    const UdpDataPacket& udpData,
    const UdpAuthenticationPacketContext& ctxContext
)
{
    // 发送端同样使用可信上下文检查条件字段，避免生成Receiver必然拒绝的线格式。
    if (udpData.u32PacketIndex() > ctxContext.u32TotalPacketCount())
    {
        throw std::invalid_argument("UDP data packet index exceeds the configured round");
    }

    if (udpData.u32IntervalIndex()
        != ctxContext.u32ExpectedInterval(udpData.u32PacketIndex()))
    {
        throw std::invalid_argument("UDP data packet interval does not match its packet index");
    }

    const bool bNeedsKey = ctxContext.bPacketCarriesDisclosedKey(
        udpData.u32IntervalIndex(),
        udpData.u32PacketIndex()
    );
    if (udpData.optDisclosedKey().has_value() != bNeedsKey)
    {
        throw std::invalid_argument("UDP data packet disclosed-key presence is invalid");
    }

    if (ctxContext.modeAuthentication() == UdpAuthenticationMode::Native)
    {
        if (!std::holds_alternative<NativeUdpAuthenticationDetails>(
                udpData.varAuthenticationDetails()
            ))
        {
            throw std::invalid_argument("Native UDP context requires native packet details");
        }

        return;
    }

    if (!std::holds_alternative<ImprovedUdpAuthenticationDetails>(
            udpData.varAuthenticationDetails()
        ))
    {
        throw std::invalid_argument("Improved UDP context requires improved packet details");
    }

    const ImprovedUdpAuthenticationDetails& detImproved =
        std::get<ImprovedUdpAuthenticationDetails>(udpData.varAuthenticationDetails());
    const bool bNeedsGroupDetails = ctxContext.bIsImprovedGroupEnd(udpData.u32PacketIndex());

    if (detImproved.optGroupDetails().has_value() != bNeedsGroupDetails)
    {
        throw std::invalid_argument("Improved UDP group details are missing or appear off-group-end");
    }

    if (bNeedsGroupDetails
        && detImproved.optGroupDetails()->vecSamdTau().size() != ctxContext.nTauCount())
    {
        throw std::invalid_argument("Improved UDP tau count does not match trusted context");
    }
}

void appendBlock(ByteBuffer& vecOutput, const BinaryBlock& arrBlock)
{
    detail::appendBytes(vecOutput, arrBlock.data(), arrBlock.size());
}
}

ByteBuffer UdpAuthenticationPacketCodec::vecEncode(
    const UdpAuthenticationPacket& udpPacket,
    const UdpAuthenticationPacketContext& ctxContext
)
{
    ByteBuffer vecDatagram;

    if (!udpPacket.bIsDataPacket())
    {
        // packetIndex固定为0即可区分披露尾包，不额外写入报文类型字段。
        const UdpDisclosurePacket& udpDisclosure = std::get<UdpDisclosurePacket>(
            udpPacket.varDetails()
        );
        const std::uint32_t u32FinalDataInterval = ctxContext.u32ExpectedInterval(
            ctxContext.u32TotalPacketCount()
        );

        if (udpDisclosure.u32IntervalIndex() <= ctxContext.u32DisclosureDelay()
            || udpDisclosure.u32IntervalIndex()
                > u32FinalDataInterval + ctxContext.u32DisclosureDelay())
        {
            throw std::invalid_argument("UDP disclosure interval is outside the configured round");
        }

        vecDatagram.reserve(DISCLOSURE_PACKET_SIZE);
        detail::appendUint64(vecDatagram, udpDisclosure.u64ChainId());
        detail::appendUint32(vecDatagram, udpDisclosure.u32IntervalIndex());
        detail::appendUint32(vecDatagram, 0);
        appendBlock(vecDatagram, udpDisclosure.arrDisclosedKey());
        return vecDatagram;
    }

    const UdpDataPacket& udpData = std::get<UdpDataPacket>(udpPacket.varDetails());
    validateDataPacketForEncoding(udpData, ctxContext);

    detail::appendUint64(vecDatagram, udpData.u64ChainId());
    detail::appendUint32(vecDatagram, udpData.u32IntervalIndex());
    detail::appendUint32(vecDatagram, udpData.u32PacketIndex());
    appendBlock(vecDatagram, udpData.arrMessage());

    if (udpData.optDisclosedKey().has_value())
    {
        appendBlock(vecDatagram, udpData.optDisclosedKey().value());
    }

    if (ctxContext.modeAuthentication() == UdpAuthenticationMode::Native)
    {
        appendBlock(
            vecDatagram,
            std::get<NativeUdpAuthenticationDetails>(
                udpData.varAuthenticationDetails()
            ).arrPacketMac()
        );
        return vecDatagram;
    }

    const ImprovedUdpAuthenticationDetails& detImproved =
        std::get<ImprovedUdpAuthenticationDetails>(udpData.varAuthenticationDetails());
    if (detImproved.optGroupDetails().has_value())
    {
        const ImprovedUdpGroupAuthenticationDetails& detGroup =
            detImproved.optGroupDetails().value();
        for (const BinaryBlock& arrTau : detGroup.vecSamdTau())
        {
            appendBlock(vecDatagram, arrTau);
        }

        appendBlock(vecDatagram, detGroup.arrFastGroupTag());
    }

    return vecDatagram;
}

UdpAuthenticationPacketHeaderDecodeResult
UdpAuthenticationPacketCodec::resDecodeHeader(const ByteBuffer& vecDatagram)
{
    if (vecDatagram.size() < FIXED_HEADER_SIZE)
    {
        return errCreate(
            ProtocolDecodeErrorCode::DatagramTooShort,
            "UDP authentication datagram is shorter than its fixed header"
        );
    }

    try
    {
        detail::BinaryReader rdrDatagram(vecDatagram);
        // 有状态读取必须显式排序，不能依赖函数实参的求值顺序。
        const std::uint64_t u64ChainId = rdrDatagram.u64Read();
        const std::uint32_t u32IntervalIndex = rdrDatagram.u32Read();
        const std::uint32_t u32PacketIndex = rdrDatagram.u32Read();
        return UdpAuthenticationPacketHeader(
            u64ChainId,
            u32IntervalIndex,
            u32PacketIndex
        );
    }
    catch (const std::exception& exError)
    {
        return errCreate(
            ProtocolDecodeErrorCode::InvalidAuthenticationFields,
            exError.what()
        );
    }
}

UdpAuthenticationPacketDecodeResult UdpAuthenticationPacketCodec::resDecode(
    const ByteBuffer& vecDatagram,
    const UdpAuthenticationPacketContext& ctxContext
)
{
    if (vecDatagram.size() < FIXED_HEADER_SIZE)
    {
        return errCreate(
            ProtocolDecodeErrorCode::DatagramTooShort,
            "UDP authentication datagram is shorter than its fixed header"
        );
    }

    try
    {
        detail::BinaryReader rdrDatagram(vecDatagram);
        const std::uint64_t u64ChainId = rdrDatagram.u64Read();
        const std::uint32_t u32IntervalIndex = rdrDatagram.u32Read();
        const std::uint32_t u32PacketIndex = rdrDatagram.u32Read();

        if (u64ChainId == 0)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidAuthenticationContext,
                "UDP authentication datagram contains a zero chain ID"
            );
        }

        if (u32IntervalIndex == 0)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidIntervalIndex,
                "UDP authentication datagram interval must start at one"
            );
        }

        if (u32PacketIndex == 0)
        {
            if (vecDatagram.size() != DISCLOSURE_PACKET_SIZE)
            {
                return errCreate(
                    ProtocolDecodeErrorCode::DatagramLengthMismatch,
                    "UDP disclosure packet must contain exactly one 32-byte key"
                );
            }

            const std::uint32_t u32FinalDataInterval = ctxContext.u32ExpectedInterval(
                ctxContext.u32TotalPacketCount()
            );
            if (u32IntervalIndex <= ctxContext.u32DisclosureDelay()
                || u32IntervalIndex
                    > u32FinalDataInterval + ctxContext.u32DisclosureDelay())
            {
                return errCreate(
                    ProtocolDecodeErrorCode::InvalidIntervalIndex,
                    "UDP disclosure interval is outside the configured round"
                );
            }

            return UdpAuthenticationPacket(UdpDisclosurePacket(
                u64ChainId,
                u32IntervalIndex,
                rdrDatagram.arrRead<BINARY_BLOCK_SIZE>()
            ));
        }

        if (u32PacketIndex > ctxContext.u32TotalPacketCount())
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidPacketIndex,
                "UDP data packet index exceeds the configured round"
            );
        }

        const std::uint32_t u32ExpectedInterval = ctxContext.u32ExpectedInterval(u32PacketIndex);
        if (u32IntervalIndex != u32ExpectedInterval)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidIntervalIndex,
                "UDP data packet interval does not match its packet index"
            );
        }

        // 在读取任何条件字段前先由上下文计算唯一合法总长度，缺失和多余字节统一拒绝。
        std::size_t nExpectedLength = DATA_PREFIX_SIZE;
        const bool bHasDisclosedKey = ctxContext.bPacketCarriesDisclosedKey(
            u32IntervalIndex,
            u32PacketIndex
        );
        if (bHasDisclosedKey)
        {
            nExpectedLength += BINARY_BLOCK_SIZE;
        }

        if (ctxContext.modeAuthentication() == UdpAuthenticationMode::Native)
        {
            nExpectedLength += BINARY_BLOCK_SIZE;
        }
        else if (ctxContext.bIsImprovedGroupEnd(u32PacketIndex))
        {
            nExpectedLength += (ctxContext.nTauCount() + 1U) * BINARY_BLOCK_SIZE;
        }

        if (vecDatagram.size() != nExpectedLength)
        {
            return errCreate(
                ProtocolDecodeErrorCode::DatagramLengthMismatch,
                "UDP authentication datagram length does not match conditional fields"
            );
        }

        const BinaryBlock arrMessage = rdrDatagram.arrRead<BINARY_BLOCK_SIZE>();
        std::optional<BinaryBlock> optDisclosedKey;
        if (bHasDisclosedKey)
        {
            optDisclosedKey = rdrDatagram.arrRead<BINARY_BLOCK_SIZE>();
        }

        if (ctxContext.modeAuthentication() == UdpAuthenticationMode::Native)
        {
            return UdpAuthenticationPacket(UdpDataPacket(
                u64ChainId,
                u32IntervalIndex,
                u32PacketIndex,
                arrMessage,
                optDisclosedKey,
                NativeUdpAuthenticationDetails(rdrDatagram.arrRead<BINARY_BLOCK_SIZE>())
            ));
        }

        std::optional<ImprovedUdpGroupAuthenticationDetails> optGroupDetails;
        if (ctxContext.bIsImprovedGroupEnd(u32PacketIndex))
        {
            std::vector<BinaryBlock> vecSamdTau;
            vecSamdTau.reserve(ctxContext.nTauCount());
            for (std::size_t nIndex = 0; nIndex < ctxContext.nTauCount(); ++nIndex)
            {
                vecSamdTau.push_back(rdrDatagram.arrRead<BINARY_BLOCK_SIZE>());
            }

            optGroupDetails.emplace(
                std::move(vecSamdTau),
                rdrDatagram.arrRead<BINARY_BLOCK_SIZE>()
            );
        }

        return UdpAuthenticationPacket(UdpDataPacket(
            u64ChainId,
            u32IntervalIndex,
            u32PacketIndex,
            arrMessage,
            optDisclosedKey,
            ImprovedUdpAuthenticationDetails(std::move(optGroupDetails))
        ));
    }
    catch (const std::out_of_range&)
    {
        return errCreate(
            ProtocolDecodeErrorCode::DatagramTooShort,
            "UDP authentication datagram ended inside a declared field"
        );
    }
    catch (const std::invalid_argument& exError)
    {
        return errCreate(
            ProtocolDecodeErrorCode::InvalidAuthenticationFields,
            exError.what()
        );
    }
}
}

#include "tesla/core/AuthenticationInputEncoder.h"

#include <limits>
#include <stdexcept>

namespace tesla::core
{
crypto::ByteBuffer AuthenticationInputEncoder::vecEncodePacketMacInput(
    const AuthenticationPacketInput& pktInput
)
{
    crypto::ByteBuffer vecOutput;
    vecOutput.reserve(
        sizeof(std::uint16_t)
        + pktInput.strSenderId().size()
        + sizeof(std::uint64_t)
        + sizeof(std::uint32_t) * 2
        + AuthenticationPacketInput::MESSAGE_SIZE
    );

    // 布局：Sender长度+Sender、ChainId、Interval、PacketIndex、32字节Message。
    appendSenderId(vecOutput, pktInput.strSenderId());
    appendUint64(vecOutput, pktInput.u64ChainId());
    appendUint32(vecOutput, pktInput.u32IntervalIndex());
    appendUint32(vecOutput, pktInput.u32PacketIndex());
    appendBytes(vecOutput, pktInput.arrMessage().data(), pktInput.arrMessage().size());

    return vecOutput;
}

crypto::ByteBuffer AuthenticationInputEncoder::vecEncodeFastGroupInput(
    const AuthenticationGroupInput& grpInput,
    const std::vector<crypto::Digest>& vecSamdTau
)
{
    if (grpInput.bHasMissingPackets())
    {
        throw std::invalid_argument("Fast-group input requires every packet slot");
    }

    if (vecSamdTau.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("SAMD tag vector is too large");
    }

    crypto::ByteBuffer vecOutput;

    // 布局头：Sender长度+Sender、ChainId、Interval、GroupIndex、固定槽位数量。
    appendSenderId(vecOutput, grpInput.strSenderId());
    appendUint64(vecOutput, grpInput.u64ChainId());
    appendUint32(vecOutput, grpInput.u32IntervalIndex());
    appendUint32(vecOutput, grpInput.u32GroupIndex());
    appendUint32(vecOutput, static_cast<std::uint32_t>(grpInput.nPacketSlotCount()));

    // 快速路径只接受完整组，因此每个槽位按顺序编码PacketIndex和Message。
    for (const AuthenticationGroupInput::PacketSlot& optPacket : grpInput.vecPacketSlots())
    {
        const AuthenticationPacketInput& pktCurrent = optPacket.value();
        appendUint32(vecOutput, pktCurrent.u32PacketIndex());
        appendBytes(vecOutput, pktCurrent.arrMessage().data(), pktCurrent.arrMessage().size());
    }

    // 末尾编码SAMD标签数量和原始32字节标签，绑定当前矩阵输出。
    appendUint32(vecOutput, static_cast<std::uint32_t>(vecSamdTau.size()));

    for (const crypto::Digest& digTau : vecSamdTau)
    {
        appendBytes(vecOutput, digTau.data(), digTau.size());
    }

    return vecOutput;
}

void AuthenticationInputEncoder::appendBytes(
    crypto::ByteBuffer& vecOutput,
    const std::uint8_t* pData,
    std::size_t nSize
)
{
    vecOutput.insert(vecOutput.end(), pData, pData + nSize);
}

void AuthenticationInputEncoder::appendSenderId(
    crypto::ByteBuffer& vecOutput,
    const std::string& strSenderId
)
{
    appendUint16(vecOutput, static_cast<std::uint16_t>(strSenderId.size()));
    appendBytes(
        vecOutput,
        reinterpret_cast<const std::uint8_t*>(strSenderId.data()),
        strSenderId.size()
    );
}

void AuthenticationInputEncoder::appendUint16(
    crypto::ByteBuffer& vecOutput,
    std::uint16_t u16Value
)
{
    // 算法输入中的多字节整数统一使用网络序（大端序）。
    vecOutput.push_back(static_cast<std::uint8_t>((u16Value >> 8) & 0xFF));
    vecOutput.push_back(static_cast<std::uint8_t>(u16Value & 0xFF));
}

void AuthenticationInputEncoder::appendUint32(
    crypto::ByteBuffer& vecOutput,
    std::uint32_t u32Value
)
{
    for (int nShift = 24; nShift >= 0; nShift -= 8)
    {
        vecOutput.push_back(static_cast<std::uint8_t>((u32Value >> nShift) & 0xFF));
    }
}

void AuthenticationInputEncoder::appendUint64(
    crypto::ByteBuffer& vecOutput,
    std::uint64_t u64Value
)
{
    for (int nShift = 56; nShift >= 0; nShift -= 8)
    {
        vecOutput.push_back(static_cast<std::uint8_t>((u64Value >> nShift) & 0xFF));
    }
}
}

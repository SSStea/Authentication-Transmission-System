#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <optional>
#include <variant>
#include <vector>

namespace tesla::protocol
{
/** @brief 原生TESLA数据报文专用详情，每个数据报文都携带一个MAC。 */
class NativeUdpAuthenticationDetails final
{
public:
    explicit NativeUdpAuthenticationDetails(BinaryBlock arrPacketMac);

    const BinaryBlock& arrPacketMac() const noexcept;

private:
    BinaryBlock m_arrPacketMac;
};

/** @brief 改进TESLA组末专用详情，τ集合和快速组标签必须成对出现。 */
class ImprovedUdpGroupAuthenticationDetails final
{
public:
    ImprovedUdpGroupAuthenticationDetails(
        std::vector<BinaryBlock> vecSamdTau,
        BinaryBlock arrFastGroupTag
    );

    const std::vector<BinaryBlock>& vecSamdTau() const noexcept;
    const BinaryBlock& arrFastGroupTag() const noexcept;

private:
    std::vector<BinaryBlock> m_vecSamdTau;
    BinaryBlock              m_arrFastGroupTag;
};

/** @brief 改进TESLA数据报文详情；仅组末报文包含组认证详情。 */
class ImprovedUdpAuthenticationDetails final
{
public:
    explicit ImprovedUdpAuthenticationDetails(
        std::optional<ImprovedUdpGroupAuthenticationDetails> optGroupDetails = std::nullopt
    );

    const std::optional<ImprovedUdpGroupAuthenticationDetails>& optGroupDetails() const noexcept;

private:
    std::optional<ImprovedUdpGroupAuthenticationDetails> m_optGroupDetails;
};

using UdpDataAuthenticationDetails = std::variant<
    NativeUdpAuthenticationDetails,
    ImprovedUdpAuthenticationDetails
>;

/** @brief UDP数据报文的实际字段，不包含由TCP上下文提供的Sender ID和认证模式。 */
class UdpDataPacket final
{
public:
    UdpDataPacket(
        std::uint64_t u64ChainId,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex,
        BinaryBlock arrMessage,
        std::optional<BinaryBlock> optDisclosedKey,
        UdpDataAuthenticationDetails varAuthenticationDetails
    );

    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32IntervalIndex() const noexcept;
    std::uint32_t u32PacketIndex() const noexcept;
    const BinaryBlock& arrMessage() const noexcept;
    const std::optional<BinaryBlock>& optDisclosedKey() const noexcept;
    const UdpDataAuthenticationDetails& varAuthenticationDetails() const noexcept;

private:
    std::uint64_t                m_u64ChainId;
    std::uint32_t                m_u32IntervalIndex;
    std::uint32_t                m_u32PacketIndex;
    BinaryBlock                  m_arrMessage;
    std::optional<BinaryBlock>   m_optDisclosedKey;
    UdpDataAuthenticationDetails m_varAuthenticationDetails;
};

/** @brief 数据发送完成后使用packetIndex=0传输最后披露密钥的尾包。 */
class UdpDisclosurePacket final
{
public:
    UdpDisclosurePacket(
        std::uint64_t u64ChainId,
        std::uint32_t u32IntervalIndex,
        BinaryBlock arrDisclosedKey
    );

    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32IntervalIndex() const noexcept;
    const BinaryBlock& arrDisclosedKey() const noexcept;

private:
    std::uint64_t m_u64ChainId;
    std::uint32_t m_u32IntervalIndex;
    BinaryBlock   m_arrDisclosedKey;
};

using UdpAuthenticationPacketDetails = std::variant<UdpDataPacket, UdpDisclosurePacket>;

/** @brief 一套固定UDP线格式的逻辑报文，数据包与披露尾包使用variant区分。 */
class UdpAuthenticationPacket final
{
public:
    explicit UdpAuthenticationPacket(UdpAuthenticationPacketDetails varDetails);

    bool bIsDataPacket() const noexcept;
    const UdpAuthenticationPacketDetails& varDetails() const noexcept;

private:
    UdpAuthenticationPacketDetails m_varDetails;
};
}

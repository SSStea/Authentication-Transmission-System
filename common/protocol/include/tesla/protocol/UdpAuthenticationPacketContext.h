#pragma once

#include <cstddef>
#include <cstdint>

namespace tesla::protocol
{
enum class UdpAuthenticationMode
{
    Native,
    Improved
};

/**
 * @brief Receiver通过可信TCP配置获得的UDP条件字段解析上下文。
 *
 * 这些字段不出现在UDP负载中，Codec必须依赖本上下文推导Key和组标签是否存在。
 */
class UdpAuthenticationPacketContext final
{
public:
    UdpAuthenticationPacketContext(
        UdpAuthenticationMode modeAuthentication,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32TotalPacketCount,
        std::uint32_t u32GroupSize = 0,
        std::size_t nTauCount = 0
    );

    UdpAuthenticationMode modeAuthentication() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32TotalPacketCount() const noexcept;
    std::uint32_t u32GroupSize() const noexcept;
    std::size_t nTauCount() const noexcept;

    std::uint32_t u32ExpectedInterval(std::uint32_t u32PacketIndex) const;
    bool bPacketCarriesDisclosedKey(
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex
    ) const noexcept;
    bool bIsImprovedGroupEnd(std::uint32_t u32PacketIndex) const noexcept;

private:
    UdpAuthenticationMode m_modeAuthentication;
    std::uint32_t         m_u32PacketsPerInterval;
    std::uint32_t         m_u32DisclosureDelay;
    std::uint32_t         m_u32TotalPacketCount;
    std::uint32_t         m_u32GroupSize;
    std::size_t           m_nTauCount;
};
}

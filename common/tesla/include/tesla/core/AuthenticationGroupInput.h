#pragma once

#include "tesla/core/AuthenticationPacketInput.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tesla::core
{
/**
 * @brief 表示一个认证组的算法输入及固定报文槽位。
 *
 * 空槽位保留丢包的原始位置，禁止把剩余报文压缩后重新编号。
 */
class AuthenticationGroupInput final
{
public:
    /// 固定位置上的单包输入；std::nullopt表示该位置报文缺失。
    using PacketSlot = std::optional<AuthenticationPacketInput>;

    /**
     * @brief 创建共享一个认证上下文的报文组。
     * @param strSenderId 该组可信发送者标识。
     * @param u64ChainId 该组密钥链标识。
     * @param u32IntervalIndex 从1开始的TESLA间隔索引。
     * @param u32GroupIndex 从1开始的组索引。
     * @param u32FirstPacketIndex 第一个槽位应对应的报文索引。
     * @param vecPacketSlots 保留实际位置的非空槽位序列。
     * @throws std::invalid_argument 组上下文、槽位数量或报文位置不一致时抛出。
     */
    AuthenticationGroupInput(
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32GroupIndex,
        std::uint32_t u32FirstPacketIndex,
        std::vector<PacketSlot> vecPacketSlots
    );

    /** @return 任一固定槽位缺失报文时返回true。 */
    bool bHasMissingPackets() const noexcept;

    /** @return 包含缺失位置在内的固定槽位数量。 */
    std::size_t nPacketSlotCount() const noexcept;

    /** @return 该组发送者标识的只读引用。 */
    const std::string& strSenderId() const noexcept;

    /** @return 该组密钥链标识。 */
    std::uint64_t u64ChainId() const noexcept;

    /** @return 第一个固定槽位对应的报文索引。 */
    std::uint32_t u32FirstPacketIndex() const noexcept;

    /** @return 从1开始的组索引。 */
    std::uint32_t u32GroupIndex() const noexcept;

    /** @return 从1开始的TESLA间隔索引。 */
    std::uint32_t u32IntervalIndex() const noexcept;

    /** @return 固定报文槽位的只读引用。 */
    const std::vector<PacketSlot>& vecPacketSlots() const noexcept;

private:
    void validatePacketSlots() const;

    std::string             m_strSenderId;
    std::uint64_t           m_u64ChainId;
    std::uint32_t           m_u32IntervalIndex;
    std::uint32_t           m_u32GroupIndex;
    std::uint32_t           m_u32FirstPacketIndex;
    std::vector<PacketSlot> m_vecPacketSlots;
};
}

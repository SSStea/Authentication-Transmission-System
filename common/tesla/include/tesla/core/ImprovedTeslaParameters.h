#pragma once

#include <cstddef>
#include <cstdint>

namespace tesla::core
{
/**
 * @brief 保存改进TESLA分组和检测门限，并预先验证KS+RS矩阵可构造。
 */
class ImprovedTeslaParameters final
{
public:
    ImprovedTeslaParameters(
        std::uint32_t u32GroupSize,
        std::uint32_t u32DetectionThreshold
    );

    std::uint32_t u32GroupSize() const noexcept;
    std::uint32_t u32DetectionThreshold() const noexcept;
    std::size_t nTauCount() const noexcept;

private:
    std::uint32_t m_u32GroupSize;
    std::uint32_t m_u32DetectionThreshold;
    std::size_t   m_nTauCount;
};
}

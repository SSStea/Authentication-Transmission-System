#pragma once

#include <cstddef>
#include <vector>

namespace tesla::core
{
/**
 * @brief 保存KS+RS回退验证得到的位置分类和门限状态。
 */
class KsRsVerificationResult final
{
public:
    /**
     * @brief 创建KS+RS位置级验证结果。
     * @param vecGoodPositions 被匹配矩阵行证明的固定槽位位置。
     * @param vecBadPositions 未被证明或已缺失的固定槽位位置。
     * @param bDetectionThresholdExceeded 坏位置数量是否超过配置门限。
     */
    KsRsVerificationResult(
        std::vector<std::size_t> vecGoodPositions,
        std::vector<std::size_t> vecBadPositions,
        bool bDetectionThresholdExceeded
    );

    /** @return 坏位置数量超过检测门限时返回true。 */
    bool bDetectionThresholdExceeded() const noexcept;

    /** @return 坏位置序列的只读引用。 */
    const std::vector<std::size_t>& vecBadPositions() const noexcept;

    /** @return 已证明位置序列的只读引用。 */
    const std::vector<std::size_t>& vecGoodPositions() const noexcept;

private:
    std::vector<std::size_t> m_vecGoodPositions;
    std::vector<std::size_t> m_vecBadPositions;
    bool                     m_bDetectionThresholdExceeded;
};
}

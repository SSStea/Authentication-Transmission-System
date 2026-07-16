#pragma once

#include "tesla/core/ImprovedVerificationPath.h"

#include <cstddef>
#include <vector>

namespace tesla::core
{
/**
 * @brief 保存改进TESLA模式的验证路径和位置级判定结果。
 */
class ImprovedVerificationDetails final
{
public:
    /**
     * @brief 创建一次改进模式验证的完整模式专用详情。
     * @param pathVerification 实际采用的验证路径。
     * @param bFastGroupTagMatched 快速组标签是否匹配。
     * @param vecAuthenticatedPositions 已认证的固定槽位位置。
     * @param vecRejectedPositions 被拒绝或无法证明的固定槽位位置。
     * @param bDetectionThresholdExceeded 拒绝位置数量是否超过检测门限。
     */
    ImprovedVerificationDetails(
        ImprovedVerificationPath pathVerification,
        bool bFastGroupTagMatched,
        std::vector<std::size_t> vecAuthenticatedPositions,
        std::vector<std::size_t> vecRejectedPositions,
        bool bDetectionThresholdExceeded
    );

    /** @return 拒绝位置数量超过配置门限时返回true。 */
    bool bDetectionThresholdExceeded() const noexcept;

    /** @return 快速组标签匹配时返回true。 */
    bool bFastGroupTagMatched() const noexcept;

    /** @return 本次验证采用的路径。 */
    ImprovedVerificationPath pathVerification() const noexcept;

    /** @return 已认证固定槽位位置的只读引用。 */
    const std::vector<std::size_t>& vecAuthenticatedPositions() const noexcept;

    /** @return 被拒绝固定槽位位置的只读引用。 */
    const std::vector<std::size_t>& vecRejectedPositions() const noexcept;

private:
    ImprovedVerificationPath  m_pathVerification;
    bool                      m_bFastGroupTagMatched;
    std::vector<std::size_t>  m_vecAuthenticatedPositions;
    std::vector<std::size_t>  m_vecRejectedPositions;
    bool                      m_bDetectionThresholdExceeded;
};
}

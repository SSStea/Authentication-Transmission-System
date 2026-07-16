#pragma once

#include "tesla/crypto/CryptoTypes.h"

#include <cstddef>
#include <optional>
#include <vector>

namespace tesla::core
{
/**
 * @brief 改进TESLA模式生成或接收的SAMD标签和快速组标签。
 */
class ImprovedAuthenticationDetails final
{
public:
    /**
     * @brief 保存改进模式的模式专用认证字段。
     * @param vecSamdTau 按KS+RS矩阵行顺序排列的SAMD标签。
     * @param optFastGroupTag 完整报文组可携带的快速组标签。
     */
    ImprovedAuthenticationDetails(
        std::vector<crypto::Digest> vecSamdTau,
        std::optional<crypto::Digest> optFastGroupTag
    );

    /** @return 可选快速组标签的只读引用。 */
    const std::optional<crypto::Digest>& optFastGroupTag() const noexcept;

    /** @return SAMD标签序列的只读引用。 */
    const std::vector<crypto::Digest>& vecSamdTau() const noexcept;

private:
    std::vector<crypto::Digest>   m_vecSamdTau;
    std::optional<crypto::Digest> m_optFastGroupTag;
};

/** @brief 改进TESLA验证实际采用的判定路径。 */
enum class ImprovedVerificationPath
{
    FastGroupPass,
    KsRsFallback,
    IncompleteGroupTags
};

/** @brief 保存改进TESLA模式的验证路径和位置级判定结果。 */
class ImprovedVerificationDetails final
{
public:
    ImprovedVerificationDetails(
        ImprovedVerificationPath pathVerification,
        bool bFastGroupTagMatched,
        std::vector<std::size_t> vecAuthenticatedPositions,
        std::vector<std::size_t> vecRejectedPositions,
        bool bDetectionThresholdExceeded
    );

    bool bDetectionThresholdExceeded() const noexcept;
    bool bFastGroupTagMatched() const noexcept;
    ImprovedVerificationPath pathVerification() const noexcept;
    const std::vector<std::size_t>& vecAuthenticatedPositions() const noexcept;
    const std::vector<std::size_t>& vecRejectedPositions() const noexcept;

private:
    ImprovedVerificationPath m_pathVerification;
    bool                     m_bFastGroupTagMatched;
    std::vector<std::size_t> m_vecAuthenticatedPositions;
    std::vector<std::size_t> m_vecRejectedPositions;
    bool                     m_bDetectionThresholdExceeded;
};
}

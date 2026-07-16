#pragma once

#include "tesla/crypto/CryptoTypes.h"

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
}

#pragma once

#include "tesla/core/KsRsVerificationResult.h"
#include "tesla/core/KsRsMatrix.h"
#include "tesla/crypto/CryptoProvider.h"

#include <optional>
#include <vector>

namespace tesla::core
{
/**
 * @brief 利用KS+RS矩阵和SAMD标签定位可认证及可疑报文位置。
 */
class KsRsVerifier final
{
public:
    /**
     * @brief 对保留缺失位置的逐包MAC槽位执行KS+RS回退验证。
     * @param crpProvider 用于重算SAMD标签的密码提供者。
     * @param matKsRs 与发送方生成标签时相同的矩阵。
     * @param vecPacketMacSlots 当前接收报文重算得到的固定MAC槽位。
     * @param vecReceivedTau 接收到的逐行SAMD标签。
     * @return 已证明位置、坏位置及门限状态。
     * @throws std::invalid_argument 槽位数量或SAMD标签数量与矩阵不匹配时抛出。
     */
    static KsRsVerificationResult resVerify(
        const crypto::CryptoProvider& crpProvider,
        const KsRsMatrix& matKsRs,
        const std::vector<std::optional<crypto::Digest>>& vecPacketMacSlots,
        const std::vector<crypto::Digest>& vecReceivedTau
    );

private:
    KsRsVerifier() = delete;
};
}

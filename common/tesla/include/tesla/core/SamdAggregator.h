#pragma once

#include "tesla/core/KsRsMatrix.h"
#include "tesla/crypto/CryptoProvider.h"

#include <vector>

namespace tesla::core
{
/**
 * @brief 根据KS+RS矩阵把逐包MAC聚合为SAMD标签。
 */
class SamdAggregator final
{
public:
    /**
     * @brief 按给定顺序和域分隔符聚合一个MAC子集。
     * @param crpProvider 用于最终摘要的密码提供者。
     * @param vecPacketMacs 当前矩阵行选中的MAC序列，可为空。
     * @return 该MAC子集的固定32字节SAMD标签。
     */
    static crypto::Digest digAggregateMacList(
        const crypto::CryptoProvider& crpProvider,
        const std::vector<crypto::Digest>& vecPacketMacs
    );

    /**
     * @brief 为矩阵的每一行生成一个SAMD标签。
     * @param crpProvider 用于聚合摘要的密码提供者。
     * @param matKsRs 决定每行选择哪些MAC的KS+RS矩阵。
     * @param vecPacketMacs 按固定槽位顺序排列的完整MAC序列。
     * @return 按矩阵行顺序排列的SAMD标签。
     * @throws std::invalid_argument MAC数量为0或超过矩阵组大小时抛出。
     */
    static std::vector<crypto::Digest> vecAggregate(
        const crypto::CryptoProvider& crpProvider,
        const KsRsMatrix& matKsRs,
        const std::vector<crypto::Digest>& vecPacketMacs
    );

private:
    SamdAggregator() = delete;
};
}

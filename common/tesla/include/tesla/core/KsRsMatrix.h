#pragma once

#include <cstddef>
#include <vector>

namespace tesla::core
{
/**
 * @brief 为指定组大小和检测门限构造KS+RS二值选择矩阵。
 *
 * 每一列对应固定报文位置，每一行定义一个需要聚合验证的MAC子集。
 */
class KsRsMatrix final
{
public:
    /**
     * @brief 搜索可用参数并构造不可变矩阵。
     * @param nGroupSize 最大报文槽位数量。
     * @param nDetectionThreshold 可容忍或定位的异常位置门限。
     * @throws std::invalid_argument 组大小或门限无效时抛出。
     * @throws std::runtime_error 无法找到有效矩阵参数时抛出。
     */
    KsRsMatrix(std::size_t nGroupSize, std::size_t nDetectionThreshold);

    /**
     * @brief 查询指定矩阵行是否包含某个报文位置。
     * @param nRowIndex 从0开始的矩阵行索引。
     * @param nColumnIndex 从0开始的报文槽位位置。
     * @return 该行需要聚合此位置MAC时返回true。
     * @throws std::out_of_range 任一索引越界时抛出。
     */
    bool bRowContains(std::size_t nRowIndex, std::size_t nColumnIndex) const;

    /** @return 配置的检测门限。 */
    std::size_t nDetectionThreshold() const noexcept;

    /** @return 矩阵支持的最大组大小。 */
    std::size_t nGroupSize() const noexcept;

    /** @return 矩阵生成的SAMD选择行数量。 */
    std::size_t nRowCount() const noexcept;

private:
    static bool bIsPrime(std::size_t nValue);
    static std::size_t nMinExponent(std::size_t nGroupSize, std::size_t nFieldSize);
    static std::size_t nNextPrime(std::size_t nValue);
    static std::size_t nPowMod(std::size_t nBase, std::size_t nExponent, std::size_t nModulus);

    void buildMatrix();
    void findBestParameters(
        std::size_t& nFieldSize,
        std::size_t& nCodeLength,
        std::size_t& nMessageLength,
        std::size_t& nRowCount
    ) const;

    std::size_t                   m_nGroupSize;
    std::size_t                   m_nDetectionThreshold;
    std::vector<std::vector<bool>> m_vecRows;
};
}

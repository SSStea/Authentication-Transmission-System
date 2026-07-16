#pragma once

#include "tesla/crypto/CryptoTypes.h"

namespace tesla::crypto
{
/**
 * @brief 提供密码数据比较和类型转换等无状态辅助操作。
 */
class CryptoUtilities final
{
public:
    /**
     * @brief 以常量时间比较两个摘要，避免普通比较引入时序差异。
     * @param digLeft 左侧摘要。
     * @param digRight 右侧摘要。
     * @return 两个摘要完全相同时返回true。
     */
    static bool bDigestEquals(const Digest& digLeft, const Digest& digRight) noexcept;

    /**
     * @brief 将固定长度摘要复制为可变长度字节缓冲区。
     * @param digValue 待转换摘要。
     * @return 包含相同原始字节的缓冲区。
     */
    static ByteBuffer vecToByteBuffer(const Digest& digValue);

private:
    CryptoUtilities() = delete;
};
}

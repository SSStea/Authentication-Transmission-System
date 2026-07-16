#pragma once

namespace tesla::crypto
{
/**
 * @brief 系统支持的固定32字节摘要算法。
 */
enum class CryptoAlgorithm
{
    Sha256,  ///< SHA-256。
    Sm3,     ///< 国密SM3。
    Sha3_256 ///< SHA3-256。
};
}

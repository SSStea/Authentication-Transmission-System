#pragma once

namespace tesla::core
{
/**
 * @brief 原生TESLA逐包验证结果。
 */
enum class NativePacketStatus
{
    Passed,       ///< 报文存在且MAC验证通过。
    MacFailed,    ///< 报文和MAC均存在，但MAC不匹配。
    MissingPacket, ///< 固定槽位上的报文缺失。
    MissingMac    ///< 报文存在，但对应MAC缺失。
};
}

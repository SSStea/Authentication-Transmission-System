#pragma once

namespace tesla::core
{
/**
 * @brief 改进TESLA验证实际采用的判定路径。
 */
enum class ImprovedVerificationPath
{
    FastGroupPass,       ///< 快速组标签直接验证通过，未执行逐包MAC验证。
    KsRsFallback,        ///< 快速验证不可用或失败，已进入KS+RS定位路径。
    IncompleteGroupTags  ///< 必需的SAMD标签或快速组标签不完整，无法验证。
};
}

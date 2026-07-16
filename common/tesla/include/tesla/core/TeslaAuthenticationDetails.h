#pragma once

#include "tesla/core/ImprovedAuthenticationDetails.h"
#include "tesla/core/NativeAuthenticationDetails.h"

#include <variant>

namespace tesla::core
{
/**
 * @brief 统一承载当前策略生成或接收的模式专用认证详情。
 *
 * 使用variant防止把原生模式和改进模式的所有字段平铺到同一结构体中。
 */
using TeslaAuthenticationDetails = std::variant<
    NativeAuthenticationDetails,
    ImprovedAuthenticationDetails
>;
}

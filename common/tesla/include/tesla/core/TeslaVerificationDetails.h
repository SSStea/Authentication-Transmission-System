#pragma once

#include "tesla/core/ImprovedVerificationDetails.h"
#include "tesla/core/NativeVerificationDetails.h"

#include <variant>

namespace tesla::core
{
/**
 * @brief 统一承载原生或改进TESLA的模式专用验证详情。
 */
using TeslaVerificationDetails = std::variant<
    NativeVerificationDetails,
    ImprovedVerificationDetails
>;
}

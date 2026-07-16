#pragma once

#include "tesla/core/NativePacketStatus.h"

#include <vector>

namespace tesla::core
{
/**
 * @brief 保存原生TESLA模式的逐包验证状态。
 */
class NativeVerificationDetails final
{
public:
    /**
     * @brief 创建与认证组固定槽位一一对应的验证详情。
     * @param vecPacketStatuses 按槽位顺序排列的逐包状态。
     */
    explicit NativeVerificationDetails(std::vector<NativePacketStatus> vecPacketStatuses);

    /** @return 保持固定槽位顺序的逐包验证状态。 */
    const std::vector<NativePacketStatus>& vecPacketStatuses() const noexcept;

private:
    std::vector<NativePacketStatus> m_vecPacketStatuses;
};
}

#pragma once

#include "tesla/core/AuthenticationRuntimeTypes.h"

namespace tesla::node_agent
{
/** @brief 查询Ubuntu Server的systemd-timesyncd或Chrony同步状态。 */
class SystemTimeSynchronization final
{
public:
    static core::TimeSynchronizationStatus stsQuery();

private:
    SystemTimeSynchronization() = delete;
};
}

#pragma once

#include <string>

namespace tesla::node_agent
{
/** @brief 从Linux活动IPv4接口中自动选择局域网接口并生成UAV节点名称。 */
class NetworkInterfaceSelector final
{
public:
    static std::string strSelectIpv4Address();
    static std::string strCreateNodeName(const std::string& strIpv4Address);

private:
    NetworkInterfaceSelector() = delete;
};
}

#include "tesla/node_agent/SystemTimeSynchronization.h"

#include <array>
#include <cstdio>
#include <string>

namespace tesla::node_agent
{
namespace
{
std::string strRunCommand(const char* pCommand)
{
    std::array<char, 256> arrBuffer{};
    std::string           strOutput;
    FILE*                 pPipe = popen(pCommand, "r");

    if (pPipe == nullptr)
    {
        return "";
    }

    while (fgets(arrBuffer.data(), static_cast<int>(arrBuffer.size()), pPipe)
        != nullptr)
    {
        strOutput.append(arrBuffer.data());
    }

    const int nExitCode = pclose(pPipe);
    return nExitCode == 0 ? strOutput : "";
}
}

core::TimeSynchronizationStatus SystemTimeSynchronization::stsQuery()
{
    const std::string strSystemd = strRunCommand(
        "timedatectl show --property=NTPSynchronized --value 2>/dev/null"
    );
    if (strSystemd.find("yes") != std::string::npos)
    {
        return core::TimeSynchronizationStatus(
            true,
            5,
            "systemd reports the node clock is synchronized"
        );
    }

    const std::string strChrony = strRunCommand(
        "chronyc tracking 2>/dev/null"
    );
    if (strChrony.find("Leap status") != std::string::npos
        && strChrony.find("Normal") != std::string::npos)
    {
        return core::TimeSynchronizationStatus(
            true,
            5,
            "Chrony reports a normal synchronized clock"
        );
    }

    return core::TimeSynchronizationStatus(
        false,
        0,
        "NTP/Chrony synchronization is unavailable; authentication start is blocked"
    );
}
}

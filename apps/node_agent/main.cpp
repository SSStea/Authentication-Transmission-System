#include <iostream>

#if defined(__linux__)

#include "tesla/node_agent/NetworkInterfaceSelector.h"
#include "tesla/node_agent/NodeAgentConfig.h"
#include "tesla/node_agent/NodeAgentService.h"

#include <atomic>
#include <chrono>
#include <csignal>
#include <exception>
#include <thread>

namespace
{
std::atomic<bool> g_bStopRequested{false};

void handleSignal(int)
{
    g_bStopRequested = true;
}
}

int main()
{
    std::signal(SIGINT, handleSignal);
    std::signal(SIGTERM, handleSignal);

    try
    {
        const std::string strAddress =
            tesla::node_agent::NetworkInterfaceSelector::strSelectIpv4Address();
        const std::string strNodeName =
            tesla::node_agent::NetworkInterfaceSelector::strCreateNodeName(strAddress);
        tesla::node_agent::NodeAgentService svcAgent(
            tesla::node_agent::NodeAgentConfig(strNodeName, strAddress)
        );

        svcAgent.start();
        std::cout
            << "NodeAgent " << strNodeName << " is running on " << strAddress
            << "; press Ctrl+C to stop." << std::endl;

        while (!g_bStopRequested.load())
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        svcAgent.stop();
        std::cout << "NodeAgent stopped." << std::endl;
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "NodeAgent startup failed: " << exError.what() << std::endl;
        return 1;
    }
}

#else

int main()
{
    // Windows目标用于在Visual Studio中审阅工程；正式NodeAgent运行在Ubuntu Server。
    std::cout << "NodeAgent POSIX runtime is built on Linux; sources are available for review."
              << std::endl;
    return 0;
}

#endif

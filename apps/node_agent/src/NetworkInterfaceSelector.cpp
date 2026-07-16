#include "tesla/node_agent/NetworkInterfaceSelector.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace tesla::node_agent
{
namespace
{
// 保存经过基础状态筛选的接口地址及其局域网优先级评分。
class InterfaceCandidate final
{
public:
    InterfaceCandidate(std::string strAddress, int nScore)
        : m_strAddress(std::move(strAddress)),
          m_nScore(nScore)
    {
    }

    const std::string& strAddress() const noexcept
    {
        return m_strAddress;
    }

    int nScore() const noexcept
    {
        return m_nScore;
    }

private:
    std::string m_strAddress;
    int         m_nScore;
};

bool bStartsWith(const std::string& strValue, const std::string& strPrefix)
{
    return strValue.rfind(strPrefix, 0) == 0;
}

bool bIsPrivateIpv4(std::uint32_t u32HostAddress)
{
    const std::uint8_t u8First = static_cast<std::uint8_t>((u32HostAddress >> 24U) & 0xFFU);
    const std::uint8_t u8Second = static_cast<std::uint8_t>((u32HostAddress >> 16U) & 0xFFU);
    return u8First == 10
        || (u8First == 172 && u8Second >= 16 && u8Second <= 31)
        || (u8First == 192 && u8Second == 168);
}

int nInterfaceScore(const std::string& strName, std::uint32_t u32HostAddress)
{
    int nScore = bIsPrivateIpv4(u32HostAddress) ? 100 : 0;

    if (bStartsWith(strName, "wl"))
    {
        nScore += 50;
    }
    else if (bStartsWith(strName, "en") || bStartsWith(strName, "eth"))
    {
        nScore += 40;
    }

    // 容器和隧道接口只作为没有物理接口时的最后候选。
    if (bStartsWith(strName, "docker")
        || bStartsWith(strName, "veth")
        || bStartsWith(strName, "virbr")
        || bStartsWith(strName, "tun")
        || bStartsWith(strName, "tap"))
    {
        nScore -= 100;
    }

    return nScore;
}
}

std::string NetworkInterfaceSelector::strSelectIpv4Address()
{
    ifaddrs* pInterfaces = nullptr;
    if (getifaddrs(&pInterfaces) != 0)
    {
        throw std::runtime_error("Unable to enumerate Linux network interfaces");
    }

    std::vector<InterfaceCandidate> vecCandidates;
    for (ifaddrs* pCurrent = pInterfaces; pCurrent != nullptr; pCurrent = pCurrent->ifa_next)
    {
        if (pCurrent->ifa_addr == nullptr || pCurrent->ifa_addr->sa_family != AF_INET)
        {
            continue;
        }

        const unsigned int uFlags = pCurrent->ifa_flags;
        if ((uFlags & IFF_UP) == 0 || (uFlags & IFF_RUNNING) == 0 || (uFlags & IFF_LOOPBACK) != 0)
        {
            continue;
        }

        const auto* pAddress = reinterpret_cast<const sockaddr_in*>(pCurrent->ifa_addr);
        char arrAddress[INET_ADDRSTRLEN]{};
        if (inet_ntop(AF_INET, &pAddress->sin_addr, arrAddress, sizeof(arrAddress)) == nullptr)
        {
            continue;
        }

        const std::uint32_t u32HostAddress = ntohl(pAddress->sin_addr.s_addr);
        vecCandidates.emplace_back(
            arrAddress,
            nInterfaceScore(pCurrent->ifa_name, u32HostAddress)
        );
    }

    freeifaddrs(pInterfaces);
    if (vecCandidates.empty())
    {
        throw std::runtime_error("No active non-loopback IPv4 interface is available");
    }

    const auto itrBest = std::max_element(
        vecCandidates.begin(),
        vecCandidates.end(),
        [](const InterfaceCandidate& lhsCandidate, const InterfaceCandidate& rhsCandidate)
        {
            return lhsCandidate.nScore() < rhsCandidate.nScore();
        }
    );
    return itrBest->strAddress();
}

std::string NetworkInterfaceSelector::strCreateNodeName(const std::string& strIpv4Address)
{
    in_addr adrIpv4{};
    if (inet_pton(AF_INET, strIpv4Address.c_str(), &adrIpv4) != 1)
    {
        throw std::invalid_argument("Node name requires a valid IPv4 address");
    }

    const std::uint32_t u32HostAddress = ntohl(adrIpv4.s_addr);
    const std::uint32_t u32LastOctet = u32HostAddress & 0xFFU;
    return "UAV-" + std::to_string(u32LastOctet);
}
}

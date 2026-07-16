#include "tesla/core/ReceiverAuthenticationContextStore.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
void ReceiverAuthenticationContextStore::replaceAll(
    std::vector<ReceiverAuthenticationContext> vecContexts
)
{
    std::map<std::string, std::string> mapSenderIdByIpAddress;
    std::map<std::string, std::string> mapIpAddressBySenderId;
    std::map<SenderChainKey, ReceiverAuthenticationContext> mapContextBySenderChain;

    // 所有映射先在局部容器验证，任何一个冲突都不会影响当前正在使用的上下文。
    for (ReceiverAuthenticationContext& ctxContext : vecContexts)
    {
        const std::string& strSenderId = ctxContext.strSenderId();
        const std::string& strIpAddress = ctxContext.strSenderIpAddress();

        const auto [itrIp, bIpInserted] = mapSenderIdByIpAddress.emplace(
            strIpAddress,
            strSenderId
        );
        if (!bIpInserted && itrIp->second != strSenderId)
        {
            throw std::invalid_argument(
                "One source IP address cannot map to multiple sender IDs"
            );
        }

        const auto [itrSender, bSenderInserted] = mapIpAddressBySenderId.emplace(
            strSenderId,
            strIpAddress
        );
        if (!bSenderInserted && itrSender->second != strIpAddress)
        {
            throw std::invalid_argument(
                "One sender ID cannot map to multiple source IP addresses"
            );
        }

        const SenderChainKey keyContext(strSenderId, ctxContext.u64ChainId());
        const auto [itrContext, bContextInserted] = mapContextBySenderChain.emplace(
            keyContext,
            std::move(ctxContext)
        );
        static_cast<void>(itrContext);

        if (!bContextInserted)
        {
            throw std::invalid_argument(
                "Receiver authentication contexts contain a duplicate sender-chain pair"
            );
        }
    }

    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    m_mapSenderIdByIpAddress.swap(mapSenderIdByIpAddress);
    m_mapIpAddressBySenderId.swap(mapIpAddressBySenderId);
    m_mapContextBySenderChain.swap(mapContextBySenderChain);
}

ReceiverAuthenticationContextLookupResult ReceiverAuthenticationContextStore::resFind(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    const auto itrSender = m_mapSenderIdByIpAddress.find(strSourceIpAddress);

    // 必须先通过实际来源IP确定Sender，不能信任报文内自报的senderId。
    if (itrSender == m_mapSenderIdByIpAddress.end())
    {
        return ReceiverAuthenticationContextLookupError::UnknownSourceIp;
    }

    const auto itrContext = m_mapContextBySenderChain.find(
        SenderChainKey(itrSender->second, u64ChainId)
    );
    if (itrContext == m_mapContextBySenderChain.end())
    {
        return ReceiverAuthenticationContextLookupError::UnknownChainId;
    }

    return itrContext->second;
}

std::size_t ReceiverAuthenticationContextStore::nSize() const
{
    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    return m_mapContextBySenderChain.size();
}
}

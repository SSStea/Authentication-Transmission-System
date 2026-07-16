#pragma once

#include "tesla/core/ReceiverAuthenticationContext.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
enum class ReceiverAuthenticationContextLookupError
{
    UnknownSourceIp,
    UnknownChainId
};

using ReceiverAuthenticationContextLookupResult = std::variant<
    ReceiverAuthenticationContext,
    ReceiverAuthenticationContextLookupError
>;

/**
 * @brief 以来源IP先映射Sender，再以Sender和chainId查找公开认证上下文。
 *
 * replaceAll先在临时容器中完成全部校验，确认无冲突后一次性交换，避免半更新状态。
 */
class ReceiverAuthenticationContextStore final
{
public:
    void replaceAll(std::vector<ReceiverAuthenticationContext> vecContexts);

    ReceiverAuthenticationContextLookupResult resFind(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const;

    std::size_t nSize() const;

private:
    using SenderChainKey = std::pair<std::string, std::uint64_t>;

    mutable std::mutex                                  m_mtxContexts;
    std::map<std::string, std::string>                  m_mapSenderIdByIpAddress;
    std::map<std::string, std::string>                  m_mapIpAddressBySenderId;
    std::map<SenderChainKey, ReceiverAuthenticationContext> m_mapContextBySenderChain;
};
}

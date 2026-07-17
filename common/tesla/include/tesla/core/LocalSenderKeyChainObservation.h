#pragma once

#include "tesla/crypto/CryptoTypes.h"

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace tesla::core
{
/**
 * @brief PC作为Sender时可在本机展示的完整密钥链快照。
 *
 * 该类型包含私有密钥值，只允许进入本地GUI回调，不属于NodeControl协议，
 * 因此不会发送给Manager、MONITOR或其他Receiver。
 */
class LocalSenderKeyChainSnapshot final
{
public:
    LocalSenderKeyChainSnapshot(
        std::string strSenderId,
        std::uint64_t u64ChainId,
        std::uint32_t u32DisclosureDelay,
        std::vector<crypto::Digest> vecKeys
    );

    const std::string& strSenderId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    const std::vector<crypto::Digest>& vecKeys() const noexcept;

private:
    std::string                 m_strSenderId;
    std::uint64_t               m_u64ChainId;
    std::uint32_t               m_u32DisclosureDelay;
    std::vector<crypto::Digest> m_vecKeys;
};

/** @brief 更新本地密钥链当前使用和已披露范围，不重复复制完整密钥。 */
class LocalSenderKeyChainProgress final
{
public:
    LocalSenderKeyChainProgress(
        std::string strRoundId,
        std::uint64_t u64ChainId,
        std::uint32_t u32CurrentDataKeyIndex,
        std::uint32_t u32DisclosedThroughKeyIndex,
        bool bCompleted
    );

    const std::string& strRoundId() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32CurrentDataKeyIndex() const noexcept;
    std::uint32_t u32DisclosedThroughKeyIndex() const noexcept;
    bool bCompleted() const noexcept;

private:
    std::string   m_strRoundId;
    std::uint64_t m_u64ChainId;
    std::uint32_t m_u32CurrentDataKeyIndex;
    std::uint32_t m_u32DisclosedThroughKeyIndex;
    bool          m_bCompleted;
};

using LocalSenderKeyChainObservation = std::variant<
    LocalSenderKeyChainSnapshot,
    LocalSenderKeyChainProgress
>;
}

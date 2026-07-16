#pragma once

#include "tesla/crypto/CryptoTypes.h"

#include <optional>
#include <vector>

namespace tesla::core
{
/**
 * @brief 原生TESLA模式生成或接收的逐包MAC详情。
 */
class NativeAuthenticationDetails final
{
public:
    /**
     * @brief 保存与认证组固定槽位一一对应的MAC。
     * @param vecPacketMacs 每个位置的MAC；空值表示该位置未携带MAC。
     */
    explicit NativeAuthenticationDetails(
        std::vector<std::optional<crypto::Digest>> vecPacketMacs
    );

    /** @return 保持固定槽位顺序的逐包MAC只读引用。 */
    const std::vector<std::optional<crypto::Digest>>& vecPacketMacs() const noexcept;

private:
    std::vector<std::optional<crypto::Digest>> m_vecPacketMacs;
};

/** @brief 原生TESLA逐包验证结果。 */
enum class NativePacketStatus
{
    Passed,
    MacFailed,
    MissingPacket,
    MissingMac
};

/** @brief 保存原生TESLA模式的逐包验证状态。 */
class NativeVerificationDetails final
{
public:
    explicit NativeVerificationDetails(
        std::vector<NativePacketStatus> vecPacketStatuses
    );

    const std::vector<NativePacketStatus>& vecPacketStatuses() const noexcept;

private:
    std::vector<NativePacketStatus> m_vecPacketStatuses;
};
}

#pragma once

namespace tesla::protocol
{
/** @brief 控制面可选择的固定32字节摘要与HMAC算法。 */
enum class AuthenticationCryptoAlgorithm
{
    Sha256,
    Sm3,
    Sha3_256
};

/** @brief Sender和Receiver配置确认消息中的目标类型。 */
enum class AuthenticationConfigTarget
{
    Sender,
    Receiver
};
}

#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <string>

namespace tesla::protocol
{
/**
 * @brief 编解码认证控制消息中的固定长度十六进制值。
 *
 * chainId使用16个十六进制字符而非JSON数字，避免任意uint64值被JSON双精度数截断。
 */
class AuthenticationControlValueCodec final
{
public:
    static std::string strEncodeChainId(std::uint64_t u64ChainId);
    static std::uint64_t u64DecodeChainId(const std::string& strChainId);

    static std::string strEncodeBlock(const BinaryBlock& arrBlock);
    static BinaryBlock arrDecodeBlock(const std::string& strBlock);

private:
    AuthenticationControlValueCodec() = delete;
};
}

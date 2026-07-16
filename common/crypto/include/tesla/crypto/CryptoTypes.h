#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tesla::crypto
{
/// 所有受支持摘要算法统一使用的摘要字节数。
constexpr std::size_t DIGEST_SIZE = 32;

/// 任意长度的二进制数据缓冲区。
using ByteBuffer = std::vector<std::uint8_t>;

/// 固定32字节的摘要或消息认证码。
using Digest = std::array<std::uint8_t, DIGEST_SIZE>;
}

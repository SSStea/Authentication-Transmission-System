#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace tesla::protocol
{
/// 协议编解码统一使用的任意长度字节缓冲区。
using ByteBuffer = std::vector<std::uint8_t>;

/// TESLA Message、Key、MAC和标签共同使用的固定32字节二进制块。
constexpr std::size_t BINARY_BLOCK_SIZE = 32;
using BinaryBlock = std::array<std::uint8_t, BINARY_BLOCK_SIZE>;
}

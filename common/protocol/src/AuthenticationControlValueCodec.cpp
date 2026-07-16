#include "tesla/protocol/AuthenticationControlValueCodec.h"

#include <array>
#include <cstddef>
#include <stdexcept>

namespace tesla::protocol
{
namespace
{
std::uint8_t u8DecodeHexCharacter(char chValue)
{
    if (chValue >= '0' && chValue <= '9')
    {
        return static_cast<std::uint8_t>(chValue - '0');
    }

    if (chValue >= 'a' && chValue <= 'f')
    {
        return static_cast<std::uint8_t>(chValue - 'a' + 10);
    }

    if (chValue >= 'A' && chValue <= 'F')
    {
        return static_cast<std::uint8_t>(chValue - 'A' + 10);
    }

    throw std::invalid_argument("Authentication hex value contains an invalid character");
}

std::string strEncodeBytes(const std::uint8_t* pBytes, std::size_t nByteCount)
{
    static constexpr std::array<char, 16> arrHex = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    std::string strResult;
    strResult.reserve(nByteCount * 2);

    for (std::size_t nIndex = 0; nIndex < nByteCount; ++nIndex)
    {
        const std::uint8_t u8Value = pBytes[nIndex];
        strResult.push_back(arrHex[(u8Value >> 4U) & 0x0FU]);
        strResult.push_back(arrHex[u8Value & 0x0FU]);
    }

    return strResult;
}
}

std::string AuthenticationControlValueCodec::strEncodeChainId(std::uint64_t u64ChainId)
{
    std::array<std::uint8_t, 8> arrBytes{};
    for (std::size_t nIndex = 0; nIndex < arrBytes.size(); ++nIndex)
    {
        const std::size_t nShift = (arrBytes.size() - 1U - nIndex) * 8U;
        arrBytes[nIndex] = static_cast<std::uint8_t>(u64ChainId >> nShift);
    }

    return strEncodeBytes(arrBytes.data(), arrBytes.size());
}

std::uint64_t AuthenticationControlValueCodec::u64DecodeChainId(
    const std::string& strChainId
)
{
    if (strChainId.size() != 16)
    {
        throw std::invalid_argument("Authentication chain ID must contain 16 hex characters");
    }

    std::uint64_t u64Result = 0;
    for (char chValue : strChainId)
    {
        u64Result = (u64Result << 4U) | u8DecodeHexCharacter(chValue);
    }

    return u64Result;
}

std::string AuthenticationControlValueCodec::strEncodeBlock(const BinaryBlock& arrBlock)
{
    return strEncodeBytes(arrBlock.data(), arrBlock.size());
}

BinaryBlock AuthenticationControlValueCodec::arrDecodeBlock(const std::string& strBlock)
{
    if (strBlock.size() != BINARY_BLOCK_SIZE * 2)
    {
        throw std::invalid_argument(
            "Authentication binary block must contain exactly 64 hex characters"
        );
    }

    BinaryBlock arrResult{};
    for (std::size_t nIndex = 0; nIndex < arrResult.size(); ++nIndex)
    {
        const std::uint8_t u8High = u8DecodeHexCharacter(strBlock[nIndex * 2]);
        const std::uint8_t u8Low = u8DecodeHexCharacter(strBlock[nIndex * 2 + 1]);
        arrResult[nIndex] = static_cast<std::uint8_t>((u8High << 4U) | u8Low);
    }

    return arrResult;
}
}

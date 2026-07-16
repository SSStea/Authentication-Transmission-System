#include "tesla/protocol/TcpFrame.h"

#include <nlohmann/json.hpp>

#include <limits>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
JsonControlFramePayload::JsonControlFramePayload(std::string strJson)
    : m_strJson(std::move(strJson))
{
    // 控制帧必须恰好包含一个JSON对象，数组、标量和无效UTF-8都在边界处拒绝。
    const nlohmann::json jsnPayload = nlohmann::json::parse(
        m_strJson,
        nullptr,
        false,
        true
    );

    if (jsnPayload.is_discarded() || !jsnPayload.is_object())
    {
        throw std::invalid_argument("JSON control payload must be one valid object");
    }
}

const std::string& JsonControlFramePayload::strJson() const noexcept
{
    return m_strJson;
}

FileBinaryChunk::FileBinaryChunk(
    std::uint64_t u64ChainId,
    std::uint32_t u32ChunkIndex,
    ByteBuffer vecData
)
    : m_u64ChainId(u64ChainId),
      m_u32ChunkIndex(u32ChunkIndex),
      m_vecData(std::move(vecData))
{
    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("File chunk chain ID must not be zero");
    }

    if (m_u32ChunkIndex == 0)
    {
        throw std::invalid_argument("File chunk index must start at one");
    }

    if (m_vecData.empty())
    {
        throw std::invalid_argument("File chunk data must not be empty");
    }

    if (m_vecData.size() > std::numeric_limits<std::uint32_t>::max())
    {
        throw std::invalid_argument("File chunk data is too large");
    }
}

std::uint64_t FileBinaryChunk::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t FileBinaryChunk::u32ChunkIndex() const noexcept
{
    return m_u32ChunkIndex;
}

const ByteBuffer& FileBinaryChunk::vecData() const noexcept
{
    return m_vecData;
}

TcpFrame::TcpFrame(TcpFramePayload varPayload)
    : m_varPayload(std::move(varPayload))
{
}

TcpFrameType TcpFrame::type() const noexcept
{
    if (std::holds_alternative<JsonControlFramePayload>(m_varPayload))
    {
        return TcpFrameType::JsonControl;
    }

    return TcpFrameType::FileBinaryChunk;
}

const TcpFramePayload& TcpFrame::varPayload() const noexcept
{
    return m_varPayload;
}
}

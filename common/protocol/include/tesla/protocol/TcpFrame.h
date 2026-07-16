#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstdint>
#include <string>
#include <variant>

namespace tesla::protocol
{
enum class TcpFrameType : std::uint8_t
{
    JsonControl = 0x01,
    FileBinaryChunk = 0x02
};

/** @brief 保存一个已经验证为完整JSON对象的控制帧载荷。 */
class JsonControlFramePayload final
{
public:
    explicit JsonControlFramePayload(std::string strJson);

    const std::string& strJson() const noexcept;

private:
    std::string m_strJson;
};

/** @brief 表示TCP文件上传分块；它与32B TESLA Message分片没有类型复用关系。 */
class FileBinaryChunk final
{
public:
    FileBinaryChunk(
        std::uint64_t u64ChainId,
        std::uint32_t u32ChunkIndex,
        ByteBuffer vecData
    );

    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32ChunkIndex() const noexcept;
    const ByteBuffer& vecData() const noexcept;

private:
    std::uint64_t m_u64ChainId;
    std::uint32_t m_u32ChunkIndex;
    ByteBuffer    m_vecData;
};

using TcpFramePayload = std::variant<JsonControlFramePayload, FileBinaryChunk>;

/** @brief 统一TCP长度前缀帧；帧类型由模式专用载荷自动推导。 */
class TcpFrame final
{
public:
    explicit TcpFrame(TcpFramePayload varPayload);

    TcpFrameType type() const noexcept;
    const TcpFramePayload& varPayload() const noexcept;

private:
    TcpFramePayload m_varPayload;
};
}

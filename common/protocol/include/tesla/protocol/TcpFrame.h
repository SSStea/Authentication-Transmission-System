#pragma once

#include "tesla/protocol/ProtocolTypes.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

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

using TcpFrameDecodeResult = std::variant<TcpFrame, ProtocolDecodeError>;

/** @brief 对一整个TCP长度前缀帧逐字段编解码，不处理流分段。 */
class TcpFrameCodec final
{
public:
    static constexpr std::size_t LENGTH_PREFIX_SIZE = 4;
    static constexpr std::size_t TYPE_SIZE = 1;

    static ByteBuffer vecEncode(const TcpFrame& frmFrame);
    static TcpFrameDecodeResult resDecode(const ByteBuffer& vecFrameBytes);

private:
    TcpFrameCodec() = delete;
};

/** @brief 一次流输入后解析出的完整帧以及可选的致命协议错误。 */
class TcpFrameStreamDecodeBatch final
{
public:
    TcpFrameStreamDecodeBatch(
        std::vector<TcpFrame> vecFrames,
        std::optional<ProtocolDecodeError> optError
    );

    const std::vector<TcpFrame>& vecFrames() const noexcept;
    const std::optional<ProtocolDecodeError>& optError() const noexcept;

private:
    std::vector<TcpFrame>              m_vecFrames;
    std::optional<ProtocolDecodeError> m_optError;
};

/**
 * @brief 将任意分片或粘连的TCP字节流恢复为完整帧。
 *
 * 帧模型、整帧Codec和流式拆帧器共享同一帧边界与长度约束，因此集中在TCP帧模块。
 */
class TcpFrameStreamDecoder final
{
public:
    explicit TcpFrameStreamDecoder(
        std::size_t nMaximumFrameLength = 16U * 1024U * 1024U
    );

    TcpFrameStreamDecodeBatch batConsume(const ByteBuffer& vecBytes);
    void reset() noexcept;

private:
    std::size_t m_nMaximumFrameLength;
    ByteBuffer  m_vecPendingBytes;
};
}

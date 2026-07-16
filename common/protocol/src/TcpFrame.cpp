#include "tesla/protocol/TcpFrame.h"

#include "BinaryCodecUtilities.h"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::protocol
{
namespace
{
TcpFrameDecodeResult errCreate(
    ProtocolDecodeErrorCode errCode,
    const std::string& strMessage
)
{
    return ProtocolDecodeError(errCode, strMessage);
}
}

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

ByteBuffer TcpFrameCodec::vecEncode(const TcpFrame& frmFrame)
{
    ByteBuffer vecPayload;

    // 先生成模式专用payload，再统一添加4B长度和1B类型，避免两种帧各自维护外层格式。
    if (frmFrame.type() == TcpFrameType::JsonControl)
    {
        const std::string& strJson = std::get<JsonControlFramePayload>(
            frmFrame.varPayload()
        ).strJson();
        vecPayload.assign(strJson.begin(), strJson.end());
    }
    else
    {
        const FileBinaryChunk& chkFile = std::get<FileBinaryChunk>(frmFrame.varPayload());
        detail::appendUint64(vecPayload, chkFile.u64ChainId());
        detail::appendUint32(vecPayload, chkFile.u32ChunkIndex());
        detail::appendUint32(vecPayload, static_cast<std::uint32_t>(chkFile.vecData().size()));
        detail::appendBytes(vecPayload, chkFile.vecData().data(), chkFile.vecData().size());
    }

    if (vecPayload.size() > std::numeric_limits<std::uint32_t>::max() - TYPE_SIZE)
    {
        throw std::length_error("TCP frame payload is too large");
    }

    ByteBuffer vecFrame;
    vecFrame.reserve(LENGTH_PREFIX_SIZE + TYPE_SIZE + vecPayload.size());
    detail::appendUint32(
        vecFrame,
        static_cast<std::uint32_t>(TYPE_SIZE + vecPayload.size())
    );
    vecFrame.push_back(static_cast<std::uint8_t>(frmFrame.type()));
    detail::appendBytes(vecFrame, vecPayload.data(), vecPayload.size());
    return vecFrame;
}

TcpFrameDecodeResult TcpFrameCodec::resDecode(const ByteBuffer& vecFrameBytes)
{
    if (vecFrameBytes.size() < LENGTH_PREFIX_SIZE + TYPE_SIZE)
    {
        return errCreate(
            ProtocolDecodeErrorCode::InvalidFrameLength,
            "TCP frame is shorter than its length prefix and type"
        );
    }

    try
    {
        detail::BinaryReader rdrFrame(vecFrameBytes);
        const std::uint32_t u32FrameLength = rdrFrame.u32Read();

        if (u32FrameLength < TYPE_SIZE
            || u32FrameLength != vecFrameBytes.size() - LENGTH_PREFIX_SIZE)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidFrameLength,
                "TCP frame length prefix does not match the supplied bytes"
            );
        }

        const std::uint8_t u8FrameType = rdrFrame.arrRead<1>()[0];
        const ByteBuffer vecPayload = rdrFrame.vecRead(rdrFrame.nRemaining());

        if (u8FrameType == static_cast<std::uint8_t>(TcpFrameType::JsonControl))
        {
            try
            {
                return TcpFrame(JsonControlFramePayload(
                    std::string(vecPayload.begin(), vecPayload.end())
                ));
            }
            catch (const std::invalid_argument&)
            {
                return errCreate(
                    ProtocolDecodeErrorCode::InvalidJsonPayload,
                    "TCP JSON control payload is not one valid object"
                );
            }
        }

        if (u8FrameType != static_cast<std::uint8_t>(TcpFrameType::FileBinaryChunk))
        {
            return errCreate(
                ProtocolDecodeErrorCode::UnsupportedFrameType,
                "TCP frame type is not supported"
            );
        }

        constexpr std::size_t FILE_CHUNK_HEADER_SIZE = 16;
        if (vecPayload.size() < FILE_CHUNK_HEADER_SIZE)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidFileChunk,
                "TCP file chunk is shorter than its fixed header"
            );
        }

        detail::BinaryReader rdrChunk(vecPayload);
        const std::uint64_t u64ChainId = rdrChunk.u64Read();
        const std::uint32_t u32ChunkIndex = rdrChunk.u32Read();
        const std::uint32_t u32DataLength = rdrChunk.u32Read();

        if (u32DataLength != rdrChunk.nRemaining())
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidFileChunk,
                "TCP file chunk data length does not match its payload"
            );
        }

        try
        {
            return TcpFrame(FileBinaryChunk(
                u64ChainId,
                u32ChunkIndex,
                rdrChunk.vecRead(u32DataLength)
            ));
        }
        catch (const std::invalid_argument& exError)
        {
            return errCreate(
                ProtocolDecodeErrorCode::InvalidFileChunk,
                exError.what()
            );
        }
    }
    catch (const std::out_of_range&)
    {
        return errCreate(
            ProtocolDecodeErrorCode::InvalidFrameLength,
            "TCP frame ended inside a declared field"
        );
    }
}

TcpFrameStreamDecodeBatch::TcpFrameStreamDecodeBatch(
    std::vector<TcpFrame> vecFrames,
    std::optional<ProtocolDecodeError> optError
)
    : m_vecFrames(std::move(vecFrames)),
      m_optError(std::move(optError))
{
}

const std::vector<TcpFrame>& TcpFrameStreamDecodeBatch::vecFrames() const noexcept
{
    return m_vecFrames;
}

const std::optional<ProtocolDecodeError>&
TcpFrameStreamDecodeBatch::optError() const noexcept
{
    return m_optError;
}

TcpFrameStreamDecoder::TcpFrameStreamDecoder(std::size_t nMaximumFrameLength)
    : m_nMaximumFrameLength(nMaximumFrameLength)
{
    if (m_nMaximumFrameLength < TcpFrameCodec::TYPE_SIZE)
    {
        throw std::invalid_argument("Maximum TCP frame length must include its type byte");
    }
}

TcpFrameStreamDecodeBatch TcpFrameStreamDecoder::batConsume(const ByteBuffer& vecBytes)
{
    // recv()边界与应用帧无关，因此新字节先进入待解析缓存，再按长度前缀循环取帧。
    m_vecPendingBytes.insert(m_vecPendingBytes.end(), vecBytes.begin(), vecBytes.end());
    std::vector<TcpFrame> vecFrames;

    while (m_vecPendingBytes.size() >= TcpFrameCodec::LENGTH_PREFIX_SIZE)
    {
        const ByteBuffer vecLengthBytes(
            m_vecPendingBytes.begin(),
            m_vecPendingBytes.begin()
                + static_cast<std::ptrdiff_t>(TcpFrameCodec::LENGTH_PREFIX_SIZE)
        );
        detail::BinaryReader rdrLength(vecLengthBytes);
        const std::uint32_t u32FrameLength = rdrLength.u32Read();

        if (u32FrameLength < TcpFrameCodec::TYPE_SIZE)
        {
            reset();
            return TcpFrameStreamDecodeBatch(
                std::move(vecFrames),
                ProtocolDecodeError(
                    ProtocolDecodeErrorCode::InvalidFrameLength,
                    "TCP stream declared a frame without a type byte"
                )
            );
        }

        if (u32FrameLength > m_nMaximumFrameLength)
        {
            reset();
            return TcpFrameStreamDecodeBatch(
                std::move(vecFrames),
                ProtocolDecodeError(
                    ProtocolDecodeErrorCode::FrameTooLarge,
                    "TCP stream frame exceeds the configured safety limit"
                )
            );
        }

        const std::size_t nTotalLength =
            TcpFrameCodec::LENGTH_PREFIX_SIZE + u32FrameLength;
        if (m_vecPendingBytes.size() < nTotalLength)
        {
            break;
        }

        const ByteBuffer vecFrameBytes(
            m_vecPendingBytes.begin(),
            m_vecPendingBytes.begin() + static_cast<std::ptrdiff_t>(nTotalLength)
        );
        m_vecPendingBytes.erase(
            m_vecPendingBytes.begin(),
            m_vecPendingBytes.begin() + static_cast<std::ptrdiff_t>(nTotalLength)
        );

        TcpFrameDecodeResult resFrame = TcpFrameCodec::resDecode(vecFrameBytes);
        if (std::holds_alternative<ProtocolDecodeError>(resFrame))
        {
            const ProtocolDecodeError errDecode = std::get<ProtocolDecodeError>(resFrame);
            reset();
            return TcpFrameStreamDecodeBatch(std::move(vecFrames), errDecode);
        }

        vecFrames.push_back(std::get<TcpFrame>(std::move(resFrame)));
    }

    return TcpFrameStreamDecodeBatch(std::move(vecFrames), std::nullopt);
}

void TcpFrameStreamDecoder::reset() noexcept
{
    m_vecPendingBytes.clear();
}
}

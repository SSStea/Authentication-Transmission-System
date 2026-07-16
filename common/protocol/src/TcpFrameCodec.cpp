#include "tesla/protocol/TcpFrameCodec.h"

#include "BinaryCodecUtilities.h"

#include <limits>
#include <stdexcept>

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

        // 文件分块头固定为chainId、chunkIndex和dataLength，不把文件字节转换成JSON。
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
}

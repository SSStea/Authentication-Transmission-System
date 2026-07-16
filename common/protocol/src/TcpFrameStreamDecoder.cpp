#include "tesla/protocol/TcpFrameStreamDecoder.h"

#include "BinaryCodecUtilities.h"
#include "tesla/protocol/TcpFrameCodec.h"

#include <stdexcept>
#include <utility>
#include <variant>

namespace tesla::protocol
{
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

const std::optional<ProtocolDecodeError>& TcpFrameStreamDecodeBatch::optError() const noexcept
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
            m_vecPendingBytes.begin() + static_cast<std::ptrdiff_t>(TcpFrameCodec::LENGTH_PREFIX_SIZE)
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
            // 在等待或分配完整payload前拒绝超限长度，防止恶意长度导致无界缓存增长。
            reset();
            return TcpFrameStreamDecodeBatch(
                std::move(vecFrames),
                ProtocolDecodeError(
                    ProtocolDecodeErrorCode::FrameTooLarge,
                    "TCP stream frame exceeds the configured safety limit"
                )
            );
        }

        const std::size_t nTotalLength = TcpFrameCodec::LENGTH_PREFIX_SIZE + u32FrameLength;
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

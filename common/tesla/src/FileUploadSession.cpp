#include "tesla/core/FileUploadSession.h"

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace tesla::core
{
void FileUploadSession::begin(
    std::string strRequestId,
    std::uint64_t u64ChainId,
    std::uint64_t u64OriginalByteCount
)
{
    if (m_bActive)
    {
        throw std::logic_error("A file upload is already active on this connection");
    }

    if (strRequestId.empty() || u64ChainId == 0)
    {
        throw std::invalid_argument(
            "File upload request ID and chain ID must be valid"
        );
    }

    if (u64OriginalByteCount == 0
        || u64OriginalByteCount > workload::FileWorkload::MAXIMUM_FILE_SIZE)
    {
        throw std::invalid_argument("File upload size is outside the bounded range");
    }

    m_bActive = true;
    m_strRequestId = std::move(strRequestId);
    m_u64ChainId = u64ChainId;
    m_u64OriginalByteCount = u64OriginalByteCount;
    m_u32NextChunkIndex = 1;
    m_vecFileBytes.clear();
    m_vecFileBytes.reserve(static_cast<std::size_t>(u64OriginalByteCount));
}

void FileUploadSession::append(const protocol::FileBinaryChunk& chkChunk)
{
    if (!m_bActive)
    {
        throw std::logic_error("File chunk arrived without an active upload");
    }

    if (chkChunk.u64ChainId() != m_u64ChainId)
    {
        throw std::invalid_argument("File chunk chain ID does not match the upload");
    }

    if (chkChunk.u32ChunkIndex() != m_u32NextChunkIndex)
    {
        throw std::invalid_argument("File chunks must arrive once in continuous order");
    }

    const std::uint64_t u64RemainingByteCount =
        m_u64OriginalByteCount - m_vecFileBytes.size();
    const std::size_t nExpectedChunkSize = static_cast<std::size_t>(std::min<
        std::uint64_t
    >(MAXIMUM_CHUNK_SIZE, u64RemainingByteCount));
    if (chkChunk.vecData().size() != nExpectedChunkSize)
    {
        throw std::invalid_argument(
            "File upload chunk size does not match the 64 KiB transfer policy"
        );
    }

    m_vecFileBytes.insert(
        m_vecFileBytes.end(),
        chkChunk.vecData().begin(),
        chkChunk.vecData().end()
    );
    ++m_u32NextChunkIndex;
}

workload::FileWorkload FileUploadSession::wrkComplete(
    const std::string& strRequestId,
    std::uint64_t u64ChainId,
    std::uint32_t u32ChunkCount,
    std::uint64_t u64TransferredByteCount
)
{
    if (!m_bActive)
    {
        throw std::logic_error("File upload end arrived without an active upload");
    }

    if (strRequestId != m_strRequestId || u64ChainId != m_u64ChainId)
    {
        throw std::invalid_argument(
            "File upload end request ID or chain ID does not match"
        );
    }

    if (u32ChunkCount != u32ReceivedChunkCount())
    {
        throw std::invalid_argument("File upload end chunk count does not match");
    }

    if (u64TransferredByteCount != m_vecFileBytes.size()
        || u64TransferredByteCount != m_u64OriginalByteCount)
    {
        throw std::invalid_argument("File upload end byte count does not match");
    }

    std::vector<std::uint8_t> vecCompleted = std::move(m_vecFileBytes);
    reset();
    return workload::FileWorkload(std::move(vecCompleted));
}

void FileUploadSession::reset() noexcept
{
    m_bActive = false;
    m_strRequestId.clear();
    m_u64ChainId = 0;
    m_u64OriginalByteCount = 0;
    m_u32NextChunkIndex = 1;
    m_vecFileBytes.clear();
}

bool FileUploadSession::bIsActive() const noexcept
{
    return m_bActive;
}

std::uint64_t FileUploadSession::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

std::uint32_t FileUploadSession::u32ReceivedChunkCount() const noexcept
{
    return m_u32NextChunkIndex - 1U;
}

std::uint64_t FileUploadSession::u64ReceivedByteCount() const noexcept
{
    return static_cast<std::uint64_t>(m_vecFileBytes.size());
}
}

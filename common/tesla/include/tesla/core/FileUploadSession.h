#pragma once

#include "tesla/protocol/TcpFrame.h"
#include "tesla/workload/FileWorkload.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tesla::core
{
/**
 * @brief 验证一条MANAGER TCP连接上的完整文件上传事务。
 *
 * 会话严格要求requestId和chainId一致、分块从1连续递增、除末块外固定64KiB，
 * 且累计长度等于声明值。只有complete成功才会生成FileWorkload；错误可直接reset。
 */
class FileUploadSession final
{
public:
    static constexpr std::size_t MAXIMUM_CHUNK_SIZE = 64U * 1024U;

    void begin(
        std::string strRequestId,
        std::uint64_t u64ChainId,
        std::uint64_t u64OriginalByteCount
    );
    void append(const protocol::FileBinaryChunk& chkChunk);
    workload::FileWorkload wrkComplete(
        const std::string& strRequestId,
        std::uint64_t u64ChainId,
        std::uint32_t u32ChunkCount,
        std::uint64_t u64TransferredByteCount
    );
    void reset() noexcept;

    bool bIsActive() const noexcept;
    std::uint64_t u64ChainId() const noexcept;
    std::uint32_t u32ReceivedChunkCount() const noexcept;
    std::uint64_t u64ReceivedByteCount() const noexcept;

private:
    bool                      m_bActive = false;
    std::string               m_strRequestId;
    std::uint64_t             m_u64ChainId = 0;
    std::uint64_t             m_u64OriginalByteCount = 0;
    std::uint32_t             m_u32NextChunkIndex = 1;
    std::vector<std::uint8_t> m_vecFileBytes;
};
}

#pragma once

#include "tesla/protocol/MonitorControl.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace tesla::core
{
enum class ObservationStoreAppendResult
{
    Stored,
    Updated,
    CountOnly,
    AbnormalLimitReached
};

/**
 * @brief 保存报文、异常、分组定位和DoS汇总的线程安全有界记录。
 *
 * 普通报文使用环形队列；失败事件持有对应报文的共享记录，因此普通报文被淘汰后，
 * 当前轮次和最近完成轮次的异常详情仍可跳转。异常达到上限后只累计分类计数。
 */
class AuthenticationObservationStore final
{
public:
    static constexpr std::size_t DEFAULT_PACKET_LIMIT = 5000;
    static constexpr std::size_t DEFAULT_ABNORMAL_LIMIT = 2000;
    static constexpr std::size_t DEFAULT_GROUP_LIMIT = 512;
    static constexpr std::size_t DEFAULT_DOS_SUMMARY_LIMIT = 120;

    explicit AuthenticationObservationStore(
        std::size_t nPacketLimit = DEFAULT_PACKET_LIMIT,
        std::size_t nAbnormalLimit = DEFAULT_ABNORMAL_LIMIT,
        std::size_t nGroupLimit = DEFAULT_GROUP_LIMIT,
        std::size_t nDosSummaryLimit = DEFAULT_DOS_SUMMARY_LIMIT
    );

    /** @brief 开始新轮次，并只保留新轮次及紧邻的上一轮异常记录。 */
    void beginRound(std::string strRoundId);
    ObservationStoreAppendResult resAppend(
        const protocol::AuthenticationObservation& varObservation
    );
    void clear();

    std::vector<protocol::PacketObservationControlDetails>
        vecPacketSnapshot() const;
    std::vector<protocol::PacketFailureControlDetails>
        vecFailureSnapshot() const;
    /** @brief 返回异常记录仍引用的报文，用于监控端重连后恢复完整详情。 */
    std::vector<protocol::PacketObservationControlDetails>
        vecAbnormalPacketSnapshot() const;
    std::vector<protocol::ImprovedGroupObservationControlDetails>
        vecGroupSnapshot() const;
    std::vector<protocol::DosSummaryControlDetails>
        vecDosSummarySnapshot() const;
    std::optional<protocol::PacketObservationControlDetails> optPacket(
        std::uint64_t u64EventId
    ) const;

    std::size_t nFailureCount(
        protocol::AuthenticationFailureType typeFailure
    ) const;
    std::size_t nPacketCount() const;
    std::size_t nStoredFailureCount() const;
    std::uint64_t u64DiscardedAbnormalCount() const;

private:
    struct FailureRecord final
    {
        protocol::PacketFailureControlDetails detFailure;
        std::shared_ptr<protocol::PacketObservationControlDetails> ptrPacket;
    };

    ObservationStoreAppendResult resAppendPacket(
        const protocol::PacketObservationControlDetails& detPacket
    );
    ObservationStoreAppendResult resAppendFailure(
        const protocol::PacketFailureControlDetails& detFailure
    );
    ObservationStoreAppendResult resAppendGroup(
        const protocol::ImprovedGroupObservationControlDetails& detGroup
    );
    ObservationStoreAppendResult resAppendDosSummary(
        const protocol::DosSummaryControlDetails& detSummary
    );
    void removeExpiredFailures();
    void removeExpiredPacketIndexEntries();

    std::size_t m_nPacketLimit;
    std::size_t m_nAbnormalLimit;
    std::size_t m_nGroupLimit;
    std::size_t m_nDosSummaryLimit;

    mutable std::mutex m_mtxStore;
    std::string        m_strCurrentRoundId;
    std::string        m_strPreviousRoundId;
    std::deque<std::shared_ptr<protocol::PacketObservationControlDetails>>
        m_deqPackets;
    std::unordered_map<
        std::uint64_t,
        std::weak_ptr<protocol::PacketObservationControlDetails>
    > m_mapPacketByEventId;
    std::deque<FailureRecord> m_deqFailures;
    std::deque<protocol::ImprovedGroupObservationControlDetails> m_deqGroups;
    std::deque<protocol::DosSummaryControlDetails> m_deqDosSummaries;
    std::map<protocol::AuthenticationFailureType, std::size_t>
        m_mapFailureCounts;
    std::uint64_t m_u64DiscardedAbnormalCount;
    bool          m_bAbnormalLimitReported;
};
}

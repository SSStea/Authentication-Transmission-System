#include "tesla/core/AuthenticationObservationStore.h"

#include <algorithm>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <variant>

namespace tesla::core
{
namespace
{
std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}
}

AuthenticationObservationStore::AuthenticationObservationStore(
    std::size_t nPacketLimit,
    std::size_t nAbnormalLimit,
    std::size_t nGroupLimit,
    std::size_t nDosSummaryLimit
)
    : m_nPacketLimit(nPacketLimit),
      m_nAbnormalLimit(nAbnormalLimit),
      m_nGroupLimit(nGroupLimit),
      m_nDosSummaryLimit(nDosSummaryLimit),
      m_u64DiscardedAbnormalCount(0),
      m_bAbnormalLimitReported(false)
{
    if (m_nPacketLimit == 0
        || m_nAbnormalLimit < 2
        || m_nGroupLimit == 0
        || m_nDosSummaryLimit == 0)
    {
        throw std::invalid_argument("Observation store limits are invalid");
    }
}

void AuthenticationObservationStore::beginRound(std::string strRoundId)
{
    if (strRoundId.empty())
    {
        throw std::invalid_argument("Observation round ID must not be empty");
    }

    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    if (strRoundId == m_strCurrentRoundId)
    {
        return;
    }

    m_strPreviousRoundId = std::move(m_strCurrentRoundId);
    m_strCurrentRoundId = std::move(strRoundId);
    m_bAbnormalLimitReported = false;
    removeExpiredFailures();

    m_deqGroups.erase(
        std::remove_if(
            m_deqGroups.begin(),
            m_deqGroups.end(),
            [this](const protocol::ImprovedGroupObservationControlDetails& detGroup)
            {
                return detGroup.strRoundId() != m_strCurrentRoundId
                    && detGroup.strRoundId() != m_strPreviousRoundId;
            }
        ),
        m_deqGroups.end()
    );
    removeExpiredPacketIndexEntries();
}

ObservationStoreAppendResult AuthenticationObservationStore::resAppend(
    const protocol::AuthenticationObservation& varObservation
)
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return std::visit(
        [this](const auto& detObservation)
        {
            using ObservationType = std::decay_t<decltype(detObservation)>;
            if constexpr (std::is_same_v<
                    ObservationType,
                    protocol::PacketObservationControlDetails
                >)
            {
                return resAppendPacket(detObservation);
            }
            else if constexpr (std::is_same_v<
                    ObservationType,
                    protocol::PacketFailureControlDetails
                >)
            {
                return resAppendFailure(detObservation);
            }
            else if constexpr (std::is_same_v<
                    ObservationType,
                    protocol::ImprovedGroupObservationControlDetails
                >)
            {
                return resAppendGroup(detObservation);
            }
            else
            {
                return resAppendDosSummary(detObservation);
            }
        },
        varObservation
    );
}

void AuthenticationObservationStore::clear()
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    m_strCurrentRoundId.clear();
    m_strPreviousRoundId.clear();
    m_deqPackets.clear();
    m_mapPacketByEventId.clear();
    m_deqFailures.clear();
    m_deqGroups.clear();
    m_deqDosSummaries.clear();
    m_mapFailureCounts.clear();
    m_u64DiscardedAbnormalCount = 0;
    m_bAbnormalLimitReported = false;
}

std::vector<protocol::PacketObservationControlDetails>
AuthenticationObservationStore::vecPacketSnapshot() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    std::vector<protocol::PacketObservationControlDetails> vecPackets;
    vecPackets.reserve(m_deqPackets.size());
    for (const auto& ptrPacket : m_deqPackets)
    {
        vecPackets.push_back(*ptrPacket);
    }
    return vecPackets;
}

std::vector<protocol::PacketFailureControlDetails>
AuthenticationObservationStore::vecFailureSnapshot() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    std::vector<protocol::PacketFailureControlDetails> vecFailures;
    vecFailures.reserve(m_deqFailures.size());
    for (const FailureRecord& recFailure : m_deqFailures)
    {
        vecFailures.push_back(recFailure.detFailure);
    }
    return vecFailures;
}

std::vector<protocol::PacketObservationControlDetails>
AuthenticationObservationStore::vecAbnormalPacketSnapshot() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    std::vector<protocol::PacketObservationControlDetails> vecPackets;
    std::unordered_map<std::uint64_t, bool> mapIncludedEventIds;
    vecPackets.reserve(m_deqFailures.size());
    for (const FailureRecord& recFailure : m_deqFailures)
    {
        if (recFailure.ptrPacket == nullptr)
        {
            continue;
        }

        const std::uint64_t u64EventId = recFailure.ptrPacket->u64EventId();
        if (mapIncludedEventIds.emplace(u64EventId, true).second)
        {
            vecPackets.push_back(*recFailure.ptrPacket);
        }
    }
    return vecPackets;
}

std::vector<protocol::ImprovedGroupObservationControlDetails>
AuthenticationObservationStore::vecGroupSnapshot() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return std::vector<protocol::ImprovedGroupObservationControlDetails>(
        m_deqGroups.begin(),
        m_deqGroups.end()
    );
}

std::vector<protocol::DosSummaryControlDetails>
AuthenticationObservationStore::vecDosSummarySnapshot() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return std::vector<protocol::DosSummaryControlDetails>(
        m_deqDosSummaries.begin(),
        m_deqDosSummaries.end()
    );
}

std::optional<protocol::PacketObservationControlDetails>
AuthenticationObservationStore::optPacket(std::uint64_t u64EventId) const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    const auto itPacket = m_mapPacketByEventId.find(u64EventId);
    if (itPacket == m_mapPacketByEventId.end())
    {
        return std::nullopt;
    }

    const auto ptrPacket = itPacket->second.lock();
    return ptrPacket == nullptr
        ? std::nullopt
        : std::optional<protocol::PacketObservationControlDetails>(*ptrPacket);
}

std::size_t AuthenticationObservationStore::nFailureCount(
    protocol::AuthenticationFailureType typeFailure
) const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    const auto itCount = m_mapFailureCounts.find(typeFailure);
    return itCount == m_mapFailureCounts.end() ? 0 : itCount->second;
}

std::size_t AuthenticationObservationStore::nPacketCount() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return m_deqPackets.size();
}

std::size_t AuthenticationObservationStore::nStoredFailureCount() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return m_deqFailures.size();
}

std::uint64_t AuthenticationObservationStore::u64DiscardedAbnormalCount() const
{
    std::lock_guard<std::mutex> lckStore(m_mtxStore);
    return m_u64DiscardedAbnormalCount;
}

ObservationStoreAppendResult AuthenticationObservationStore::resAppendPacket(
    const protocol::PacketObservationControlDetails& detPacket
)
{
    const auto itPacket = m_mapPacketByEventId.find(detPacket.u64EventId());
    if (itPacket != m_mapPacketByEventId.end())
    {
        const auto ptrExisting = itPacket->second.lock();
        if (ptrExisting != nullptr)
        {
            *ptrExisting = detPacket;
            return ObservationStoreAppendResult::Updated;
        }
    }

    auto ptrPacket = std::make_shared<
        protocol::PacketObservationControlDetails
    >(detPacket);
    m_deqPackets.push_back(ptrPacket);
    m_mapPacketByEventId[detPacket.u64EventId()] = ptrPacket;

    while (m_deqPackets.size() > m_nPacketLimit)
    {
        m_deqPackets.pop_front();
    }
    removeExpiredPacketIndexEntries();
    return ObservationStoreAppendResult::Stored;
}

ObservationStoreAppendResult AuthenticationObservationStore::resAppendFailure(
    const protocol::PacketFailureControlDetails& detFailure
)
{
    // 快照重放可能和实时事件相交；eventId相同的失败只更新，不重复计数。
    const auto itExisting = std::find_if(
        m_deqFailures.begin(),
        m_deqFailures.end(),
        [&detFailure](const FailureRecord& recFailure)
        {
            return recFailure.detFailure.u64EventId()
                == detFailure.u64EventId();
        }
    );
    if (itExisting != m_deqFailures.end())
    {
        itExisting->detFailure = detFailure;
        return ObservationStoreAppendResult::Updated;
    }

    ++m_mapFailureCounts[detFailure.typeFailure()];
    if (m_deqFailures.size() >= m_nAbnormalLimit
        && !m_strCurrentRoundId.empty()
        && detFailure.strRoundId() == m_strCurrentRoundId)
    {
        // 总容量冲突时优先给当前轮次让位；先淘汰最老的上一轮详情。
        const auto itPreviousRound = std::find_if(
            m_deqFailures.begin(),
            m_deqFailures.end(),
            [this](const FailureRecord& recFailure)
            {
                return recFailure.detFailure.strRoundId()
                    == m_strPreviousRoundId;
            }
        );
        if (itPreviousRound != m_deqFailures.end())
        {
            m_deqFailures.erase(itPreviousRound);
        }
    }

    if (m_deqFailures.size() >= m_nAbnormalLimit)
    {
        ++m_u64DiscardedAbnormalCount;
        if (m_bAbnormalLimitReported)
        {
            return ObservationStoreAppendResult::CountOnly;
        }

        m_bAbnormalLimitReported = true;
        const std::uint64_t u64WarningEventId =
            std::numeric_limits<std::uint64_t>::max()
            - m_u64DiscardedAbnormalCount;
        protocol::PacketFailureControlDetails detLimit(
            u64WarningEventId,
            0,
            u64NowMilliseconds(),
            protocol::ObservationSeverity::Warning,
            protocol::AuthenticationFailureType::AbnormalRecordLimitReached,
            m_strCurrentRoundId,
            "",
            "",
            "",
            0,
            0,
            0,
            std::nullopt,
            "",
            "Abnormal record limit reached; later details are counted only",
            "",
            "",
            {},
            1
        );
        ++m_mapFailureCounts[
            protocol::AuthenticationFailureType::AbnormalRecordLimitReached
        ];
        m_deqFailures.back() = FailureRecord{std::move(detLimit), nullptr};
        return ObservationStoreAppendResult::AbnormalLimitReached;
    }

    std::shared_ptr<protocol::PacketObservationControlDetails> ptrPacket;
    if (detFailure.u64PacketEventId() != 0)
    {
        const auto itPacket = m_mapPacketByEventId.find(
            detFailure.u64PacketEventId()
        );
        if (itPacket != m_mapPacketByEventId.end())
        {
            ptrPacket = itPacket->second.lock();
        }
    }

    m_deqFailures.push_back(FailureRecord{detFailure, std::move(ptrPacket)});
    return ObservationStoreAppendResult::Stored;
}

ObservationStoreAppendResult AuthenticationObservationStore::resAppendGroup(
    const protocol::ImprovedGroupObservationControlDetails& detGroup
)
{
    m_deqGroups.push_back(detGroup);
    while (m_deqGroups.size() > m_nGroupLimit)
    {
        m_deqGroups.pop_front();
    }
    return ObservationStoreAppendResult::Stored;
}

ObservationStoreAppendResult AuthenticationObservationStore::resAppendDosSummary(
    const protocol::DosSummaryControlDetails& detSummary
)
{
    m_deqDosSummaries.push_back(detSummary);
    while (m_deqDosSummaries.size() > m_nDosSummaryLimit)
    {
        m_deqDosSummaries.pop_front();
    }
    return ObservationStoreAppendResult::Stored;
}

void AuthenticationObservationStore::removeExpiredFailures()
{
    m_deqFailures.erase(
        std::remove_if(
            m_deqFailures.begin(),
            m_deqFailures.end(),
            [this](const FailureRecord& recFailure)
            {
                const std::string& strRoundId =
                    recFailure.detFailure.strRoundId();
                return strRoundId != m_strCurrentRoundId
                    && strRoundId != m_strPreviousRoundId;
            }
        ),
        m_deqFailures.end()
    );
}

void AuthenticationObservationStore::removeExpiredPacketIndexEntries()
{
    for (auto itPacket = m_mapPacketByEventId.begin();
         itPacket != m_mapPacketByEventId.end();)
    {
        if (itPacket->second.expired())
        {
            itPacket = m_mapPacketByEventId.erase(itPacket);
        }
        else
        {
            ++itPacket;
        }
    }
}
}

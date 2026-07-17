#include "tesla/core/AuthenticationReceiverRuntime.h"

#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/core/AuthenticationObservationFactory.h"
#include "tesla/core/ImprovedTeslaDetails.h"
#include "tesla/core/ImprovedTeslaStrategy.h"
#include "tesla/core/NativeTeslaDetails.h"
#include "tesla/core/NativeTeslaStrategy.h"
#include "tesla/core/TeslaMac.h"
#include "tesla/core/UdpAuthenticationInputMapper.h"
#include "tesla/crypto/CryptoUtilities.h"
#include "tesla/crypto/KeyChain.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/metrics/CommunicationCost.h"
#include "tesla/metrics/PerformanceCounterSampler.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"
#include "tesla/workload/FileWorkload.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
namespace
{
using ContextKey = std::pair<std::string, std::uint64_t>;

constexpr std::size_t MAX_QUEUED_DATAGRAMS = 8192;
constexpr std::size_t MAX_CANDIDATE_VERSIONS_PER_PACKET = 4;
constexpr std::uint32_t MAX_AUTHENTICATION_PACKET_COUNT = 200000;

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

crypto::Digest digMapBlock(const protocol::BinaryBlock& arrBlock)
{
    crypto::Digest digResult{};
    std::copy(arrBlock.begin(), arrBlock.end(), digResult.begin());
    return digResult;
}

template<typename ByteRange>
std::string strHex(const ByteRange& rngBytes)
{
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    std::string strValue(rngBytes.size() * 2U, '0');
    for (std::size_t nIndex = 0; nIndex < rngBytes.size(); ++nIndex)
    {
        strValue[nIndex * 2U] =
            HEX_DIGITS[(rngBytes[nIndex] >> 4U) & 0x0FU];
        strValue[nIndex * 2U + 1U] =
            HEX_DIGITS[rngBytes[nIndex] & 0x0FU];
    }
    return strValue;
}

protocol::UdpAuthenticationPacketContext ctxCreatePacketContext(
    const AuthenticationRoundParameters& prmRound
)
{
    if (prmRound.modeAuthentication() == TeslaAuthenticationMode::Native)
    {
        return protocol::UdpAuthenticationPacketContext(
            protocol::UdpAuthenticationMode::Native,
            prmRound.u32PacketsPerInterval(),
            prmRound.u32DisclosureDelay(),
            prmRound.u32TotalPacketCount()
        );
    }

    const ImprovedTeslaParameters& prmImproved =
        prmRound.optImprovedParameters().value();
    return protocol::UdpAuthenticationPacketContext(
        protocol::UdpAuthenticationMode::Improved,
        prmRound.u32PacketsPerInterval(),
        prmRound.u32DisclosureDelay(),
        prmRound.u32TotalPacketCount(),
        prmImproved.u32GroupSize(),
        prmImproved.nTauCount()
    );
}

std::string strDecodeText(const AuthenticationPacketInput::Message& arrMessage)
{
    std::size_t nLength = arrMessage.size();
    while (nLength > 0 && arrMessage[nLength - 1U] == 0)
    {
        --nLength;
    }

    return std::string(
        reinterpret_cast<const char*>(arrMessage.data()),
        nLength
    );
}
}

class AuthenticationReceiverRuntime::Impl final
{
public:
    enum class PacketStatus
    {
        Empty,
        Pending,
        Passed,
        Failed
    };

    struct PacketRecord final
    {
        std::optional<protocol::UdpDataPacket> optPacket;
        PacketStatus                          statusPacket = PacketStatus::Empty;
        protocol::ByteBuffer                  vecRawDatagram;
        std::uint64_t                         u64ReceiveTimestampMilliseconds = 0;
        std::uint64_t                         u64ObservationEventId = 0;
        std::string                           strCandidateHash;
        std::uint32_t                         u32DuplicateCount = 0;
        std::string                           strActualSourceIp;
        protocol::PacketSourceType            typeSource =
            protocol::PacketSourceType::NormalSender;
    };

    struct AdditionalCandidateRecord final
    {
        protocol::UdpDataPacket udpPacket;
        protocol::ByteBuffer    vecRawDatagram;
        std::uint64_t           u64ReceiveTimestampMilliseconds = 0;
        std::uint64_t           u64ObservationEventId = 0;
        std::string             strCandidateHash;
        std::uint32_t           u32DuplicateCount = 1;
        PacketStatus            statusPacket = PacketStatus::Pending;
        std::string             strActualSourceIp;
        protocol::PacketSourceType typeSource =
            protocol::PacketSourceType::AttackInjection;
    };

    struct TimelineSegment final
    {
        std::uint32_t u32FirstLogicalInterval = 1;
        std::uint64_t u64StartTimestampMilliseconds = 0;
    };

    struct ReceiverState final
    {
        explicit ReceiverState(ReceiverAuthenticationContext ctxValue)
            : ctxContext(std::move(ctxValue))
        {
        }

        ReceiverAuthenticationContext  ctxContext;
        std::string                    strRoundId;
        std::vector<PacketRecord>      vecPacketRecords;
        std::map<std::uint32_t, std::vector<AdditionalCandidateRecord>>
            mapAdditionalCandidates;
        std::map<std::uint32_t, crypto::Digest> mapDisclosedKeys;
        std::set<std::uint32_t>        setCountedDisclosureKeyIndexes;
        std::set<std::uint32_t>        setVerifiedIntervals;
        std::optional<metrics::AuthenticationRoundMetricCollector>
            optMetricCollector;
        std::vector<TimelineSegment>   vecTimeline;
        std::optional<std::uint32_t>   optPauseAfterInterval;
        std::uint64_t                  u64PauseTimestampMilliseconds = 0;
        std::uint32_t                  u32ClockToleranceMilliseconds = 0;
        std::uint32_t                  u32ReceivedPacketCount = 0;
        bool                           bActive = false;
        bool                           bPaused = false;
        bool                           bProtocolIncomplete = false;
        bool                           bResultReported = false;
        bool                           bMetricSummaryQueued = false;
    };

    struct QueuedDatagram final
    {
        ContextKey            keyContext;
        protocol::ByteBuffer  vecDatagram;
        std::uint64_t         u64ReceiveTimestampMilliseconds = 0;
        std::string           strActualSourceIp;
        protocol::PacketSourceType typeSource =
            protocol::PacketSourceType::NormalSender;
    };

    struct AttackSourceMapping final
    {
        std::string   strRoundId;
        std::string   strTargetSenderId;
        std::string   strTargetSenderIp;
        std::string   strAttackSourceIp;
        std::uint64_t u64ChainId = 0;
        std::uint64_t u64ExpiresAtMilliseconds = 0;
    };

    Impl(
        ResultHandler fnResultHandler,
        ObservationHandler fnObservationHandler,
        MetricHandler fnMetricHandler
    )
        : m_fnResultHandler(std::move(fnResultHandler)),
          m_fnObservationHandler(std::move(fnObservationHandler)),
          m_fnMetricHandler(std::move(fnMetricHandler)),
          m_ptrPerformanceSampler(
              metrics::ptrCreateVerificationPerformanceSampler()
          )
    {
        if (!m_fnResultHandler)
        {
            throw std::invalid_argument("Receiver runtime requires a result callback");
        }

        m_thrWorker = std::thread([this]()
        {
            workerLoop();
        });
    }

    ~Impl()
    {
        {
            std::lock_guard<std::mutex> lckState(m_mtxState);
            m_bShutdown = true;
            m_cndState.notify_all();
        }

        if (m_thrWorker.joinable())
        {
            m_thrWorker.join();
        }
    }

    void configure(std::vector<ReceiverAuthenticationContext> vecContexts)
    {
        stop(false);

        std::map<ContextKey, std::unique_ptr<ReceiverState>> mapCandidate;
        std::map<std::string, std::string> mapSenderByIp;

        for (ReceiverAuthenticationContext& ctxContext : vecContexts)
        {
            const AuthenticationRoundParameters& prmRound =
                ctxContext.prmRoundParameters();
            if (prmRound.u32TotalPacketCount()
                > MAX_AUTHENTICATION_PACKET_COUNT)
            {
                throw std::invalid_argument(
                    "Receiver packet count exceeds the bounded runtime"
                );
            }

            const auto prIpInsert = mapSenderByIp.emplace(
                ctxContext.strSenderIpAddress(),
                ctxContext.strSenderId()
            );
            if (!prIpInsert.second
                && prIpInsert.first->second != ctxContext.strSenderId())
            {
                throw std::invalid_argument(
                    "Receiver contexts map one source IP to multiple senders"
                );
            }

            const ContextKey keyContext(
                ctxContext.strSenderIpAddress(),
                ctxContext.u64ChainId()
            );
            if (!mapCandidate.emplace(
                    keyContext,
                    std::make_unique<ReceiverState>(std::move(ctxContext))
                ).second)
            {
                throw std::invalid_argument("Receiver context key is duplicated");
            }
        }

        if (mapCandidate.empty())
        {
            throw std::invalid_argument("Receiver runtime requires at least one context");
        }

        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_mapStates = std::move(mapCandidate);
        m_deqDatagrams.clear();
        m_bConfigured = true;
    }

    void start(
        std::string strRoundId,
        std::uint64_t u64StartTimestampMilliseconds,
        std::uint32_t u32ClockToleranceMilliseconds
    )
    {
        if (strRoundId.empty()
            || u64StartTimestampMilliseconds == 0
            || u64StartTimestampMilliseconds <= u64NowMilliseconds() + 100U
            || u32ClockToleranceMilliseconds == 0)
        {
            throw std::invalid_argument("Receiver start schedule is invalid");
        }

        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (!m_bConfigured)
        {
            throw std::logic_error("Receiver runtime is not configured");
        }

        for (auto& prState : m_mapStates)
        {
            ReceiverState& staReceiver = *prState.second;
            const std::uint32_t u32PacketCount =
                staReceiver.ctxContext.prmRoundParameters().u32TotalPacketCount();
            staReceiver.strRoundId = strRoundId;
            staReceiver.vecPacketRecords.assign(
                static_cast<std::size_t>(u32PacketCount) + 1U,
                PacketRecord{}
            );
            staReceiver.mapAdditionalCandidates.clear();
            staReceiver.mapDisclosedKeys.clear();
            staReceiver.setCountedDisclosureKeyIndexes.clear();
            staReceiver.setVerifiedIntervals.clear();
            if (m_fnMetricHandler)
            {
                const AuthenticationRoundParameters& prmRound =
                    staReceiver.ctxContext.prmRoundParameters();
                staReceiver.optMetricCollector.emplace(
                    strRoundId,
                    staReceiver.ctxContext.strSenderId(),
                    staReceiver.ctxContext.u64ChainId(),
                    prmRound.modeAuthentication() == TeslaAuthenticationMode::Native
                        ? metrics::AuthenticationMetricMode::Native
                        : metrics::AuthenticationMetricMode::Improved,
                    u32PacketCount
                );
            }
            else
            {
                staReceiver.optMetricCollector.reset();
            }
            staReceiver.vecTimeline = {
                TimelineSegment{1, u64StartTimestampMilliseconds}
            };
            staReceiver.optPauseAfterInterval.reset();
            staReceiver.u64PauseTimestampMilliseconds = 0;
            staReceiver.u32ClockToleranceMilliseconds =
                u32ClockToleranceMilliseconds;
            staReceiver.u32ReceivedPacketCount = 0;
            staReceiver.bActive = true;
            staReceiver.bPaused = false;
            staReceiver.bProtocolIncomplete = false;
            staReceiver.bResultReported = false;
            staReceiver.bMetricSummaryQueued = false;
        }

        m_strRoundId = std::move(strRoundId);
        m_bRunning = true;
        m_bPaused = false;
        m_cndState.notify_all();
    }

    void requestPause(
        const std::string& strRoundId,
        std::uint32_t u32PauseAfterInterval,
        std::uint64_t u64PauseTimestampMilliseconds
    )
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        validateActiveRound(strRoundId);

        if (u32PauseAfterInterval == 0
            || u64PauseTimestampMilliseconds <= u64NowMilliseconds())
        {
            throw std::invalid_argument("Receiver pause schedule is invalid");
        }

        for (auto& prState : m_mapStates)
        {
            ReceiverState& staReceiver = *prState.second;
            if (!staReceiver.bActive)
            {
                continue;
            }

            const std::uint32_t u32LastLogicalInterval =
                static_cast<std::uint32_t>(
                    staReceiver.ctxContext.prmRoundParameters()
                        .nDataIntervalCount()
                )
                + staReceiver.ctxContext.prmRoundParameters().u32DisclosureDelay();
            if (u32PauseAfterInterval >= u32LastLogicalInterval)
            {
                throw std::invalid_argument(
                    "Receiver pause boundary is outside the active round"
                );
            }

            staReceiver.optPauseAfterInterval = u32PauseAfterInterval;
            staReceiver.u64PauseTimestampMilliseconds =
                u64PauseTimestampMilliseconds;
        }
    }

    void resume(
        const std::string& strRoundId,
        std::uint32_t u32ResumeInterval,
        std::uint64_t u64ResumeTimestampMilliseconds
    )
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        validateActiveRound(strRoundId);

        for (auto& prState : m_mapStates)
        {
            ReceiverState& staReceiver = *prState.second;
            if (!staReceiver.bActive)
            {
                continue;
            }

            if (!staReceiver.optPauseAfterInterval.has_value()
                || u32ResumeInterval
                    != staReceiver.optPauseAfterInterval.value() + 1U
                || u64ResumeTimestampMilliseconds
                    <= staReceiver.u64PauseTimestampMilliseconds
                || u64ResumeTimestampMilliseconds
                    <= u64NowMilliseconds() + 100U)
            {
                throw std::invalid_argument(
                    "Receiver resume interval does not follow the pause"
                );
            }

            staReceiver.vecTimeline.push_back(TimelineSegment{
                u32ResumeInterval,
                u64ResumeTimestampMilliseconds
            });
            staReceiver.bPaused = false;
        }

        m_bPaused = false;
        m_cndState.notify_all();
    }

    void stop(bool bReportResults) noexcept
    {
        std::vector<AuthenticationRuntimeResult> vecResults;
        std::vector<metrics::AuthenticationMetricRecord> vecMetrics;

        {
            std::lock_guard<std::mutex> lckState(m_mtxState);
            if (bReportResults)
            {
                for (auto& prState : m_mapStates)
                {
                    ReceiverState& staReceiver = *prState.second;
                    if (staReceiver.bActive && !staReceiver.bResultReported)
                    {
                        vecResults.push_back(resCreateResult(
                            staReceiver,
                            AuthenticationRuntimeResultStatus::Stopped,
                            "Receiver round stopped"
                        ));
                        staReceiver.bResultReported = true;
                    }
                }
            }

            for (auto& prState : m_mapStates)
            {
                prState.second->bActive = false;
                prState.second->bPaused = false;
            }

            m_bRunning = false;
            m_bPaused = false;
            m_deqDatagrams.clear();
            m_mapAttackSourceMappings.clear();
            vecMetrics.swap(m_vecPendingMetrics);
        }

        emitMetrics(vecMetrics);
        // 轮次汇总归档依赖最终能耗摘要，因此指标必须先于结果回调可见。
        emitResults(vecResults);
    }

    void applyAttackSourceMapping(
        const protocol::AttackSourceMappingControlDetails& detMapping
    )
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        const ContextKey keyTarget(
            detMapping.strTargetSenderIp(),
            detMapping.u64ChainId()
        );
        const auto itTarget = m_mapStates.find(keyTarget);
        if (itTarget == m_mapStates.end()
            || itTarget->second->ctxContext.strSenderId()
                != detMapping.strTargetSenderId())
        {
            throw std::invalid_argument(
                "Attack source mapping target does not match a receiver context"
            );
        }

        const ContextKey keyAttack(
            detMapping.strAttackSourceIp(),
            detMapping.u64ChainId()
        );
        if (detMapping.actAction()
            == protocol::AttackSourceMappingAction::Clear)
        {
            m_mapAttackSourceMappings.erase(keyAttack);
            return;
        }

        if (m_bRunning
            || detMapping.u64ExpiresAtMilliseconds() <= u64NowMilliseconds())
        {
            throw std::logic_error(
                "Attack source mapping must be installed before start with a future expiry"
            );
        }

        const AttackSourceMapping mapMapping{
            detMapping.strRoundId(),
            detMapping.strTargetSenderId(),
            detMapping.strTargetSenderIp(),
            detMapping.strAttackSourceIp(),
            detMapping.u64ChainId(),
            detMapping.u64ExpiresAtMilliseconds()
        };
        const auto prInserted = m_mapAttackSourceMappings.emplace(
            keyAttack,
            mapMapping
        );
        if (!prInserted.second)
        {
            throw std::logic_error(
                "Only one attack source mapping may target a sender round"
            );
        }
    }

    void clearAttackSourceMappings() noexcept
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_mapAttackSourceMappings.clear();
    }

    bool bEnqueueDatagram(
        const std::string& strSourceIpAddress,
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64ReceiveTimestampMilliseconds
    )
    {
        const protocol::UdpAuthenticationPacketHeaderDecodeResult resHeader =
            protocol::UdpAuthenticationPacketCodec::resDecodeHeader(vecDatagram);
        if (!std::holds_alternative<protocol::UdpAuthenticationPacketHeader>(
                resHeader
            ))
        {
            std::lock_guard<std::mutex> lckState(m_mtxState);
            ++m_u64InvalidWindowCount;
            disqualifyActiveMetricComparisonsLocked();
            if (m_u32DetailedInvalidWindowCount < 16U)
            {
                ++m_u32DetailedInvalidWindowCount;
                queueUnscopedFailureLocked(
                    protocol::AuthenticationFailureType::ProtocolError,
                    u64ReceiveTimestampMilliseconds,
                    strSourceIpAddress,
                    0,
                    std::get<protocol::ProtocolDecodeError>(resHeader)
                        .strMessage()
                );
            }
            else
            {
                ++m_u64RateLimitedWindowCount;
            }
            return false;
        }

        const protocol::UdpAuthenticationPacketHeader& hdrPacket =
            std::get<protocol::UdpAuthenticationPacketHeader>(resHeader);
        ContextKey keyContext(
            strSourceIpAddress,
            hdrPacket.u64ChainId()
        );

        std::lock_guard<std::mutex> lckState(m_mtxState);
        auto itState = m_mapStates.find(keyContext);
        protocol::PacketSourceType typeSource =
            protocol::PacketSourceType::NormalSender;
        if (itState == m_mapStates.end())
        {
            const auto itMapping = m_mapAttackSourceMappings.find(keyContext);
            if (itMapping != m_mapAttackSourceMappings.end()
                && itMapping->second.strRoundId == m_strRoundId
                && itMapping->second.u64ExpiresAtMilliseconds
                    >= u64ReceiveTimestampMilliseconds)
            {
                keyContext = ContextKey(
                    itMapping->second.strTargetSenderIp,
                    itMapping->second.u64ChainId
                );
                itState = m_mapStates.find(keyContext);
                typeSource = protocol::PacketSourceType::AttackInjection;
            }
        }
        if (!m_bRunning
            || itState == m_mapStates.end()
            || !itState->second->bActive)
        {
            ++m_u64InvalidWindowCount;
            disqualifyActiveMetricComparisonsLocked();
            if (m_u32DetailedInvalidWindowCount < 16U)
            {
                ++m_u32DetailedInvalidWindowCount;
                queueUnscopedFailureLocked(
                    protocol::AuthenticationFailureType::UnknownContext,
                    u64ReceiveTimestampMilliseconds,
                    strSourceIpAddress,
                    hdrPacket.u64ChainId(),
                    "UDP source and chain ID do not match an active trusted context"
                );
            }
            else
            {
                ++m_u64RateLimitedWindowCount;
            }
            return false;
        }

        if (m_deqDatagrams.size() >= MAX_QUEUED_DATAGRAMS)
        {
            ++m_nDroppedQueueDatagramCount;
            ++m_u64RateLimitedWindowCount;
            ++m_u64QueueOverflowWindowCount;
            if (itState->second->optMetricCollector.has_value())
            {
                itState->second->optMetricCollector
                    ->markNormalComparisonIneligible();
            }
            return false;
        }

        m_deqDatagrams.push_back(QueuedDatagram{
            keyContext,
            vecDatagram,
            u64ReceiveTimestampMilliseconds,
            strSourceIpAddress,
            typeSource
        });
        ++m_u64LegitimateWindowCount;
        m_cndState.notify_one();
        return true;
    }

    bool bIsConfigured() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_bConfigured;
    }

    bool bIsRunning() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_bRunning;
    }

    bool bIsPaused() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_bPaused;
    }

    std::size_t nContextCount() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_mapStates.size();
    }

    std::size_t nDroppedQueueDatagramCount() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_nDroppedQueueDatagramCount;
    }

    ReceiverAuthenticationContextLookupResult resFindContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        const auto itContext = m_mapStates.find(ContextKey(
            strSourceIpAddress,
            u64ChainId
        ));
        if (itContext != m_mapStates.end())
        {
            return itContext->second->ctxContext;
        }

        const bool bKnownSource = std::any_of(
            m_mapStates.begin(),
            m_mapStates.end(),
            [&strSourceIpAddress](const auto& prState)
            {
                return prState.first.first == strSourceIpAddress;
            }
        );
        return bKnownSource
            ? ReceiverAuthenticationContextLookupError::UnknownChainId
            : ReceiverAuthenticationContextLookupError::UnknownSourceIp;
    }

private:
    void disqualifyActiveMetricComparisonsLocked() noexcept
    {
        // 无法绑定Sender的攻击或无效流量仍会污染同期实验，因此排除所有活动轮次。
        for (auto& prState : m_mapStates)
        {
            ReceiverState& staReceiver = *prState.second;
            if (staReceiver.bActive
                && staReceiver.optMetricCollector.has_value())
            {
                staReceiver.optMetricCollector
                    ->markNormalComparisonIneligible();
            }
        }
    }

    static protocol::PacketAuthenticationStatus statusMap(
        PacketStatus statusPacket
    ) noexcept
    {
        switch (statusPacket)
        {
        case PacketStatus::Empty:
        case PacketStatus::Pending:
            return protocol::PacketAuthenticationStatus::Pending;
        case PacketStatus::Passed:
            return protocol::PacketAuthenticationStatus::Passed;
        case PacketStatus::Failed:
            return protocol::PacketAuthenticationStatus::Failed;
        }

        return protocol::PacketAuthenticationStatus::Failed;
    }

    std::uint64_t nextObservationEventId() noexcept
    {
        return m_u64NextObservationEventId++;
    }

    void queuePacketObservationLocked(
        const ReceiverState& staReceiver,
        const protocol::UdpAuthenticationPacket& udpPacket,
        const protocol::ByteBuffer& vecRawDatagram,
        std::uint64_t u64ReceiveTimestampMilliseconds,
        std::uint64_t u64EventId,
        std::uint32_t u32DuplicateCount,
        protocol::PacketAuthenticationStatus statusAuthentication,
        std::string strReason,
        std::string strActualSourceIp = {},
        protocol::PacketSourceType typeSource =
            protocol::PacketSourceType::NormalSender
    )
    {
        if (!m_fnObservationHandler)
        {
            return;
        }

        std::uint32_t u32IntervalIndex = 0;
        std::uint32_t u32PacketIndex = 0;
        if (udpPacket.bIsDataPacket())
        {
            const protocol::UdpDataPacket& udpData = std::get<
                protocol::UdpDataPacket
            >(udpPacket.varDetails());
            u32IntervalIndex = udpData.u32IntervalIndex();
            u32PacketIndex = udpData.u32PacketIndex();
        }
        else
        {
            u32IntervalIndex = std::get<protocol::UdpDisclosurePacket>(
                udpPacket.varDetails()
            ).u32IntervalIndex();
        }

        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        if (strActualSourceIp.empty())
        {
            strActualSourceIp = staReceiver.ctxContext.strSenderIpAddress();
        }
        m_vecPendingObservations.emplace_back(
            protocol::PacketObservationControlDetails(
                u64EventId,
                u64ReceiveTimestampMilliseconds,
                staReceiver.strRoundId,
                staReceiver.ctxContext.strSenderId(),
                staReceiver.ctxContext.strSenderIpAddress(),
                strActualSourceIp,
                strActualSourceIp,
                protocol::PacketObservationDirection::Rx,
                typeSource,
                staReceiver.ctxContext.u64ChainId(),
                u32IntervalIndex,
                u32PacketIndex,
                prmRound.u32PacketsPerInterval(),
                prmRound.u32DisclosureDelay(),
                AuthenticationObservationFactory::algMap(
                    prmRound.algCryptoAlgorithm()
                ),
                AuthenticationObservationFactory::modeMap(
                    prmRound.modeAuthentication()
                ),
                statusAuthentication,
                AuthenticationObservationFactory::strCandidateHash(
                    vecRawDatagram
                ),
                u32DuplicateCount,
                std::move(strReason),
                AuthenticationObservationFactory::varPayloadDetails(udpPacket),
                vecRawDatagram
            )
        );
    }

    void queueFailureLocked(
        ReceiverState& staReceiver,
        protocol::AuthenticationFailureType typeFailure,
        std::uint64_t u64PacketEventId,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex,
        std::optional<std::uint32_t> optGroupIndex,
        std::string strCandidateHash,
        std::string strReason,
        std::string strReceivedTagDigest,
        std::string strCalculatedTagDigest,
        std::vector<std::uint32_t> vecLocatedPacketIndexes,
        std::uint32_t u32DuplicateCount,
        protocol::ObservationSeverity sevSeverity,
        std::string strActualSourceIp = {}
    )
    {
        if (staReceiver.optMetricCollector.has_value())
        {
            // 任何结构化失败都说明本轮不是无攻击、无丢失的正常对比样本。
            staReceiver.optMetricCollector->markNormalComparisonIneligible();
        }

        if (!m_fnObservationHandler)
        {
            return;
        }

        if (strActualSourceIp.empty())
        {
            strActualSourceIp = staReceiver.ctxContext.strSenderIpAddress();
        }

        m_vecPendingObservations.emplace_back(
            protocol::PacketFailureControlDetails(
                nextObservationEventId(),
                u64PacketEventId,
                u64NowMilliseconds(),
                sevSeverity,
                typeFailure,
                staReceiver.strRoundId,
                staReceiver.ctxContext.strSenderId(),
                staReceiver.ctxContext.strSenderIpAddress(),
                strActualSourceIp,
                staReceiver.ctxContext.u64ChainId(),
                u32IntervalIndex,
                u32PacketIndex,
                std::move(optGroupIndex),
                std::move(strCandidateHash),
                std::move(strReason),
                std::move(strReceivedTagDigest),
                std::move(strCalculatedTagDigest),
                std::move(vecLocatedPacketIndexes),
                u32DuplicateCount
            )
        );
    }

    /** @brief 记录尚无法绑定到可信Sender上下文的低频协议错误。 */
    void queueUnscopedFailureLocked(
        protocol::AuthenticationFailureType typeFailure,
        std::uint64_t u64TimestampMilliseconds,
        const std::string& strActualSourceIp,
        std::uint64_t u64ChainId,
        std::string strReason
    )
    {
        if (!m_fnObservationHandler)
        {
            return;
        }

        m_vecPendingObservations.emplace_back(
            protocol::PacketFailureControlDetails(
                nextObservationEventId(),
                0,
                u64TimestampMilliseconds,
                protocol::ObservationSeverity::Warning,
                typeFailure,
                "",
                "",
                "",
                strActualSourceIp,
                u64ChainId,
                0,
                0,
                std::nullopt,
                "",
                std::move(strReason),
                "",
                "",
                {},
                1
            )
        );
    }

    void queueDosSummaryIfDueLocked(std::uint64_t u64TimestampMilliseconds)
    {
        constexpr std::uint32_t DOS_WINDOW_MILLISECONDS = 1000;
        if (m_u64DosWindowStartMilliseconds == 0)
        {
            m_u64DosWindowStartMilliseconds = u64TimestampMilliseconds;
            return;
        }

        if (u64TimestampMilliseconds - m_u64DosWindowStartMilliseconds
            < DOS_WINDOW_MILLISECONDS)
        {
            return;
        }

        if (m_fnObservationHandler
            && (m_u64InvalidWindowCount > 0
                || m_u64RateLimitedWindowCount > 0
                || m_u64LegitimateWindowCount > 0
                || m_u64QueueOverflowWindowCount > 0))
        {
            m_vecPendingObservations.emplace_back(
                protocol::DosSummaryControlDetails(
                    u64TimestampMilliseconds,
                    DOS_WINDOW_MILLISECONDS,
                    m_u64InvalidWindowCount,
                    m_u64RateLimitedWindowCount,
                    m_u64LegitimateWindowCount,
                    m_u64QueueOverflowWindowCount
                )
            );
        }

        m_u64DosWindowStartMilliseconds = u64TimestampMilliseconds;
        m_u64InvalidWindowCount = 0;
        m_u64RateLimitedWindowCount = 0;
        m_u64LegitimateWindowCount = 0;
        m_u64QueueOverflowWindowCount = 0;
        m_u32DetailedInvalidWindowCount = 0;
    }

    void emitObservations(
        const std::vector<protocol::AuthenticationObservation>& vecObservations
    ) noexcept
    {
        if (!m_fnObservationHandler)
        {
            return;
        }

        for (const protocol::AuthenticationObservation& varObservation
            : vecObservations)
        {
            try
            {
                m_fnObservationHandler(varObservation);
            }
            catch (...)
            {
                // 平台观察回调异常不得终止Receiver工作线程。
            }
        }
    }

    void emitMetrics(
        const std::vector<metrics::AuthenticationMetricRecord>& vecMetrics
    ) noexcept
    {
        if (!m_fnMetricHandler)
        {
            return;
        }

        for (const metrics::AuthenticationMetricRecord& varMetric : vecMetrics)
        {
            try
            {
                m_fnMetricHandler(varMetric);
            }
            catch (...)
            {
                // 指标展示或传输失败不得改变Receiver认证结果。
            }
        }
    }

    void validateActiveRound(const std::string& strRoundId) const
    {
        if (!m_bRunning || m_strRoundId != strRoundId)
        {
            throw std::logic_error("Receiver round is not active");
        }
    }

    void workerLoop()
    {
        while (true)
        {
            std::optional<QueuedDatagram> optDatagram;
            std::vector<AuthenticationRuntimeResult> vecResults;
            std::vector<protocol::AuthenticationObservation> vecObservations;
            std::vector<metrics::AuthenticationMetricRecord> vecMetrics;

            {
                std::unique_lock<std::mutex> lckState(m_mtxState);
                m_cndState.wait_for(
                    lckState,
                    std::chrono::milliseconds(25),
                    [this]()
                    {
                        return m_bShutdown || !m_deqDatagrams.empty();
                    }
                );

                if (m_bShutdown)
                {
                    return;
                }

                if (!m_deqDatagrams.empty())
                {
                    optDatagram = std::move(m_deqDatagrams.front());
                    m_deqDatagrams.pop_front();
                }

                if (optDatagram.has_value())
                {
                    processDatagramLocked(optDatagram.value(), vecResults);
                }

                checkPauseAndTimeoutsLocked(vecResults);
                queueDosSummaryIfDueLocked(u64NowMilliseconds());
                vecObservations.swap(m_vecPendingObservations);
                vecMetrics.swap(m_vecPendingMetrics);
            }

            emitObservations(vecObservations);
            emitMetrics(vecMetrics);
            // 保证节点适配层在收到最终结果时已经能够组装完整逐轮指标。
            emitResults(vecResults);
        }
    }

    void processDatagramLocked(
        const QueuedDatagram& queDatagram,
        std::vector<AuthenticationRuntimeResult>& vecResults
    )
    {
        const auto itState = m_mapStates.find(queDatagram.keyContext);
        if (itState == m_mapStates.end())
        {
            return;
        }

        ReceiverState& staReceiver = *itState->second;
        if (!staReceiver.bActive || staReceiver.bResultReported)
        {
            return;
        }

        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        const protocol::UdpAuthenticationPacketDecodeResult resPacket =
            protocol::UdpAuthenticationPacketCodec::resDecode(
                queDatagram.vecDatagram,
                ctxCreatePacketContext(prmRound)
            );
        if (!std::holds_alternative<protocol::UdpAuthenticationPacket>(resPacket))
        {
            staReceiver.bProtocolIncomplete = true;
            queueFailureLocked(
                staReceiver,
                protocol::AuthenticationFailureType::ProtocolError,
                0,
                0,
                0,
                std::nullopt,
                "",
                "UDP authentication payload failed context-aware decoding",
                "",
                "",
                {},
                1,
                protocol::ObservationSeverity::Error,
                queDatagram.strActualSourceIp
            );
            return;
        }

        const protocol::UdpAuthenticationPacket& udpPacket =
            std::get<protocol::UdpAuthenticationPacket>(resPacket);
        if (!udpPacket.bIsDataPacket())
        {
            const protocol::UdpDisclosurePacket& udpDisclosure =
                std::get<protocol::UdpDisclosurePacket>(
                    udpPacket.varDetails()
                );
            const bool bAccepted = processDisclosedKeyLocked(
                staReceiver,
                udpDisclosure.u32IntervalIndex(),
                udpDisclosure.arrDisclosedKey(),
                vecResults
            );
            const std::uint64_t u64PacketEventId = nextObservationEventId();
            queuePacketObservationLocked(
                staReceiver,
                udpPacket,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64PacketEventId,
                1,
                bAccepted
                    ? protocol::PacketAuthenticationStatus::Passed
                    : protocol::PacketAuthenticationStatus::Failed,
                bAccepted
                    ? "Disclosed key accepted"
                    : "Disclosed key rejected",
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            );
            if (!bAccepted)
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::ProtocolError,
                    u64PacketEventId,
                    udpDisclosure.u32IntervalIndex(),
                    0,
                    std::nullopt,
                    AuthenticationObservationFactory::strCandidateHash(
                        queDatagram.vecDatagram
                    ),
                    "Disclosed key does not match the configured commitment chain",
                    "",
                    "",
                    {},
                    1,
                    protocol::ObservationSeverity::Error
                );
            }
            return;
        }

        const protocol::UdpDataPacket& udpData =
            std::get<protocol::UdpDataPacket>(udpPacket.varDetails());
        if (!bIsPacketTimeSafe(
                staReceiver,
                udpData.u32IntervalIndex(),
                queDatagram.u64ReceiveTimestampMilliseconds
            ))
        {
            staReceiver.bProtocolIncomplete = true;
            const std::uint64_t u64PacketEventId = nextObservationEventId();
            queuePacketObservationLocked(
                staReceiver,
                udpPacket,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64PacketEventId,
                1,
                protocol::PacketAuthenticationStatus::Failed,
                "Packet arrived after its safe authentication window",
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            );
            queueFailureLocked(
                staReceiver,
                protocol::AuthenticationFailureType::ReplayLate,
                u64PacketEventId,
                udpData.u32IntervalIndex(),
                udpData.u32PacketIndex(),
                std::nullopt,
                AuthenticationObservationFactory::strCandidateHash(
                    queDatagram.vecDatagram
                ),
                "Packet arrived after its disclosed-key safety deadline",
                "",
                "",
                {},
                1,
                protocol::ObservationSeverity::Error,
                queDatagram.strActualSourceIp
            );
            return;
        }

        PacketRecord& recPacket =
            staReceiver.vecPacketRecords[udpData.u32PacketIndex()];
        const std::string strCandidateHash =
            AuthenticationObservationFactory::strCandidateHash(
                queDatagram.vecDatagram
            );
        if (recPacket.optPacket.has_value())
        {
            if (recPacket.strCandidateHash == strCandidateHash)
            {
                ++recPacket.u32DuplicateCount;
                queuePacketObservationLocked(
                    staReceiver,
                    protocol::UdpAuthenticationPacket(recPacket.optPacket.value()),
                    recPacket.vecRawDatagram,
                    recPacket.u64ReceiveTimestampMilliseconds,
                    recPacket.u64ObservationEventId,
                    recPacket.u32DuplicateCount,
                    statusMap(recPacket.statusPacket),
                    "Identical datagram received again",
                    recPacket.strActualSourceIp,
                    recPacket.typeSource
                );
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::ReplayDuplicate,
                    recPacket.u64ObservationEventId,
                    udpData.u32IntervalIndex(),
                    udpData.u32PacketIndex(),
                    std::nullopt,
                    strCandidateHash,
                    "Identical candidate datagram was received repeatedly",
                    "",
                    "",
                    {},
                recPacket.u32DuplicateCount,
                    protocol::ObservationSeverity::Warning,
                    recPacket.strActualSourceIp
                );
                return;
            }

            std::vector<AdditionalCandidateRecord>& vecCandidates =
                staReceiver.mapAdditionalCandidates[udpData.u32PacketIndex()];
            auto itCandidate = std::find_if(
                vecCandidates.begin(),
                vecCandidates.end(),
                [&strCandidateHash](const AdditionalCandidateRecord& recCandidate)
                {
                    return recCandidate.strCandidateHash == strCandidateHash;
                }
            );
            if (itCandidate != vecCandidates.end())
            {
                ++itCandidate->u32DuplicateCount;
                queuePacketObservationLocked(
                    staReceiver,
                    protocol::UdpAuthenticationPacket(itCandidate->udpPacket),
                    itCandidate->vecRawDatagram,
                    itCandidate->u64ReceiveTimestampMilliseconds,
                    itCandidate->u64ObservationEventId,
                    itCandidate->u32DuplicateCount,
                    protocol::PacketAuthenticationStatus::Failed,
                    "Conflicting candidate duplicate received",
                    itCandidate->strActualSourceIp,
                    itCandidate->typeSource
                );
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::ReplayDuplicate,
                    itCandidate->u64ObservationEventId,
                    udpData.u32IntervalIndex(),
                    udpData.u32PacketIndex(),
                    std::nullopt,
                    strCandidateHash,
                    "Identical conflicting candidate was received repeatedly",
                    "",
                    "",
                    {},
                    itCandidate->u32DuplicateCount,
                    protocol::ObservationSeverity::Warning,
                    itCandidate->strActualSourceIp
                );
                return;
            }

            if (vecCandidates.size() + 1U
                >= MAX_CANDIDATE_VERSIONS_PER_PACKET)
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::TamperedVariant,
                    0,
                    udpData.u32IntervalIndex(),
                    udpData.u32PacketIndex(),
                    std::nullopt,
                    strCandidateHash,
                    "Per-packet candidate version limit reached",
                    "",
                    "",
                    {},
                    1,
                    protocol::ObservationSeverity::Error
                );
                return;
            }

            const std::uint64_t u64CandidateEventId = nextObservationEventId();
            vecCandidates.push_back(AdditionalCandidateRecord{
                udpData,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64CandidateEventId,
                strCandidateHash,
                1,
                PacketStatus::Pending,
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            });
            queuePacketObservationLocked(
                staReceiver,
                udpPacket,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64CandidateEventId,
                1,
                protocol::PacketAuthenticationStatus::Pending,
                "Conflicting candidate retained without replacing the baseline",
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            );
            queueFailureLocked(
                staReceiver,
                protocol::AuthenticationFailureType::TamperedVariant,
                u64CandidateEventId,
                udpData.u32IntervalIndex(),
                udpData.u32PacketIndex(),
                std::nullopt,
                strCandidateHash,
                "Same sender, chain and packet index carried a different datagram",
                "",
                "",
                {},
                1,
                protocol::ObservationSeverity::Error
            );
            return;
        }

        if (queDatagram.typeSource == protocol::PacketSourceType::AttackInjection)
        {
            // 攻击副本可能比正常报文更早到达，但不能据此占用正常Sender基线槽位。
            std::vector<AdditionalCandidateRecord>& vecCandidates =
                staReceiver.mapAdditionalCandidates[udpData.u32PacketIndex()];
            const auto itExisting = std::find_if(
                vecCandidates.begin(),
                vecCandidates.end(),
                [&strCandidateHash](const AdditionalCandidateRecord& recCandidate)
                {
                    return recCandidate.strCandidateHash == strCandidateHash;
                }
            );
            if (itExisting != vecCandidates.end())
            {
                ++itExisting->u32DuplicateCount;
                queuePacketObservationLocked(
                    staReceiver,
                    protocol::UdpAuthenticationPacket(itExisting->udpPacket),
                    itExisting->vecRawDatagram,
                    itExisting->u64ReceiveTimestampMilliseconds,
                    itExisting->u64ObservationEventId,
                    itExisting->u32DuplicateCount,
                    statusMap(itExisting->statusPacket),
                    "Early attack candidate duplicate received",
                    itExisting->strActualSourceIp,
                    itExisting->typeSource
                );
                return;
            }

            if (vecCandidates.size() + 1U
                >= MAX_CANDIDATE_VERSIONS_PER_PACKET)
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::TamperedVariant,
                    0,
                    udpData.u32IntervalIndex(),
                    udpData.u32PacketIndex(),
                    std::nullopt,
                    strCandidateHash,
                    "Attack candidate arrived before baseline and hit the version limit",
                    "",
                    "",
                    {},
                    1,
                    protocol::ObservationSeverity::Error
                );
                return;
            }

            const std::uint64_t u64CandidateEventId = nextObservationEventId();
            vecCandidates.push_back(AdditionalCandidateRecord{
                udpData,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64CandidateEventId,
                strCandidateHash,
                1,
                PacketStatus::Pending,
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            });
            queuePacketObservationLocked(
                staReceiver,
                udpPacket,
                queDatagram.vecDatagram,
                queDatagram.u64ReceiveTimestampMilliseconds,
                u64CandidateEventId,
                1,
                protocol::PacketAuthenticationStatus::Pending,
                "Attack candidate retained while waiting for normal baseline",
                queDatagram.strActualSourceIp,
                queDatagram.typeSource
            );
            return;
        }

        recPacket.optPacket = udpData;
        recPacket.statusPacket = PacketStatus::Pending;
        recPacket.vecRawDatagram = queDatagram.vecDatagram;
        recPacket.u64ReceiveTimestampMilliseconds =
            queDatagram.u64ReceiveTimestampMilliseconds;
        recPacket.u64ObservationEventId = nextObservationEventId();
        recPacket.strCandidateHash = strCandidateHash;
        recPacket.u32DuplicateCount = 1;
        recPacket.strActualSourceIp = queDatagram.strActualSourceIp;
        recPacket.typeSource = queDatagram.typeSource;
        ++staReceiver.u32ReceivedPacketCount;
        recordReceivedDataFieldsLocked(staReceiver, udpData);
        queuePacketObservationLocked(
            staReceiver,
            udpPacket,
            recPacket.vecRawDatagram,
            recPacket.u64ReceiveTimestampMilliseconds,
            recPacket.u64ObservationEventId,
            recPacket.u32DuplicateCount,
            protocol::PacketAuthenticationStatus::Pending,
            "Waiting for disclosed key",
            recPacket.strActualSourceIp,
            recPacket.typeSource
        );

        if (udpData.optDisclosedKey().has_value())
        {
            processDisclosedKeyLocked(
                staReceiver,
                udpData.u32IntervalIndex(),
                udpData.optDisclosedKey().value(),
                vecResults
            );
        }
    }

    void recordReceivedDataFieldsLocked(
        ReceiverState& staReceiver,
        const protocol::UdpDataPacket& udpData
    )
    {
        if (!staReceiver.optMetricCollector.has_value())
        {
            return;
        }

        if (std::holds_alternative<protocol::NativeUdpAuthenticationDetails>(
                udpData.varAuthenticationDetails()
            ))
        {
            staReceiver.optMetricCollector->addReceivedAuthBytes(
                metrics::CommunicationCostCalculator::u64NativeDataPacketBytes()
            );
            return;
        }

        const auto& detImproved = std::get<
            protocol::ImprovedUdpAuthenticationDetails
        >(udpData.varAuthenticationDetails());
        const std::size_t nTauCount = detImproved.optGroupDetails().has_value()
            ? detImproved.optGroupDetails()->vecSamdTau().size()
            : 0;
        staReceiver.optMetricCollector->addReceivedAuthBytes(
            metrics::CommunicationCostCalculator::u64ImprovedDataPacketBytes(
                nTauCount,
                detImproved.optGroupDetails().has_value()
            )
        );
    }

    bool bIsPacketTimeSafe(
        const ReceiverState& staReceiver,
        std::uint32_t u32DataIntervalIndex,
        std::uint64_t u64ReceiveTimestampMilliseconds
    ) const
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        const std::uint32_t u32DisclosureInterval =
            u32DataIntervalIndex + prmRound.u32DisclosureDelay();
        const std::optional<std::uint64_t> optDisclosureTimestamp =
            optIntervalStartTimestamp(staReceiver, u32DisclosureInterval);

        // 披露时间位于尚未恢复的暂停区间时，密钥仍未计划披露，报文保持安全。
        if (!optDisclosureTimestamp.has_value())
        {
            return true;
        }

        return u64ReceiveTimestampMilliseconds
                + staReceiver.u32ClockToleranceMilliseconds
            < optDisclosureTimestamp.value();
    }

    std::optional<std::uint64_t> optIntervalStartTimestamp(
        const ReceiverState& staReceiver,
        std::uint32_t u32LogicalInterval
    ) const
    {
        const TimelineSegment* pSegment = nullptr;
        for (const TimelineSegment& segTimeline : staReceiver.vecTimeline)
        {
            if (segTimeline.u32FirstLogicalInterval > u32LogicalInterval)
            {
                break;
            }

            pSegment = &segTimeline;
        }

        if (pSegment == nullptr)
        {
            return std::nullopt;
        }

        if (staReceiver.optPauseAfterInterval.has_value()
            && u32LogicalInterval > staReceiver.optPauseAfterInterval.value()
            && pSegment->u32FirstLogicalInterval
                <= staReceiver.optPauseAfterInterval.value())
        {
            return std::nullopt;
        }

        const std::uint64_t u64Offset =
            static_cast<std::uint64_t>(
                u32LogicalInterval - pSegment->u32FirstLogicalInterval
            )
            * staReceiver.ctxContext.prmRoundParameters()
                .u32IntervalMilliseconds();
        return pSegment->u64StartTimestampMilliseconds + u64Offset;
    }

    bool processDisclosedKeyLocked(
        ReceiverState& staReceiver,
        std::uint32_t u32DisclosureInterval,
        const protocol::BinaryBlock& arrDisclosedKey,
        std::vector<AuthenticationRuntimeResult>& vecResults
    )
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        if (u32DisclosureInterval <= prmRound.u32DisclosureDelay())
        {
            staReceiver.bProtocolIncomplete = true;
            return false;
        }

        const std::uint32_t u32DisclosedKeyIndex =
            u32DisclosureInterval - prmRound.u32DisclosureDelay();
        if (u32DisclosedKeyIndex > prmRound.nDataIntervalCount())
        {
            staReceiver.bProtocolIncomplete = true;
            return false;
        }

        const crypto::OpenSslCryptoProvider crpProvider(
            prmRound.algCryptoAlgorithm()
        );
        crypto::Digest digCurrent = digMapBlock(arrDisclosedKey);
        const bool bMeasureKey =
            staReceiver.optMetricCollector.has_value()
            && m_ptrPerformanceSampler != nullptr;
        if (bMeasureKey)
        {
            m_ptrPerformanceSampler->begin();
        }
        const bool bKeyVerified = crypto::KeyChainVerifier::bVerifyDisclosedKey(
                crpProvider,
                digCurrent,
                u32DisclosedKeyIndex,
                staReceiver.ctxContext.digCommitmentKey()
            );
        if (bMeasureKey)
        {
            staReceiver.optMetricCollector->addDisclosureKeyMeasurement(
                m_ptrPerformanceSampler->mstEnd()
            );
        }

        if (!bKeyVerified)
        {
            staReceiver.bProtocolIncomplete = true;
            return false;
        }

        if (staReceiver.optMetricCollector.has_value()
            && staReceiver.setCountedDisclosureKeyIndexes.insert(
                u32DisclosedKeyIndex
            ).second)
        {
            staReceiver.optMetricCollector->addReceivedAuthBytes(
                metrics::CommunicationCostCalculator::u64DisclosedKeyBytes()
            );
        }

        // 后续合法密钥可沿单向链补回此前丢失的旧披露密钥。
        for (std::uint32_t u32KeyIndex = u32DisclosedKeyIndex;
             u32KeyIndex > 0;
             --u32KeyIndex)
        {
            const auto itExisting = staReceiver.mapDisclosedKeys.find(u32KeyIndex);
            if (itExisting != staReceiver.mapDisclosedKeys.end()
                && !crypto::CryptoUtilities::bDigestEquals(
                    itExisting->second,
                    digCurrent
                ))
            {
                staReceiver.bProtocolIncomplete = true;
                return false;
            }

            staReceiver.mapDisclosedKeys.emplace(u32KeyIndex, digCurrent);
            verifyIntervalLocked(staReceiver, u32KeyIndex);
            digCurrent = crpProvider.digHash(
                crypto::CryptoUtilities::vecToByteBuffer(digCurrent)
            );
        }

        if (u32DisclosedKeyIndex == prmRound.nDataIntervalCount())
        {
            vecResults.push_back(finalizeLocked(staReceiver));
        }

        return true;
    }

    void verifyIntervalLocked(
        ReceiverState& staReceiver,
        std::uint32_t u32IntervalIndex
    )
    {
        if (staReceiver.setVerifiedIntervals.count(u32IntervalIndex) > 0)
        {
            return;
        }

        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        const auto itKey = staReceiver.mapDisclosedKeys.find(u32IntervalIndex);
        if (itKey == staReceiver.mapDisclosedKeys.end())
        {
            return;
        }

        try
        {
            if (prmRound.modeAuthentication() == TeslaAuthenticationMode::Native)
            {
                verifyNativeIntervalLocked(
                    staReceiver,
                    u32IntervalIndex,
                    itKey->second
                );
            }
            else
            {
                verifyImprovedIntervalLocked(
                    staReceiver,
                    u32IntervalIndex,
                    itKey->second
                );
            }
        }
        catch (...)
        {
            staReceiver.bProtocolIncomplete = true;
        }

        staReceiver.setVerifiedIntervals.insert(u32IntervalIndex);
    }

    AuthenticationGroupInput grpCreateReceived(
        const ReceiverState& staReceiver,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32GroupIndex,
        std::uint32_t u32FirstPacketIndex,
        std::uint32_t u32LastPacketIndex
    ) const
    {
        std::vector<AuthenticationGroupInput::PacketSlot> vecSlots;
        vecSlots.reserve(u32LastPacketIndex - u32FirstPacketIndex + 1U);

        for (std::uint32_t u32PacketIndex = u32FirstPacketIndex;
             u32PacketIndex <= u32LastPacketIndex;
             ++u32PacketIndex)
        {
            const PacketRecord& recPacket =
                staReceiver.vecPacketRecords[u32PacketIndex];
            if (!recPacket.optPacket.has_value())
            {
                vecSlots.push_back(std::nullopt);
                continue;
            }

            vecSlots.emplace_back(UdpAuthenticationInputMapper::pktMapDataPacket(
                staReceiver.ctxContext.strSenderId(),
                recPacket.optPacket.value()
            ));
        }

        return AuthenticationGroupInput(
            staReceiver.ctxContext.strSenderId(),
            staReceiver.ctxContext.u64ChainId(),
            u32IntervalIndex,
            u32GroupIndex,
            u32FirstPacketIndex,
            std::move(vecSlots)
        );
    }

    AuthenticationGroupInput grpCreateAttackCandidate(
        const ReceiverState& staReceiver,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32GroupIndex,
        std::uint32_t u32FirstPacketIndex,
        std::uint32_t u32LastPacketIndex,
        std::vector<std::uint32_t>& vecReplacedPacketIndexes
    ) const
    {
        std::vector<AuthenticationGroupInput::PacketSlot> vecSlots;
        vecSlots.reserve(u32LastPacketIndex - u32FirstPacketIndex + 1U);

        for (std::uint32_t u32PacketIndex = u32FirstPacketIndex;
             u32PacketIndex <= u32LastPacketIndex;
             ++u32PacketIndex)
        {
            const PacketRecord& recBaseline =
                staReceiver.vecPacketRecords[u32PacketIndex];
            const auto itCandidates =
                staReceiver.mapAdditionalCandidates.find(u32PacketIndex);
            const AdditionalCandidateRecord* pAttackCandidate = nullptr;
            if (itCandidates != staReceiver.mapAdditionalCandidates.end())
            {
                const auto itAttack = std::find_if(
                    itCandidates->second.begin(),
                    itCandidates->second.end(),
                    [](const AdditionalCandidateRecord& recCandidate)
                    {
                        return recCandidate.typeSource
                            == protocol::PacketSourceType::AttackInjection;
                    }
                );
                if (itAttack != itCandidates->second.end())
                {
                    pAttackCandidate = &(*itAttack);
                }
            }

            if (pAttackCandidate != nullptr)
            {
                vecSlots.emplace_back(
                    UdpAuthenticationInputMapper::pktMapDataPacket(
                        staReceiver.ctxContext.strSenderId(),
                        pAttackCandidate->udpPacket
                    )
                );
                vecReplacedPacketIndexes.push_back(u32PacketIndex);
            }
            else if (recBaseline.optPacket.has_value())
            {
                vecSlots.emplace_back(
                    UdpAuthenticationInputMapper::pktMapDataPacket(
                        staReceiver.ctxContext.strSenderId(),
                        recBaseline.optPacket.value()
                    )
                );
            }
            else
            {
                vecSlots.push_back(std::nullopt);
            }
        }

        return AuthenticationGroupInput(
            staReceiver.ctxContext.strSenderId(),
            staReceiver.ctxContext.u64ChainId(),
            u32IntervalIndex,
            u32GroupIndex,
            u32FirstPacketIndex,
            std::move(vecSlots)
        );
    }

    void queueVerificationMetricLocked(
        ReceiverState& staReceiver,
        std::uint32_t u32PacketCount,
        const metrics::PerformanceMeasurement& mstPerformance,
        metrics::VerificationMetricDetails varDetails
    )
    {
        if (!staReceiver.optMetricCollector.has_value())
        {
            return;
        }

        metrics::VerificationMetricSample smpVerification(
            m_u64NextMetricEventId++,
            u64NowMilliseconds(),
            staReceiver.strRoundId,
            staReceiver.ctxContext.strSenderId(),
            staReceiver.ctxContext.u64ChainId(),
            u32PacketCount,
            mstPerformance,
            std::move(varDetails)
        );
        staReceiver.optMetricCollector->addVerificationSample(smpVerification);
        m_vecPendingMetrics.emplace_back(std::move(smpVerification));
    }

    void verifyNativeIntervalLocked(
        ReceiverState& staReceiver,
        std::uint32_t u32IntervalIndex,
        const crypto::Digest& digDataKey
    )
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        const std::uint32_t u32FirstPacketIndex =
            (u32IntervalIndex - 1U) * prmRound.u32PacketsPerInterval() + 1U;
        const std::uint32_t u32LastPacketIndex = std::min(
            prmRound.u32TotalPacketCount(),
            u32IntervalIndex * prmRound.u32PacketsPerInterval()
        );
        const AuthenticationGroupInput grpInput = grpCreateReceived(
            staReceiver,
            u32IntervalIndex,
            u32IntervalIndex,
            u32FirstPacketIndex,
            u32LastPacketIndex
        );

        std::vector<std::optional<crypto::Digest>> vecMacs;
        vecMacs.reserve(grpInput.nPacketSlotCount());
        for (std::uint32_t u32PacketIndex = u32FirstPacketIndex;
             u32PacketIndex <= u32LastPacketIndex;
             ++u32PacketIndex)
        {
            const PacketRecord& recPacket =
                staReceiver.vecPacketRecords[u32PacketIndex];
            if (!recPacket.optPacket.has_value())
            {
                vecMacs.push_back(std::nullopt);
                continue;
            }

            const auto* pNative = std::get_if<
                protocol::NativeUdpAuthenticationDetails
            >(&recPacket.optPacket->varAuthenticationDetails());
            vecMacs.push_back(
                pNative == nullptr
                    ? std::nullopt
                    : std::optional<crypto::Digest>(
                        digMapBlock(pNative->arrPacketMac())
                    )
            );
        }

        const crypto::OpenSslCryptoProvider crpProvider(
            prmRound.algCryptoAlgorithm()
        );
        const NativeTeslaStrategy stgStrategy(crpProvider);
        std::vector<std::pair<std::size_t, metrics::PerformanceMeasurement>>
            vecMeasurements;
        VerificationMeasurementHandler fnMeasurementHandler;
        if (staReceiver.optMetricCollector.has_value())
        {
            fnMeasurementHandler = [&vecMeasurements](
                std::size_t nPosition,
                const metrics::PerformanceMeasurement& mstPerformance
            )
            {
                vecMeasurements.emplace_back(nPosition, mstPerformance);
            };
        }
        const TeslaVerificationResult vfyResult = stgStrategy.vfyVerify(
            grpInput,
            NativeAuthenticationDetails(std::move(vecMacs)),
            digDataKey,
            m_ptrPerformanceSampler.get(),
            std::move(fnMeasurementHandler)
        );
        const NativeVerificationDetails& detResult =
            std::get<NativeVerificationDetails>(vfyResult.varDetails());

        for (const auto& prMeasurement : vecMeasurements)
        {
            queueVerificationMetricLocked(
                staReceiver,
                1,
                prMeasurement.second,
                metrics::NativeVerificationMetricDetails(
                    u32IntervalIndex,
                    u32FirstPacketIndex
                        + static_cast<std::uint32_t>(prMeasurement.first)
                )
            );
        }

        for (std::size_t nPosition = 0;
             nPosition < detResult.vecPacketStatuses().size();
             ++nPosition)
        {
            PacketRecord& recPacket =
                staReceiver.vecPacketRecords[u32FirstPacketIndex + nPosition];
            if (!recPacket.optPacket.has_value())
            {
                continue;
            }

            recPacket.statusPacket =
                detResult.vecPacketStatuses()[nPosition]
                    == NativePacketStatus::Passed
                ? PacketStatus::Passed
                : PacketStatus::Failed;

            queuePacketObservationLocked(
                staReceiver,
                protocol::UdpAuthenticationPacket(recPacket.optPacket.value()),
                recPacket.vecRawDatagram,
                recPacket.u64ReceiveTimestampMilliseconds,
                recPacket.u64ObservationEventId,
                recPacket.u32DuplicateCount,
                statusMap(recPacket.statusPacket),
                recPacket.statusPacket == PacketStatus::Passed
                    ? "Native packet MAC passed"
                    : "Native packet MAC failed",
                recPacket.strActualSourceIp,
                recPacket.typeSource
            );

            if (recPacket.statusPacket == PacketStatus::Failed)
            {
                const protocol::UdpDataPacket& udpFailed =
                    recPacket.optPacket.value();
                const auto* pNative = std::get_if<
                    protocol::NativeUdpAuthenticationDetails
                >(&udpFailed.varAuthenticationDetails());
                const AuthenticationPacketInput pktInput =
                    UdpAuthenticationInputMapper::pktMapDataPacket(
                        staReceiver.ctxContext.strSenderId(),
                        udpFailed
                    );
                const crypto::Digest digCalculated =
                    TeslaMac::digComputePacketMac(
                        crpProvider,
                        digDataKey,
                        pktInput
                    );
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::MacFailed,
                    recPacket.u64ObservationEventId,
                    u32IntervalIndex,
                    udpFailed.u32PacketIndex(),
                    std::nullopt,
                    recPacket.strCandidateHash,
                    "Message recalculated MAC differs from the received MAC",
                    pNative == nullptr
                        ? ""
                        : strHex(pNative->arrPacketMac()),
                    strHex(digCalculated),
                    {},
                    recPacket.u32DuplicateCount,
                    protocol::ObservationSeverity::Error,
                    recPacket.strActualSourceIp
                );
            }
        }

        // 每个不同攻击候选只进行一次真实MAC验证；相同副本只累计重复次数。
        for (std::uint32_t u32PacketIndex = u32FirstPacketIndex;
             u32PacketIndex <= u32LastPacketIndex;
             ++u32PacketIndex)
        {
            const auto itCandidates =
                staReceiver.mapAdditionalCandidates.find(u32PacketIndex);
            if (itCandidates == staReceiver.mapAdditionalCandidates.end())
            {
                continue;
            }

            const PacketRecord& recBaseline =
                staReceiver.vecPacketRecords[u32PacketIndex];
            for (AdditionalCandidateRecord& recCandidate : itCandidates->second)
            {
                const auto* pNative = std::get_if<
                    protocol::NativeUdpAuthenticationDetails
                >(&recCandidate.udpPacket.varAuthenticationDetails());
                const AuthenticationPacketInput pktInput =
                    UdpAuthenticationInputMapper::pktMapDataPacket(
                        staReceiver.ctxContext.strSenderId(),
                        recCandidate.udpPacket
                    );
                const crypto::Digest digCalculated =
                    TeslaMac::digComputePacketMac(
                        crpProvider,
                        digDataKey,
                        pktInput
                    );
                const bool bPassed = pNative != nullptr
                    && crypto::CryptoUtilities::bDigestEquals(
                        digMapBlock(pNative->arrPacketMac()),
                        digCalculated
                    );
                recCandidate.statusPacket = bPassed
                    ? PacketStatus::Passed
                    : PacketStatus::Failed;
                const bool bAttackDetected =
                    recBaseline.statusPacket == PacketStatus::Passed
                    && !bPassed;

                queuePacketObservationLocked(
                    staReceiver,
                    protocol::UdpAuthenticationPacket(recCandidate.udpPacket),
                    recCandidate.vecRawDatagram,
                    recCandidate.u64ReceiveTimestampMilliseconds,
                    recCandidate.u64ObservationEventId,
                    recCandidate.u32DuplicateCount,
                    statusMap(recCandidate.statusPacket),
                    bAttackDetected
                        ? "TAMPERED_VARIANT: baseline passed and conflicting MAC failed"
                        : (bPassed
                            ? "Conflicting candidate MAC passed"
                            : "Conflicting candidate MAC failed"),
                    recCandidate.strActualSourceIp,
                    recCandidate.typeSource
                );

                if (!bPassed)
                {
                    queueFailureLocked(
                        staReceiver,
                        recCandidate.typeSource
                                == protocol::PacketSourceType::AttackInjection
                            ? protocol::AuthenticationFailureType::TamperedVariant
                            : protocol::AuthenticationFailureType::MacFailed,
                        recCandidate.u64ObservationEventId,
                        u32IntervalIndex,
                        u32PacketIndex,
                        std::nullopt,
                        recCandidate.strCandidateHash,
                        bAttackDetected
                            ? "ATTACK_DETECTED: legal baseline passed and attack candidate failed"
                            : "Conflicting candidate failed native MAC verification",
                        pNative == nullptr
                            ? ""
                            : strHex(pNative->arrPacketMac()),
                        strHex(digCalculated),
                        {},
                        recCandidate.u32DuplicateCount,
                        protocol::ObservationSeverity::Error,
                        recCandidate.strActualSourceIp
                    );
                }
            }
        }
    }

    void verifyImprovedIntervalLocked(
        ReceiverState& staReceiver,
        std::uint32_t u32IntervalIndex,
        const crypto::Digest& digDataKey
    )
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        const ImprovedTeslaParameters& prmImproved =
            prmRound.optImprovedParameters().value();
        const crypto::OpenSslCryptoProvider crpProvider(
            prmRound.algCryptoAlgorithm()
        );
        const ImprovedTeslaStrategy stgStrategy(
            crpProvider,
            prmImproved.u32GroupSize(),
            prmImproved.u32DetectionThreshold()
        );
        const std::uint32_t u32IntervalFirstPacket =
            (u32IntervalIndex - 1U) * prmRound.u32PacketsPerInterval() + 1U;
        const std::uint32_t u32IntervalLastPacket = std::min(
            prmRound.u32TotalPacketCount(),
            u32IntervalIndex * prmRound.u32PacketsPerInterval()
        );

        std::uint32_t u32GroupFirstPacket = u32IntervalFirstPacket;
        while (u32GroupFirstPacket <= u32IntervalLastPacket)
        {
            const std::uint32_t u32GroupLastPacket = std::min(
                u32IntervalLastPacket,
                u32GroupFirstPacket + prmImproved.u32GroupSize() - 1U
            );
            const std::uint32_t u32GroupIndex =
                ((u32GroupFirstPacket - 1U) / prmImproved.u32GroupSize()) + 1U;
            const AuthenticationGroupInput grpInput = grpCreateReceived(
                staReceiver,
                u32IntervalIndex,
                u32GroupIndex,
                u32GroupFirstPacket,
                u32GroupLastPacket
            );

            std::vector<crypto::Digest> vecTau;
            std::optional<crypto::Digest> optFastGroupTag;
            const PacketRecord& recGroupEnd =
                staReceiver.vecPacketRecords[u32GroupLastPacket];
            if (recGroupEnd.optPacket.has_value())
            {
                const auto* pImproved = std::get_if<
                    protocol::ImprovedUdpAuthenticationDetails
                >(&recGroupEnd.optPacket->varAuthenticationDetails());
                if (pImproved != nullptr
                    && pImproved->optGroupDetails().has_value())
                {
                    for (const protocol::BinaryBlock& arrTau
                        : pImproved->optGroupDetails()->vecSamdTau())
                    {
                        vecTau.push_back(digMapBlock(arrTau));
                    }
                    optFastGroupTag = digMapBlock(
                        pImproved->optGroupDetails()->arrFastGroupTag()
                    );
                }
            }

            std::optional<metrics::PerformanceMeasurement> optMeasurement;
            VerificationMeasurementHandler fnMeasurementHandler;
            if (staReceiver.optMetricCollector.has_value())
            {
                fnMeasurementHandler = [&optMeasurement](
                    std::size_t,
                    const metrics::PerformanceMeasurement& mstPerformance
                )
                {
                    optMeasurement = mstPerformance;
                };
            }
            const TeslaVerificationResult vfyResult = stgStrategy.vfyVerify(
                grpInput,
                ImprovedAuthenticationDetails(
                    vecTau,
                    optFastGroupTag
                ),
                digDataKey,
                m_ptrPerformanceSampler.get(),
                std::move(fnMeasurementHandler)
            );
            const ImprovedVerificationDetails& detResult =
                std::get<ImprovedVerificationDetails>(vfyResult.varDetails());

            metrics::VerificationMetricPath pathMetric =
                metrics::VerificationMetricPath::KsRsFallback;
            if (detResult.pathVerification()
                == ImprovedVerificationPath::FastGroupPass)
            {
                pathMetric = metrics::VerificationMetricPath::FastGroupPass;
            }
            else if (detResult.pathVerification()
                == ImprovedVerificationPath::IncompleteGroupTags)
            {
                pathMetric =
                    metrics::VerificationMetricPath::IncompleteGroupTags;
            }
            if (optMeasurement.has_value())
            {
                queueVerificationMetricLocked(
                    staReceiver,
                    u32GroupLastPacket - u32GroupFirstPacket + 1U,
                    optMeasurement.value(),
                    metrics::ImprovedVerificationMetricDetails(
                        u32GroupIndex,
                        u32GroupFirstPacket,
                        u32GroupLastPacket,
                        pathMetric
                    )
                );
            }

            if (detResult.pathVerification()
                == ImprovedVerificationPath::IncompleteGroupTags)
            {
                staReceiver.bProtocolIncomplete = true;
            }

            for (std::size_t nPosition
                : detResult.vecAuthenticatedPositions())
            {
                PacketRecord& recPacket =
                    staReceiver.vecPacketRecords[
                        u32GroupFirstPacket + nPosition
                    ];
                if (recPacket.optPacket.has_value())
                {
                    recPacket.statusPacket = PacketStatus::Passed;
                }
            }

            for (std::size_t nPosition : detResult.vecRejectedPositions())
            {
                PacketRecord& recPacket =
                    staReceiver.vecPacketRecords[
                        u32GroupFirstPacket + nPosition
                    ];
                if (recPacket.optPacket.has_value())
                {
                    recPacket.statusPacket = PacketStatus::Failed;
                }
            }

            if (vfyResult.bPassed())
            {
                for (std::uint32_t u32PacketIndex = u32GroupFirstPacket;
                     u32PacketIndex <= u32GroupLastPacket;
                     ++u32PacketIndex)
                {
                    PacketRecord& recPacket =
                        staReceiver.vecPacketRecords[u32PacketIndex];
                    if (recPacket.optPacket.has_value())
                    {
                        recPacket.statusPacket = PacketStatus::Passed;
                    }
                }
            }

            protocol::GroupVerificationPath pathObservation =
                protocol::GroupVerificationPath::KsRsFallback;
            if (detResult.pathVerification()
                == ImprovedVerificationPath::FastGroupPass)
            {
                pathObservation = protocol::GroupVerificationPath::FastGroupPass;
            }
            else if (detResult.pathVerification()
                == ImprovedVerificationPath::IncompleteGroupTags)
            {
                pathObservation =
                    protocol::GroupVerificationPath::IncompleteGroupTags;
            }

            std::vector<std::uint32_t> vecLocatedPacketIndexes;
            for (std::size_t nPosition : detResult.vecRejectedPositions())
            {
                vecLocatedPacketIndexes.push_back(
                    u32GroupFirstPacket + static_cast<std::uint32_t>(nPosition)
                );
            }

            std::vector<protocol::MatrixLocationStepControlDetails> vecSteps;
            if (pathObservation == protocol::GroupVerificationPath::KsRsFallback)
            {
                std::vector<std::uint32_t> vecInitialCandidates;
                for (std::uint32_t u32PacketIndex = u32GroupFirstPacket;
                     u32PacketIndex <= u32GroupLastPacket;
                     ++u32PacketIndex)
                {
                    vecInitialCandidates.push_back(u32PacketIndex);
                }
                vecSteps.emplace_back(
                    1,
                    "Initialize all packet slots as candidates",
                    std::vector<std::uint32_t>{},
                    std::move(vecInitialCandidates)
                );

                std::uint32_t u32StepIndex = 2;
                for (const KsRsLocationStep& detLocation
                    : detResult.vecLocationSteps())
                {
                    std::vector<std::uint32_t> vecNewGood;
                    std::vector<std::uint32_t> vecRemaining;
                    for (std::size_t nPosition
                        : detLocation.vecNewGoodPositions())
                    {
                        vecNewGood.push_back(
                            u32GroupFirstPacket
                            + static_cast<std::uint32_t>(nPosition)
                        );
                    }
                    for (std::size_t nPosition
                        : detLocation.vecRemainingCandidatePositions())
                    {
                        vecRemaining.push_back(
                            u32GroupFirstPacket
                            + static_cast<std::uint32_t>(nPosition)
                        );
                    }
                    vecSteps.emplace_back(
                        u32StepIndex++,
                        "Scan a verified test row and exclude proven-good packets",
                        std::move(vecNewGood),
                        std::move(vecRemaining)
                    );
                }
                vecSteps.emplace_back(
                    u32StepIndex,
                    "Finish row scan and retain final bad-packet candidates",
                    std::vector<std::uint32_t>{},
                    vecLocatedPacketIndexes
                );
            }

            m_vecPendingObservations.emplace_back(
                protocol::ImprovedGroupObservationControlDetails(
                    nextObservationEventId(),
                    u64NowMilliseconds(),
                    staReceiver.strRoundId,
                    staReceiver.ctxContext.strSenderId(),
                    staReceiver.ctxContext.u64ChainId(),
                    u32GroupIndex,
                    u32GroupFirstPacket,
                    u32GroupLastPacket,
                    prmImproved.u32DetectionThreshold(),
                    pathObservation,
                    detResult.bFastGroupTagMatched(),
                    detResult.bDetectionThresholdExceeded(),
                    vecLocatedPacketIndexes,
                    std::move(vecSteps)
                )
            );

            for (std::uint32_t u32PacketIndex = u32GroupFirstPacket;
                 u32PacketIndex <= u32GroupLastPacket;
                 ++u32PacketIndex)
            {
                PacketRecord& recPacket =
                    staReceiver.vecPacketRecords[u32PacketIndex];
                if (!recPacket.optPacket.has_value())
                {
                    continue;
                }
                queuePacketObservationLocked(
                    staReceiver,
                    protocol::UdpAuthenticationPacket(recPacket.optPacket.value()),
                    recPacket.vecRawDatagram,
                    recPacket.u64ReceiveTimestampMilliseconds,
                    recPacket.u64ObservationEventId,
                    recPacket.u32DuplicateCount,
                    statusMap(recPacket.statusPacket),
                    recPacket.statusPacket == PacketStatus::Passed
                        ? "Improved group authentication passed"
                        : "Improved group authentication rejected this packet",
                    recPacket.strActualSourceIp,
                    recPacket.typeSource
                );
            }

            if (pathObservation == protocol::GroupVerificationPath::KsRsFallback)
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::FastGroupFailed,
                    recGroupEnd.u64ObservationEventId,
                    u32IntervalIndex,
                    u32GroupFirstPacket,
                    u32GroupIndex,
                    recGroupEnd.strCandidateHash,
                    "FastGroupTag failed and KS+RS fallback was executed",
                    "",
                    "",
                    vecLocatedPacketIndexes,
                    1,
                    protocol::ObservationSeverity::Error
                );
            }
            else if (pathObservation
                == protocol::GroupVerificationPath::IncompleteGroupTags)
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::IncompleteGroupTags,
                    recGroupEnd.u64ObservationEventId,
                    u32IntervalIndex,
                    u32GroupFirstPacket,
                    u32GroupIndex,
                    recGroupEnd.strCandidateHash,
                    "Improved group did not contain a complete tau/FastGroupTag set",
                    "",
                    "",
                    {},
                    1,
                    protocol::ObservationSeverity::Error
                );
            }

            if (detResult.bDetectionThresholdExceeded())
            {
                queueFailureLocked(
                    staReceiver,
                    protocol::AuthenticationFailureType::DetectionThresholdExceeded,
                    recGroupEnd.u64ObservationEventId,
                    u32IntervalIndex,
                    u32GroupFirstPacket,
                    u32GroupIndex,
                    recGroupEnd.strCandidateHash,
                    "Located bad-packet candidates exceed the configured threshold",
                    "",
                    "",
                    vecLocatedPacketIndexes,
                    1,
                    protocol::ObservationSeverity::Warning
                );
            }

            std::vector<std::uint32_t> vecReplacedPacketIndexes;
            const AuthenticationGroupInput grpAttack = grpCreateAttackCandidate(
                staReceiver,
                u32IntervalIndex,
                u32GroupIndex,
                u32GroupFirstPacket,
                u32GroupLastPacket,
                vecReplacedPacketIndexes
            );
            if (!vecReplacedPacketIndexes.empty())
            {
                if (detResult.pathVerification()
                    != ImprovedVerificationPath::FastGroupPass)
                {
                    for (std::uint32_t u32PacketIndex
                        : vecReplacedPacketIndexes)
                    {
                        const auto& vecCandidates = staReceiver
                            .mapAdditionalCandidates[u32PacketIndex];
                        const auto itAttack = std::find_if(
                            vecCandidates.begin(),
                            vecCandidates.end(),
                            [](const AdditionalCandidateRecord& recCandidate)
                            {
                                return recCandidate.typeSource
                                    == protocol::PacketSourceType::AttackInjection;
                            }
                        );
                        if (itAttack != vecCandidates.end())
                        {
                            queueFailureLocked(
                                staReceiver,
                                protocol::AuthenticationFailureType::
                                    UnverifiableMissingBaseline,
                                itAttack->u64ObservationEventId,
                                u32IntervalIndex,
                                u32PacketIndex,
                                u32GroupIndex,
                                itAttack->strCandidateHash,
                                "Attack candidate cannot be judged because the normal group did not pass FastGroupTag",
                                "",
                                "",
                                {},
                                itAttack->u32DuplicateCount,
                                protocol::ObservationSeverity::Error,
                                itAttack->strActualSourceIp
                            );
                        }
                    }
                }
                else
                {
                    std::optional<metrics::PerformanceMeasurement>
                        optAttackMeasurement;
                    VerificationMeasurementHandler fnAttackMeasurement;
                    if (staReceiver.optMetricCollector.has_value())
                    {
                        fnAttackMeasurement = [&optAttackMeasurement](
                            std::size_t,
                            const metrics::PerformanceMeasurement& mstPerformance
                        )
                        {
                            optAttackMeasurement = mstPerformance;
                        };
                    }

                    const TeslaVerificationResult vfyAttack =
                        stgStrategy.vfyVerify(
                            grpAttack,
                            ImprovedAuthenticationDetails(
                                vecTau,
                                optFastGroupTag
                            ),
                            digDataKey,
                            m_ptrPerformanceSampler.get(),
                            std::move(fnAttackMeasurement)
                        );
                    const ImprovedVerificationDetails& detAttack = std::get<
                        ImprovedVerificationDetails
                    >(vfyAttack.varDetails());
                    if (optAttackMeasurement.has_value())
                    {
                        queueVerificationMetricLocked(
                            staReceiver,
                            u32GroupLastPacket - u32GroupFirstPacket + 1U,
                            optAttackMeasurement.value(),
                            metrics::ImprovedVerificationMetricDetails(
                                u32GroupIndex,
                                u32GroupFirstPacket,
                                u32GroupLastPacket,
                                metrics::VerificationMetricPath::KsRsFallback
                            )
                        );
                    }

                    std::vector<std::uint32_t> vecAttackLocatedIndexes;
                    for (std::size_t nPosition
                        : detAttack.vecRejectedPositions())
                    {
                        vecAttackLocatedIndexes.push_back(
                            u32GroupFirstPacket
                                + static_cast<std::uint32_t>(nPosition)
                        );
                    }

                    std::vector<protocol::MatrixLocationStepControlDetails>
                        vecAttackSteps;
                    std::uint32_t u32StepIndex = 1;
                    for (const KsRsLocationStep& detLocation
                        : detAttack.vecLocationSteps())
                    {
                        std::vector<std::uint32_t> vecNewGood;
                        std::vector<std::uint32_t> vecRemaining;
                        for (std::size_t nPosition
                            : detLocation.vecNewGoodPositions())
                        {
                            vecNewGood.push_back(
                                u32GroupFirstPacket
                                    + static_cast<std::uint32_t>(nPosition)
                            );
                        }
                        for (std::size_t nPosition
                            : detLocation.vecRemainingCandidatePositions())
                        {
                            vecRemaining.push_back(
                                u32GroupFirstPacket
                                    + static_cast<std::uint32_t>(nPosition)
                            );
                        }
                        vecAttackSteps.emplace_back(
                            u32StepIndex++,
                            "Attack candidate KS+RS row scan",
                            std::move(vecNewGood),
                            std::move(vecRemaining)
                        );
                    }

                    m_vecPendingObservations.emplace_back(
                        protocol::ImprovedGroupObservationControlDetails(
                            nextObservationEventId(),
                            u64NowMilliseconds(),
                            staReceiver.strRoundId,
                            staReceiver.ctxContext.strSenderId(),
                            staReceiver.ctxContext.u64ChainId(),
                            u32GroupIndex,
                            u32GroupFirstPacket,
                            u32GroupLastPacket,
                            prmImproved.u32DetectionThreshold(),
                            protocol::GroupVerificationPath::KsRsFallback,
                            detAttack.bFastGroupTagMatched(),
                            detAttack.bDetectionThresholdExceeded(),
                            vecAttackLocatedIndexes,
                            std::move(vecAttackSteps)
                        )
                    );

                    for (std::uint32_t u32PacketIndex
                        : vecReplacedPacketIndexes)
                    {
                        auto& vecCandidates = staReceiver
                            .mapAdditionalCandidates[u32PacketIndex];
                        auto itAttack = std::find_if(
                            vecCandidates.begin(),
                            vecCandidates.end(),
                            [](const AdditionalCandidateRecord& recCandidate)
                            {
                                return recCandidate.typeSource
                                    == protocol::PacketSourceType::AttackInjection;
                            }
                        );
                        if (itAttack == vecCandidates.end())
                        {
                            continue;
                        }

                        itAttack->statusPacket = PacketStatus::Failed;
                        queuePacketObservationLocked(
                            staReceiver,
                            protocol::UdpAuthenticationPacket(
                                itAttack->udpPacket
                            ),
                            itAttack->vecRawDatagram,
                            itAttack->u64ReceiveTimestampMilliseconds,
                            itAttack->u64ObservationEventId,
                            itAttack->u32DuplicateCount,
                            protocol::PacketAuthenticationStatus::Failed,
                            "TAMPERED_VARIANT: attack group failed FastGroupTag and entered KS+RS",
                            itAttack->strActualSourceIp,
                            itAttack->typeSource
                        );
                        queueFailureLocked(
                            staReceiver,
                            protocol::AuthenticationFailureType::TamperedVariant,
                            itAttack->u64ObservationEventId,
                            u32IntervalIndex,
                            u32PacketIndex,
                            u32GroupIndex,
                            itAttack->strCandidateHash,
                            detAttack.bDetectionThresholdExceeded()
                                ? "ATTACK_DETECTED; DETECTION_THRESHOLD_EXCEEDED"
                                : "ATTACK_DETECTED; attack candidate located by KS+RS fallback",
                            "",
                            "",
                            vecAttackLocatedIndexes,
                            itAttack->u32DuplicateCount,
                            detAttack.bDetectionThresholdExceeded()
                                ? protocol::ObservationSeverity::Warning
                                : protocol::ObservationSeverity::Error,
                            itAttack->strActualSourceIp
                        );
                    }
                }
            }

            u32GroupFirstPacket = u32GroupLastPacket + 1U;
        }
    }

    void queueMissingPacketFailuresLocked(ReceiverState& staReceiver)
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        for (std::uint32_t u32PacketIndex = 1;
             u32PacketIndex <= prmRound.u32TotalPacketCount();
             ++u32PacketIndex)
        {
            const PacketRecord& recPacket =
                staReceiver.vecPacketRecords[u32PacketIndex];
            if (recPacket.optPacket.has_value())
            {
                continue;
            }

            const std::uint32_t u32IntervalIndex =
                ((u32PacketIndex - 1U) / prmRound.u32PacketsPerInterval()) + 1U;
            std::optional<std::uint32_t> optGroupIndex;
            if (prmRound.modeAuthentication() == TeslaAuthenticationMode::Improved)
            {
                optGroupIndex = ((u32PacketIndex - 1U)
                    / prmRound.optImprovedParameters()->u32GroupSize()) + 1U;
            }
            queueFailureLocked(
                staReceiver,
                protocol::AuthenticationFailureType::MissingPacket,
                0,
                u32IntervalIndex,
                u32PacketIndex,
                optGroupIndex,
                "",
                "Expected packet slot was not received",
                "",
                "",
                {},
                1,
                protocol::ObservationSeverity::Error
            );
        }
    }

    void queueEnergySummaryLocked(
        ReceiverState& staReceiver,
        AuthenticationRuntimeResultStatus statusResult
    )
    {
        if (!staReceiver.optMetricCollector.has_value()
            || staReceiver.bMetricSummaryQueued)
        {
            return;
        }

        m_vecPendingMetrics.emplace_back(
            staReceiver.optMetricCollector->sumCreateEnergySummary(
                u64NowMilliseconds(),
                statusResult == AuthenticationRuntimeResultStatus::Completed
            )
        );
        staReceiver.bMetricSummaryQueued = true;
    }

    AuthenticationRuntimeResult finalizeLocked(ReceiverState& staReceiver)
    {
        const AuthenticationRoundParameters& prmRound =
            staReceiver.ctxContext.prmRoundParameters();
        for (std::uint32_t u32IntervalIndex = 1;
             u32IntervalIndex <= prmRound.nDataIntervalCount();
             ++u32IntervalIndex)
        {
            verifyIntervalLocked(staReceiver, u32IntervalIndex);
        }

        queueMissingPacketFailuresLocked(staReceiver);

        staReceiver.bActive = false;
        staReceiver.bResultReported = true;

        const std::uint32_t u32Authenticated = nCountStatus(
            staReceiver,
            PacketStatus::Passed
        );
        const std::uint32_t u32Failed = nCountStatus(
            staReceiver,
            PacketStatus::Failed
        );
        const std::uint32_t u32Expected = prmRound.u32TotalPacketCount();
        const std::uint32_t u32Missing =
            u32Expected - staReceiver.u32ReceivedPacketCount;

        AuthenticationRuntimeResultDetails varResultDetails =
            varIncompletePayloadDetails(staReceiver);
        bool bPayloadRecovered = false;
        if (u32Authenticated == u32Expected
            && u32Failed == 0
            && u32Missing == 0
            && !staReceiver.bProtocolIncomplete)
        {
            try
            {
                if (prmRound.modePayload() == AuthenticationPayloadMode::Text)
                {
                    const std::string strRecoveredPayload =
                        strRecoveredText(staReceiver);
                    bPayloadRecovered = !strRecoveredPayload.empty();
                    varResultDetails = TextAuthenticationRuntimeResultDetails(
                        strRecoveredPayload
                    );
                }
                else
                {
                    varResultDetails = varRecoverFileDetails(staReceiver);
                    bPayloadRecovered = true;
                }
            }
            catch (const std::exception&)
            {
                staReceiver.bProtocolIncomplete = true;
            }
        }

        AuthenticationRuntimeResultStatus statusResult =
            AuthenticationRuntimeResultStatus::Completed;
        std::string strMessage = prmRound.modePayload()
                == AuthenticationPayloadMode::Text
            ? "Receiver authenticated the complete text round"
            : "Receiver authenticated and recovered the complete file";

        if (staReceiver.bProtocolIncomplete)
        {
            statusResult = AuthenticationRuntimeResultStatus::ProtocolIncomplete;
            strMessage = "Receiver detected incomplete or inconsistent protocol data";
        }
        else if (u32Authenticated != u32Expected
            || u32Failed > 0
            || u32Missing > 0
            || !bPayloadRecovered)
        {
            statusResult = AuthenticationRuntimeResultStatus::AuthenticationFailed;
            strMessage = prmRound.modePayload()
                    == AuthenticationPayloadMode::Text
                ? "Receiver did not authenticate every expected text packet"
                : "Receiver did not authenticate every expected file packet";
        }

        queueEnergySummaryLocked(staReceiver, statusResult);
        updateGlobalRunningLocked();
        return AuthenticationRuntimeResult(
            staReceiver.strRoundId,
            staReceiver.ctxContext.strSenderId(),
            staReceiver.ctxContext.u64ChainId(),
            statusResult,
            u32Expected,
            staReceiver.u32ReceivedPacketCount,
            u32Authenticated,
            u32Failed,
            u32Missing,
            std::move(varResultDetails),
            std::move(strMessage)
        );
    }

    AuthenticationRuntimeResult resCreateResult(
        ReceiverState& staReceiver,
        AuthenticationRuntimeResultStatus statusResult,
        const std::string& strMessage
    )
    {
        const std::uint32_t u32Expected = staReceiver.ctxContext
            .prmRoundParameters().u32TotalPacketCount();
        const std::uint32_t u32Authenticated = nCountStatus(
            staReceiver,
            PacketStatus::Passed
        );
        const std::uint32_t u32Failed = nCountStatus(
            staReceiver,
            PacketStatus::Failed
        );

        queueEnergySummaryLocked(staReceiver, statusResult);
        return AuthenticationRuntimeResult(
            staReceiver.strRoundId,
            staReceiver.ctxContext.strSenderId(),
            staReceiver.ctxContext.u64ChainId(),
            statusResult,
            u32Expected,
            staReceiver.u32ReceivedPacketCount,
            u32Authenticated,
            u32Failed,
            u32Expected - staReceiver.u32ReceivedPacketCount,
            varIncompletePayloadDetails(staReceiver),
            strMessage
        );
    }

    std::uint32_t nCountStatus(
        const ReceiverState& staReceiver,
        PacketStatus statusPacket
    ) const
    {
        return static_cast<std::uint32_t>(std::count_if(
            staReceiver.vecPacketRecords.begin() + 1,
            staReceiver.vecPacketRecords.end(),
            [statusPacket](const PacketRecord& recPacket)
            {
                return recPacket.statusPacket == statusPacket;
            }
        ));
    }

    std::string strRecoveredText(const ReceiverState& staReceiver) const
    {
        std::string strText;

        for (std::size_t nPacketIndex = 1;
             nPacketIndex < staReceiver.vecPacketRecords.size();
             ++nPacketIndex)
        {
            const PacketRecord& recPacket =
                staReceiver.vecPacketRecords[nPacketIndex];
            if (recPacket.statusPacket != PacketStatus::Passed
                || !recPacket.optPacket.has_value())
            {
                continue;
            }

            const AuthenticationPacketInput pktInput =
                UdpAuthenticationInputMapper::pktMapDataPacket(
                    staReceiver.ctxContext.strSenderId(),
                    recPacket.optPacket.value()
                );
            const std::string strCurrent = strDecodeText(pktInput.arrMessage());
            if (strText.empty())
            {
                strText = strCurrent;
            }
            else if (strText != strCurrent)
            {
                return "";
            }
        }

        return strText;
    }

    AuthenticationRuntimeResultDetails varIncompletePayloadDetails(
        const ReceiverState& staReceiver
    ) const
    {
        if (staReceiver.ctxContext.prmRoundParameters().modePayload()
            == AuthenticationPayloadMode::Text)
        {
            return TextAuthenticationRuntimeResultDetails(
                strRecoveredText(staReceiver)
            );
        }

        const std::uint64_t u64OriginalByteCount = std::get<
            FileReceiverPayloadDetails
        >(staReceiver.ctxContext.varPayloadDetails()).u64OriginalByteCount();
        return FileReceiverAuthenticationRuntimeResultDetails(
            u64OriginalByteCount,
            {},
            std::nullopt
        );
    }

    AuthenticationRuntimeResultDetails varRecoverFileDetails(
        const ReceiverState& staReceiver
    ) const
    {
        const std::uint64_t u64OriginalByteCount = std::get<
            FileReceiverPayloadDetails
        >(staReceiver.ctxContext.varPayloadDetails()).u64OriginalByteCount();
        std::vector<workload::FileWorkload::Message> vecMessages;
        vecMessages.reserve(staReceiver.vecPacketRecords.size() - 1U);

        // 固定槽位顺序就是文件分片顺序，缺失位置不能压缩或重排。
        for (std::size_t nPacketIndex = 1;
             nPacketIndex < staReceiver.vecPacketRecords.size();
             ++nPacketIndex)
        {
            const PacketRecord& recPacket =
                staReceiver.vecPacketRecords[nPacketIndex];
            if (recPacket.statusPacket != PacketStatus::Passed
                || !recPacket.optPacket.has_value())
            {
                throw std::logic_error(
                    "File recovery encountered a non-authenticated slot"
                );
            }

            vecMessages.push_back(
                UdpAuthenticationInputMapper::pktMapDataPacket(
                    staReceiver.ctxContext.strSenderId(),
                    recPacket.optPacket.value()
                ).arrMessage()
            );
        }

        crypto::ByteBuffer vecRecovered = workload::FileWorkload::vecRecover(
            vecMessages,
            u64OriginalByteCount
        );
        const crypto::OpenSslCryptoProvider crpSha256(
            crypto::CryptoAlgorithm::Sha256
        );
        const crypto::Digest digRecoveredSha256 = crpSha256.digHash(
            vecRecovered
        );
        return FileReceiverAuthenticationRuntimeResultDetails(
            u64OriginalByteCount,
            std::move(vecRecovered),
            digRecoveredSha256
        );
    }

    void checkPauseAndTimeoutsLocked(
        std::vector<AuthenticationRuntimeResult>& vecResults
    )
    {
        const std::uint64_t u64Now = u64NowMilliseconds();

        bool bAnyPaused = false;
        for (auto& prState : m_mapStates)
        {
            ReceiverState& staReceiver = *prState.second;
            if (!staReceiver.bActive || staReceiver.bResultReported)
            {
                continue;
            }

            if (staReceiver.optPauseAfterInterval.has_value()
                && staReceiver.vecTimeline.back().u32FirstLogicalInterval
                    <= staReceiver.optPauseAfterInterval.value()
                && u64Now >= staReceiver.u64PauseTimestampMilliseconds)
            {
                staReceiver.bPaused = true;
                bAnyPaused = true;
            }

            const AuthenticationRoundParameters& prmRound =
                staReceiver.ctxContext.prmRoundParameters();
            const std::uint32_t u32LastLogicalInterval =
                static_cast<std::uint32_t>(prmRound.nDataIntervalCount())
                + prmRound.u32DisclosureDelay();
            const std::optional<std::uint64_t> optLastStart =
                optIntervalStartTimestamp(staReceiver, u32LastLogicalInterval);
            if (!optLastStart.has_value())
            {
                continue;
            }

            const std::uint64_t u64Deadline =
                optLastStart.value()
                + prmRound.u32IntervalMilliseconds()
                + staReceiver.u32ClockToleranceMilliseconds;
            if (u64Now > u64Deadline)
            {
                // 超时结果同样需要生成可跳转的预期槽位记录，不能只给汇总计数。
                queueMissingPacketFailuresLocked(staReceiver);
                staReceiver.bActive = false;
                staReceiver.bResultReported = true;
                vecResults.push_back(resCreateResult(
                    staReceiver,
                    AuthenticationRuntimeResultStatus::VerificationTimeout,
                    "Receiver timed out waiting for the final disclosed key"
                ));
            }
        }

        m_bPaused = bAnyPaused;
        updateGlobalRunningLocked();
    }

    void updateGlobalRunningLocked()
    {
        m_bRunning = std::any_of(
            m_mapStates.begin(),
            m_mapStates.end(),
            [](const auto& prState)
            {
                return prState.second->bActive;
            }
        );
    }

    void emitResults(
        const std::vector<AuthenticationRuntimeResult>& vecResults
    ) noexcept
    {
        for (const AuthenticationRuntimeResult& resResult : vecResults)
        {
            try
            {
                m_fnResultHandler(resResult);
            }
            catch (...)
            {
                // 节点适配层异常不得终止接收工作线程。
            }
        }
    }

    ResultHandler      m_fnResultHandler;
    ObservationHandler m_fnObservationHandler;
    MetricHandler      m_fnMetricHandler;
    std::unique_ptr<metrics::VerificationPerformanceSampler>
        m_ptrPerformanceSampler;

    mutable std::mutex m_mtxState;
    std::condition_variable m_cndState;
    std::thread m_thrWorker;
    std::map<ContextKey, std::unique_ptr<ReceiverState>> m_mapStates;
    std::map<ContextKey, AttackSourceMapping> m_mapAttackSourceMappings;
    std::deque<QueuedDatagram> m_deqDatagrams;
    std::vector<protocol::AuthenticationObservation> m_vecPendingObservations;
    std::vector<metrics::AuthenticationMetricRecord> m_vecPendingMetrics;
    std::string m_strRoundId;
    std::size_t m_nDroppedQueueDatagramCount = 0;
    std::uint64_t m_u64NextObservationEventId = (1ULL << 40U);
    std::uint64_t m_u64NextMetricEventId = 1;
    std::uint64_t m_u64DosWindowStartMilliseconds = 0;
    std::uint64_t m_u64InvalidWindowCount = 0;
    std::uint64_t m_u64RateLimitedWindowCount = 0;
    std::uint64_t m_u64LegitimateWindowCount = 0;
    std::uint64_t m_u64QueueOverflowWindowCount = 0;
    std::uint32_t m_u32DetailedInvalidWindowCount = 0;
    bool m_bConfigured = false;
    bool m_bRunning = false;
    bool m_bPaused = false;
    bool m_bShutdown = false;
};

AuthenticationReceiverRuntime::AuthenticationReceiverRuntime(
    ResultHandler fnResultHandler,
    ObservationHandler fnObservationHandler,
    MetricHandler fnMetricHandler
)
    : m_ptrImpl(std::make_unique<Impl>(
          std::move(fnResultHandler),
          std::move(fnObservationHandler),
          std::move(fnMetricHandler)
      ))
{
}

AuthenticationReceiverRuntime::~AuthenticationReceiverRuntime() = default;

void AuthenticationReceiverRuntime::configure(
    std::vector<ReceiverAuthenticationContext> vecContexts
)
{
    m_ptrImpl->configure(std::move(vecContexts));
}

void AuthenticationReceiverRuntime::start(
    std::string strRoundId,
    std::uint64_t u64StartTimestampMilliseconds,
    std::uint32_t u32ClockToleranceMilliseconds
)
{
    m_ptrImpl->start(
        std::move(strRoundId),
        u64StartTimestampMilliseconds,
        u32ClockToleranceMilliseconds
    );
}

void AuthenticationReceiverRuntime::requestPause(
    const std::string& strRoundId,
    std::uint32_t u32PauseAfterInterval,
    std::uint64_t u64PauseTimestampMilliseconds
)
{
    m_ptrImpl->requestPause(
        strRoundId,
        u32PauseAfterInterval,
        u64PauseTimestampMilliseconds
    );
}

void AuthenticationReceiverRuntime::resume(
    const std::string& strRoundId,
    std::uint32_t u32ResumeInterval,
    std::uint64_t u64ResumeTimestampMilliseconds
)
{
    m_ptrImpl->resume(
        strRoundId,
        u32ResumeInterval,
        u64ResumeTimestampMilliseconds
    );
}

void AuthenticationReceiverRuntime::stop() noexcept
{
    m_ptrImpl->stop(true);
}

void AuthenticationReceiverRuntime::applyAttackSourceMapping(
    const protocol::AttackSourceMappingControlDetails& detMapping
)
{
    m_ptrImpl->applyAttackSourceMapping(detMapping);
}

void AuthenticationReceiverRuntime::clearAttackSourceMappings() noexcept
{
    m_ptrImpl->clearAttackSourceMappings();
}

bool AuthenticationReceiverRuntime::bEnqueueDatagram(
    const std::string& strSourceIpAddress,
    const protocol::ByteBuffer& vecDatagram,
    std::uint64_t u64ReceiveTimestampMilliseconds
)
{
    return m_ptrImpl->bEnqueueDatagram(
        strSourceIpAddress,
        vecDatagram,
        u64ReceiveTimestampMilliseconds
    );
}

bool AuthenticationReceiverRuntime::bIsConfigured() const
{
    return m_ptrImpl->bIsConfigured();
}

bool AuthenticationReceiverRuntime::bIsRunning() const
{
    return m_ptrImpl->bIsRunning();
}

bool AuthenticationReceiverRuntime::bIsPaused() const
{
    return m_ptrImpl->bIsPaused();
}

std::size_t AuthenticationReceiverRuntime::nContextCount() const
{
    return m_ptrImpl->nContextCount();
}

std::size_t AuthenticationReceiverRuntime::nDroppedQueueDatagramCount() const
{
    return m_ptrImpl->nDroppedQueueDatagramCount();
}

ReceiverAuthenticationContextLookupResult
AuthenticationReceiverRuntime::resFindContext(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    return m_ptrImpl->resFindContext(strSourceIpAddress, u64ChainId);
}
}

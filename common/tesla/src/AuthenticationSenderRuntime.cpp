#include "tesla/core/AuthenticationSenderRuntime.h"

#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/core/ImprovedTeslaDetails.h"
#include "tesla/core/ImprovedTeslaStrategy.h"
#include "tesla/core/NativeTeslaDetails.h"
#include "tesla/core/NativeTeslaStrategy.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
namespace
{
using SteadyClock = std::chrono::steady_clock;
using SystemClock = std::chrono::system_clock;

constexpr std::uint32_t MAX_STAGE6_PACKET_COUNT = 200000;
constexpr std::chrono::microseconds DEFAULT_SEND_BUDGET(250);

protocol::BinaryBlock arrMapDigest(const crypto::Digest& digValue)
{
    protocol::BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

protocol::UdpAuthenticationMode modeMap(TeslaAuthenticationMode modeAuthentication)
{
    return modeAuthentication == TeslaAuthenticationMode::Native
        ? protocol::UdpAuthenticationMode::Native
        : protocol::UdpAuthenticationMode::Improved;
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

AuthenticationPacketInput::Message arrMapMessage(
    const workload::TextPayload::Message& arrMessage
)
{
    AuthenticationPacketInput::Message arrResult{};
    std::copy(arrMessage.begin(), arrMessage.end(), arrResult.begin());
    return arrResult;
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            SystemClock::now().time_since_epoch()
        ).count()
    );
}
}

class AuthenticationSenderRuntime::Impl final
{
public:
    struct IntervalDatagrams final
    {
        std::vector<protocol::ByteBuffer> vecDatagrams;
        std::uint32_t                     u32DataPacketCount = 0;
    };

    Impl(
        DatagramSender fnDatagramSender,
        ResultHandler fnResultHandler
    )
        : m_fnDatagramSender(std::move(fnDatagramSender)),
          m_fnResultHandler(std::move(fnResultHandler))
    {
        if (!m_fnDatagramSender || !m_fnResultHandler)
        {
            throw std::invalid_argument(
                "Sender runtime requires datagram and result callbacks"
            );
        }
    }

    ~Impl()
    {
        stop(false);
    }

    void configure(
        SenderAuthenticationContext ctxSender,
        workload::TextWorkload wrkText
    )
    {
        stop(false);

        const AuthenticationRoundParameters& prmRound =
            ctxSender.matMaterial().prmRoundParameters();
        if (prmRound.modePayload() != AuthenticationPayloadMode::Text)
        {
            throw std::invalid_argument("Stage6 sender runtime only accepts text payloads");
        }

        if (wrkText.u32PacketCount() != prmRound.u32TotalPacketCount())
        {
            throw std::invalid_argument(
                "Text workload packet count does not match sender configuration"
            );
        }

        if (wrkText.u32PacketCount() > MAX_STAGE6_PACKET_COUNT)
        {
            throw std::invalid_argument("Stage6 text packet count exceeds the bounded runtime");
        }

        std::vector<IntervalDatagrams> vecIntervals;
        std::chrono::nanoseconds durWorstGeneration(0);
        buildDatagrams(
            ctxSender,
            wrkText,
            vecIntervals,
            durWorstGeneration
        );
        validateScheduling(prmRound, vecIntervals, durWorstGeneration);

        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_optSenderContext = std::move(ctxSender);
        m_optTextWorkload = std::move(wrkText);
        m_vecIntervals = std::move(vecIntervals);
        m_durWorstGeneration = durWorstGeneration;
        m_bConfigured = true;
        m_bRunning = false;
        m_bPaused = false;
    }

    void start(
        std::string strRoundId,
        std::uint64_t u64StartTimestampMilliseconds
    )
    {
        stop(false);

        {
            std::lock_guard<std::mutex> lckState(m_mtxState);
            if (!m_bConfigured
                || !m_optSenderContext.has_value()
                || !m_optTextWorkload.has_value())
            {
                throw std::logic_error("Sender runtime is not fully configured");
            }

            if (strRoundId.empty())
            {
                throw std::invalid_argument("Sender round ID must not be empty");
            }

            if (u64StartTimestampMilliseconds <= u64NowMilliseconds() + 100)
            {
                throw std::invalid_argument(
                    "Sender round start timestamp must leave preparation time"
                );
            }

            m_strRoundId = std::move(strRoundId);
            m_u64StartTimestampMilliseconds = u64StartTimestampMilliseconds;
            m_bStopRequested = false;
            m_bRunning = true;
            m_bPaused = false;
            m_optPauseAfterInterval.reset();
            m_optResumeInterval.reset();
            m_u32CurrentInterval = 0;
            m_u32SentDataPacketCount = 0;
        }

        m_thrWorker = std::thread([this]()
        {
            run();
        });
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
            || u32PauseAfterInterval < m_u32CurrentInterval
            || u64PauseTimestampMilliseconds <= u64NowMilliseconds())
        {
            throw std::invalid_argument("Sender pause boundary is already invalid");
        }

        if (u32PauseAfterInterval >= m_vecIntervals.size())
        {
            throw std::invalid_argument("Sender pause boundary is outside the round");
        }

        m_optPauseAfterInterval = u32PauseAfterInterval;
        m_u64PauseTimestampMilliseconds = u64PauseTimestampMilliseconds;
        m_cndState.notify_all();
    }

    void resume(
        const std::string& strRoundId,
        std::uint32_t u32ResumeInterval,
        std::uint64_t u64ResumeTimestampMilliseconds
    )
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        validateActiveRound(strRoundId);

        if (!m_optPauseAfterInterval.has_value()
            || u32ResumeInterval != m_optPauseAfterInterval.value() + 1U
            || u64ResumeTimestampMilliseconds <= u64NowMilliseconds() + 100
            || u64ResumeTimestampMilliseconds
                <= m_u64PauseTimestampMilliseconds)
        {
            throw std::invalid_argument("Sender resume schedule does not follow the pause");
        }

        m_optResumeInterval = u32ResumeInterval;
        m_u64ResumeTimestampMilliseconds = u64ResumeTimestampMilliseconds;
        m_cndState.notify_all();
    }

    void stop(bool bReportResult) noexcept
    {
        bool bWasRunning = false;

        {
            std::lock_guard<std::mutex> lckState(m_mtxState);
            bWasRunning = m_bRunning;
            m_bStopRequested = true;
            m_cndState.notify_all();
        }

        if (m_thrWorker.joinable())
        {
            m_thrWorker.join();
        }

        if (bReportResult && bWasRunning)
        {
            emitResult(AuthenticationRuntimeResultStatus::Stopped, "Round stopped");
        }

        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_bRunning = false;
        m_bPaused = false;
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

private:
    void buildDatagrams(
        const SenderAuthenticationContext& ctxSender,
        const workload::TextWorkload& wrkText,
        std::vector<IntervalDatagrams>& vecIntervals,
        std::chrono::nanoseconds& durWorstGeneration
    ) const
    {
        const AuthenticationRoundParameters& prmRound =
            ctxSender.matMaterial().prmRoundParameters();
        const std::uint32_t u32DataIntervalCount = static_cast<std::uint32_t>(
            prmRound.nDataIntervalCount()
        );
        const std::uint32_t u32TotalLogicalIntervals =
            u32DataIntervalCount + prmRound.u32DisclosureDelay();
        vecIntervals.resize(static_cast<std::size_t>(u32TotalLogicalIntervals) + 1U);

        const crypto::OpenSslCryptoProvider crpProvider(
            prmRound.algCryptoAlgorithm()
        );
        const protocol::UdpAuthenticationPacketContext ctxPacket =
            ctxCreatePacketContext(prmRound);

        for (std::uint32_t u32IntervalIndex = 1;
             u32IntervalIndex <= u32DataIntervalCount;
             ++u32IntervalIndex)
        {
            const SteadyClock::time_point tpGenerationStart = SteadyClock::now();
            buildDataInterval(
                ctxSender,
                wrkText,
                crpProvider,
                ctxPacket,
                u32IntervalIndex,
                vecIntervals[u32IntervalIndex]
            );
            durWorstGeneration = std::max(
                durWorstGeneration,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    SteadyClock::now() - tpGenerationStart
                )
            );
        }

        // 数据结束后每个逻辑间隔只发送一个披露尾包，直到KI完成披露。
        for (std::uint32_t u32LogicalInterval = u32DataIntervalCount + 1U;
             u32LogicalInterval <= u32TotalLogicalIntervals;
             ++u32LogicalInterval)
        {
            const std::uint32_t u32DisclosedKeyIndex =
                u32LogicalInterval - prmRound.u32DisclosureDelay();
            IntervalDatagrams& intDatagrams = vecIntervals[u32LogicalInterval];
            intDatagrams.vecDatagrams.push_back(
                protocol::UdpAuthenticationPacketCodec::vecEncode(
                    protocol::UdpAuthenticationPacket(
                        protocol::UdpDisclosurePacket(
                            ctxSender.matMaterial().u64ChainId(),
                            u32LogicalInterval,
                            arrMapDigest(
                                ctxSender.keyChain().digDataKey(
                                    u32DisclosedKeyIndex
                                )
                            )
                        )
                    ),
                    ctxPacket
                )
            );
        }
    }

    void buildDataInterval(
        const SenderAuthenticationContext& ctxSender,
        const workload::TextWorkload& wrkText,
        const crypto::CryptoProvider& crpProvider,
        const protocol::UdpAuthenticationPacketContext& ctxPacket,
        std::uint32_t u32IntervalIndex,
        IntervalDatagrams& intDatagrams
    ) const
    {
        const AuthenticationRoundParameters& prmRound =
            ctxSender.matMaterial().prmRoundParameters();
        const std::uint32_t u32FirstPacketIndex =
            (u32IntervalIndex - 1U) * prmRound.u32PacketsPerInterval() + 1U;
        const std::uint32_t u32LastPacketIndex = std::min(
            prmRound.u32TotalPacketCount(),
            u32IntervalIndex * prmRound.u32PacketsPerInterval()
        );
        intDatagrams.u32DataPacketCount =
            u32LastPacketIndex - u32FirstPacketIndex + 1U;
        intDatagrams.vecDatagrams.reserve(intDatagrams.u32DataPacketCount);

        if (prmRound.modeAuthentication() == TeslaAuthenticationMode::Native)
        {
            buildNativeInterval(
                ctxSender,
                wrkText,
                crpProvider,
                ctxPacket,
                u32IntervalIndex,
                u32FirstPacketIndex,
                u32LastPacketIndex,
                intDatagrams
            );
            return;
        }

        buildImprovedInterval(
            ctxSender,
            wrkText,
            crpProvider,
            ctxPacket,
            u32IntervalIndex,
            u32FirstPacketIndex,
            u32LastPacketIndex,
            intDatagrams
        );
    }

    AuthenticationGroupInput grpCreate(
        const SenderAuthenticationContext& ctxSender,
        const workload::TextWorkload& wrkText,
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
            vecSlots.emplace_back(AuthenticationPacketInput(
                ctxSender.matMaterial().strSenderId(),
                ctxSender.matMaterial().u64ChainId(),
                u32IntervalIndex,
                u32PacketIndex,
                arrMapMessage(wrkText.arrMessage(u32PacketIndex))
            ));
        }

        return AuthenticationGroupInput(
            ctxSender.matMaterial().strSenderId(),
            ctxSender.matMaterial().u64ChainId(),
            u32IntervalIndex,
            u32GroupIndex,
            u32FirstPacketIndex,
            std::move(vecSlots)
        );
    }

    std::optional<protocol::BinaryBlock> optDisclosureForPacket(
        const SenderAuthenticationContext& ctxSender,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32PacketIndex,
        std::uint32_t u32FirstPacketIndex
    ) const
    {
        const AuthenticationRoundParameters& prmRound =
            ctxSender.matMaterial().prmRoundParameters();
        if (u32PacketIndex != u32FirstPacketIndex
            || u32IntervalIndex <= prmRound.u32DisclosureDelay())
        {
            return std::nullopt;
        }

        return arrMapDigest(ctxSender.keyChain().digDataKey(
            u32IntervalIndex - prmRound.u32DisclosureDelay()
        ));
    }

    void buildNativeInterval(
        const SenderAuthenticationContext& ctxSender,
        const workload::TextWorkload& wrkText,
        const crypto::CryptoProvider& crpProvider,
        const protocol::UdpAuthenticationPacketContext& ctxPacket,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32FirstPacketIndex,
        std::uint32_t u32LastPacketIndex,
        IntervalDatagrams& intDatagrams
    ) const
    {
        const AuthenticationGroupInput grpInterval = grpCreate(
            ctxSender,
            wrkText,
            u32IntervalIndex,
            u32IntervalIndex,
            u32FirstPacketIndex,
            u32LastPacketIndex
        );
        const NativeTeslaStrategy stgStrategy(crpProvider);
        const TeslaAuthenticationDetails varAuthentication =
            stgStrategy.authCreateAuthenticationDetails(
                grpInterval,
                ctxSender.keyChain().digDataKey(u32IntervalIndex)
            );
        const NativeAuthenticationDetails& detAuthentication =
            std::get<NativeAuthenticationDetails>(
                varAuthentication
            );

        for (std::uint32_t u32PacketIndex = u32FirstPacketIndex;
             u32PacketIndex <= u32LastPacketIndex;
             ++u32PacketIndex)
        {
            const std::size_t nPosition = u32PacketIndex - u32FirstPacketIndex;
            intDatagrams.vecDatagrams.push_back(
                protocol::UdpAuthenticationPacketCodec::vecEncode(
                    protocol::UdpAuthenticationPacket(protocol::UdpDataPacket(
                        ctxSender.matMaterial().u64ChainId(),
                        u32IntervalIndex,
                        u32PacketIndex,
                        wrkText.arrMessage(u32PacketIndex),
                        optDisclosureForPacket(
                            ctxSender,
                            u32IntervalIndex,
                            u32PacketIndex,
                            u32FirstPacketIndex
                        ),
                        protocol::NativeUdpAuthenticationDetails(arrMapDigest(
                            detAuthentication.vecPacketMacs()[nPosition].value()
                        ))
                    )),
                    ctxPacket
                )
            );
        }
    }

    void buildImprovedInterval(
        const SenderAuthenticationContext& ctxSender,
        const workload::TextWorkload& wrkText,
        const crypto::CryptoProvider& crpProvider,
        const protocol::UdpAuthenticationPacketContext& ctxPacket,
        std::uint32_t u32IntervalIndex,
        std::uint32_t u32FirstPacketIndex,
        std::uint32_t u32LastPacketIndex,
        IntervalDatagrams& intDatagrams
    ) const
    {
        const ImprovedTeslaParameters& prmImproved =
            ctxSender.matMaterial().prmRoundParameters()
                .optImprovedParameters().value();
        const ImprovedTeslaStrategy stgStrategy(
            crpProvider,
            prmImproved.u32GroupSize(),
            prmImproved.u32DetectionThreshold()
        );

        std::uint32_t u32GroupFirstPacket = u32FirstPacketIndex;
        while (u32GroupFirstPacket <= u32LastPacketIndex)
        {
            const std::uint32_t u32GroupLastPacket = std::min(
                u32LastPacketIndex,
                u32GroupFirstPacket + prmImproved.u32GroupSize() - 1U
            );
            const std::uint32_t u32GroupIndex =
                ((u32GroupFirstPacket - 1U) / prmImproved.u32GroupSize()) + 1U;
            const AuthenticationGroupInput grpInput = grpCreate(
                ctxSender,
                wrkText,
                u32IntervalIndex,
                u32GroupIndex,
                u32GroupFirstPacket,
                u32GroupLastPacket
            );
            const TeslaAuthenticationDetails varAuthentication =
                stgStrategy.authCreateAuthenticationDetails(
                    grpInput,
                    ctxSender.keyChain().digDataKey(u32IntervalIndex)
                );
            const ImprovedAuthenticationDetails& detAuthentication =
                std::get<ImprovedAuthenticationDetails>(
                    varAuthentication
                );

            for (std::uint32_t u32PacketIndex = u32GroupFirstPacket;
                 u32PacketIndex <= u32GroupLastPacket;
                 ++u32PacketIndex)
            {
                std::optional<protocol::ImprovedUdpGroupAuthenticationDetails>
                    optGroupDetails;
                if (u32PacketIndex == u32GroupLastPacket)
                {
                    std::vector<protocol::BinaryBlock> vecTau;
                    vecTau.reserve(detAuthentication.vecSamdTau().size());
                    for (const crypto::Digest& digTau
                        : detAuthentication.vecSamdTau())
                    {
                        vecTau.push_back(arrMapDigest(digTau));
                    }

                    optGroupDetails.emplace(
                        std::move(vecTau),
                        arrMapDigest(detAuthentication.optFastGroupTag().value())
                    );
                }

                intDatagrams.vecDatagrams.push_back(
                    protocol::UdpAuthenticationPacketCodec::vecEncode(
                        protocol::UdpAuthenticationPacket(protocol::UdpDataPacket(
                            ctxSender.matMaterial().u64ChainId(),
                            u32IntervalIndex,
                            u32PacketIndex,
                            wrkText.arrMessage(u32PacketIndex),
                            optDisclosureForPacket(
                                ctxSender,
                                u32IntervalIndex,
                                u32PacketIndex,
                                u32FirstPacketIndex
                            ),
                            protocol::ImprovedUdpAuthenticationDetails(
                                std::move(optGroupDetails)
                            )
                        )),
                        ctxPacket
                    )
                );
            }

            u32GroupFirstPacket = u32GroupLastPacket + 1U;
        }
    }

    void validateScheduling(
        const AuthenticationRoundParameters& prmRound,
        const std::vector<IntervalDatagrams>& vecIntervals,
        std::chrono::nanoseconds durWorstGeneration
    ) const
    {
        const std::chrono::nanoseconds durInterval =
            std::chrono::milliseconds(prmRound.u32IntervalMilliseconds());
        const std::chrono::nanoseconds durSafetyMargin = std::max(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::milliseconds(1)
            ),
            durInterval / 10
        );
        std::size_t nWorstDatagramCount = 0;

        for (std::size_t nIndex = 1; nIndex < vecIntervals.size(); ++nIndex)
        {
            nWorstDatagramCount = std::max(
                nWorstDatagramCount,
                vecIntervals[nIndex].vecDatagrams.size()
            );
        }

        const std::chrono::nanoseconds durSendBudget =
            DEFAULT_SEND_BUDGET * nWorstDatagramCount;
        if (durWorstGeneration + durSendBudget + durSafetyMargin >= durInterval)
        {
            throw std::invalid_argument(
                "Authentication schedule cannot fit measured generation, send budget and safety margin"
            );
        }
    }

    void validateActiveRound(const std::string& strRoundId) const
    {
        if (!m_bRunning || m_strRoundId != strRoundId)
        {
            throw std::logic_error("Sender round is not active");
        }
    }

    bool bWaitUntil(const SteadyClock::time_point& tpDeadline)
    {
        std::unique_lock<std::mutex> lckState(m_mtxState);
        m_cndState.wait_until(
            lckState,
            tpDeadline,
            [this]()
            {
                return m_bStopRequested;
            }
        );
        return !m_bStopRequested;
    }

    bool bWaitForWallTimestamp(std::uint64_t u64TimestampMilliseconds)
    {
        const SystemClock::time_point tpTarget{
            std::chrono::milliseconds(u64TimestampMilliseconds)
        };
        std::unique_lock<std::mutex> lckState(m_mtxState);
        m_cndState.wait_until(
            lckState,
            tpTarget,
            [this]()
            {
                return m_bStopRequested;
            }
        );
        return !m_bStopRequested;
    }

    void run()
    {
        if (!bWaitForWallTimestamp(m_u64StartTimestampMilliseconds))
        {
            finishWithoutDuplicateResult();
            return;
        }

        const AuthenticationRoundParameters& prmRound =
            m_optSenderContext->matMaterial().prmRoundParameters();
        const std::chrono::nanoseconds durInterval =
            std::chrono::milliseconds(prmRound.u32IntervalMilliseconds());
        SteadyClock::time_point tpSegmentStart = SteadyClock::now();
        std::uint32_t u32SegmentFirstInterval = 1;
        bool bOverrun = false;

        for (std::uint32_t u32IntervalIndex = 1;
             u32IntervalIndex < m_vecIntervals.size();
             ++u32IntervalIndex)
        {
            {
                std::lock_guard<std::mutex> lckState(m_mtxState);
                if (m_bStopRequested)
                {
                    break;
                }

                m_u32CurrentInterval = u32IntervalIndex;
            }

            const SteadyClock::time_point tpIntervalStart =
                tpSegmentStart
                + durInterval * (u32IntervalIndex - u32SegmentFirstInterval);
            const SteadyClock::time_point tpIntervalEnd =
                tpIntervalStart + durInterval;
            if (!bWaitUntil(tpIntervalStart))
            {
                break;
            }

            const IntervalDatagrams& intDatagrams = m_vecIntervals[u32IntervalIndex];
            const std::chrono::nanoseconds durPacketGap =
                intDatagrams.vecDatagrams.size() > 1
                ? durInterval / static_cast<std::chrono::nanoseconds::rep>(
                    intDatagrams.vecDatagrams.size()
                )
                : std::chrono::nanoseconds(0);

            for (std::size_t nDatagramIndex = 0;
                 nDatagramIndex < intDatagrams.vecDatagrams.size();
                 ++nDatagramIndex)
            {
                const SteadyClock::time_point tpSendTarget =
                    tpIntervalStart + durPacketGap * nDatagramIndex;
                if (!bWaitUntil(tpSendTarget))
                {
                    break;
                }

                const SteadyClock::time_point tpSendStart = SteadyClock::now();
                const bool bSent = m_fnDatagramSender(
                    intDatagrams.vecDatagrams[nDatagramIndex]
                );
                const std::chrono::nanoseconds durSend =
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        SteadyClock::now() - tpSendStart
                    );
                m_durWorstObservedSend = std::max(
                    m_durWorstObservedSend,
                    durSend
                );

                if (!bSent || SteadyClock::now() >= tpIntervalEnd)
                {
                    bOverrun = true;
                    break;
                }

                if (nDatagramIndex < intDatagrams.u32DataPacketCount)
                {
                    ++m_u32SentDataPacketCount;
                }
            }

            if (bOverrun || bStopRequested())
            {
                break;
            }

            std::unique_lock<std::mutex> lckState(m_mtxState);
            if (m_optPauseAfterInterval.has_value()
                && u32IntervalIndex == m_optPauseAfterInterval.value())
            {
                const std::uint64_t u64PauseTimestamp =
                    m_u64PauseTimestampMilliseconds;
                lckState.unlock();

                // Pause becomes visible only at the manager-issued interval
                // boundary, so all nodes share one wall-clock time base.
                if (!bWaitForWallTimestamp(u64PauseTimestamp))
                {
                    break;
                }

                lckState.lock();
                m_bPaused = true;
                m_cndState.wait(
                    lckState,
                    [this]()
                    {
                        return m_bStopRequested || m_optResumeInterval.has_value();
                    }
                );

                if (m_bStopRequested)
                {
                    break;
                }

                const std::uint32_t u32ResumeInterval =
                    m_optResumeInterval.value();
                const std::uint64_t u64ResumeTimestamp =
                    m_u64ResumeTimestampMilliseconds;
                m_bPaused = false;
                lckState.unlock();

                if (!bWaitForWallTimestamp(u64ResumeTimestamp))
                {
                    break;
                }

                tpSegmentStart = SteadyClock::now();
                u32SegmentFirstInterval = u32ResumeInterval;
                lckState.lock();
                m_optPauseAfterInterval.reset();
                m_optResumeInterval.reset();
            }
        }

        if (bOverrun)
        {
            emitResult(
                AuthenticationRuntimeResultStatus::InvalidSchedulingOverrun,
                "Authentication interval exceeded its runtime deadline"
            );
        }
        else if (!bStopRequested())
        {
            emitResult(
                AuthenticationRuntimeResultStatus::Completed,
                "Sender completed all data and disclosure intervals"
            );
        }

        finishWithoutDuplicateResult();
    }

    bool bStopRequested() const
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        return m_bStopRequested;
    }

    void finishWithoutDuplicateResult()
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_bRunning = false;
        m_bPaused = false;
    }

    void emitResult(
        AuthenticationRuntimeResultStatus statusResult,
        const std::string& strMessage
    ) noexcept
    {
        try
        {
            std::string   strRoundId;
            std::string   strSenderId;
            std::uint64_t u64ChainId = 0;
            std::uint32_t u32ExpectedPacketCount = 0;
            std::uint32_t u32SentPacketCount = 0;

            {
                std::lock_guard<std::mutex> lckState(m_mtxState);
                if (!m_optSenderContext.has_value())
                {
                    return;
                }

                strRoundId = m_strRoundId;
                strSenderId = m_optSenderContext->matMaterial().strSenderId();
                u64ChainId = m_optSenderContext->matMaterial().u64ChainId();
                u32ExpectedPacketCount = m_optSenderContext->matMaterial()
                    .prmRoundParameters().u32TotalPacketCount();
                u32SentPacketCount = std::min(
                    m_u32SentDataPacketCount,
                    u32ExpectedPacketCount
                );
            }

            m_fnResultHandler(AuthenticationRuntimeResult(
                std::move(strRoundId),
                std::move(strSenderId),
                u64ChainId,
                statusResult,
                u32ExpectedPacketCount,
                u32SentPacketCount,
                statusResult == AuthenticationRuntimeResultStatus::Completed
                    ? u32SentPacketCount
                    : 0,
                0,
                u32ExpectedPacketCount - u32SentPacketCount,
                "",
                strMessage
            ));
        }
        catch (...)
        {
            // 结果回调不得使工作线程穿透异常并触发std::terminate。
        }
    }

    DatagramSender m_fnDatagramSender;
    ResultHandler  m_fnResultHandler;

    mutable std::mutex              m_mtxState;
    std::condition_variable         m_cndState;
    std::thread                     m_thrWorker;
    std::optional<SenderAuthenticationContext> m_optSenderContext;
    std::optional<workload::TextWorkload>      m_optTextWorkload;
    std::vector<IntervalDatagrams>  m_vecIntervals;
    std::string                     m_strRoundId;
    std::uint64_t                   m_u64StartTimestampMilliseconds = 0;
    std::uint64_t                   m_u64PauseTimestampMilliseconds = 0;
    std::uint64_t                   m_u64ResumeTimestampMilliseconds = 0;
    std::optional<std::uint32_t>    m_optPauseAfterInterval;
    std::optional<std::uint32_t>    m_optResumeInterval;
    std::uint32_t                   m_u32CurrentInterval = 0;
    std::uint32_t                   m_u32SentDataPacketCount = 0;
    std::chrono::nanoseconds        m_durWorstGeneration{0};
    std::chrono::nanoseconds        m_durWorstObservedSend{0};
    bool                            m_bConfigured = false;
    bool                            m_bRunning = false;
    bool                            m_bPaused = false;
    bool                            m_bStopRequested = false;
};

AuthenticationSenderRuntime::AuthenticationSenderRuntime(
    DatagramSender fnDatagramSender,
    ResultHandler fnResultHandler
)
    : m_ptrImpl(std::make_unique<Impl>(
          std::move(fnDatagramSender),
          std::move(fnResultHandler)
      ))
{
}

AuthenticationSenderRuntime::~AuthenticationSenderRuntime() = default;

void AuthenticationSenderRuntime::configure(
    SenderAuthenticationContext ctxSender,
    workload::TextWorkload wrkText
)
{
    m_ptrImpl->configure(std::move(ctxSender), std::move(wrkText));
}

void AuthenticationSenderRuntime::start(
    std::string strRoundId,
    std::uint64_t u64StartTimestampMilliseconds
)
{
    m_ptrImpl->start(
        std::move(strRoundId),
        u64StartTimestampMilliseconds
    );
}

void AuthenticationSenderRuntime::requestPause(
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

void AuthenticationSenderRuntime::resume(
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

void AuthenticationSenderRuntime::stop() noexcept
{
    m_ptrImpl->stop(true);
}

bool AuthenticationSenderRuntime::bIsConfigured() const
{
    return m_ptrImpl->bIsConfigured();
}

bool AuthenticationSenderRuntime::bIsRunning() const
{
    return m_ptrImpl->bIsRunning();
}

bool AuthenticationSenderRuntime::bIsPaused() const
{
    return m_ptrImpl->bIsPaused();
}
}

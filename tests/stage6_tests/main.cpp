#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationNodeRuntime.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/protocol/AuthenticationControl.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{
using namespace tesla;

protocol::BinaryBlock arrBlock(const crypto::ByteBuffer& vecBytes)
{
    if (vecBytes.size() != protocol::BINARY_BLOCK_SIZE)
    {
        throw std::runtime_error("Stage 6 test block has an invalid size");
    }

    protocol::BinaryBlock arrResult{};
    std::copy(vecBytes.begin(), vecBytes.end(), arrResult.begin());
    return arrResult;
}

protocol::BinaryBlock arrBlock(const crypto::Digest& digValue)
{
    protocol::BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

protocol::AuthenticationRoundControlParameters prmControl(
    const core::AuthenticationRoundParameters& prmRound
)
{
    std::optional<protocol::ImprovedTeslaControlParameters>
        optImprovedParameters;
    if (prmRound.optImprovedParameters().has_value())
    {
        optImprovedParameters.emplace(
            prmRound.optImprovedParameters()->u32GroupSize(),
            prmRound.optImprovedParameters()->u32DetectionThreshold()
        );
    }

    return protocol::AuthenticationRoundControlParameters(
        protocol::AuthenticationCryptoAlgorithm::Sha256,
        prmRound.modeAuthentication() == core::TeslaAuthenticationMode::Native
            ? protocol::UdpAuthenticationMode::Native
            : protocol::UdpAuthenticationMode::Improved,
        prmRound.u32TotalPacketCount(),
        prmRound.u32PacketsPerInterval(),
        prmRound.u32DisclosureDelay(),
        prmRound.u32IntervalMilliseconds(),
        prmRound.u64StartTimestampMilliseconds(),
        prmRound.u32ChainLength(),
        std::move(optImprovedParameters),
        protocol::AuthenticationPayloadMode::Text
    );
}

bool bAccepted(
    const protocol::NodeControlMessage& msgMessage,
    protocol::AuthenticationConfigTarget targetConfig
)
{
    if (msgMessage.typeMessage()
        != protocol::NodeControlMessageType::
            AuthenticationConfigAcknowledgement)
    {
        return false;
    }

    const auto& detAcknowledgement = std::get<
        protocol::AuthenticationConfigAcknowledgementControlDetails
    >(msgMessage.varDetails());
    return detAcknowledgement.bAccepted()
        && detAcknowledgement.targetConfig() == targetConfig;
}

bool bRoundAccepted(const protocol::NodeControlMessage& msgMessage)
{
    if (msgMessage.typeMessage()
        != protocol::NodeControlMessageType::RoundCommandAcknowledgement)
    {
        return false;
    }

    const auto& detAcknowledgement = std::get<
        protocol::AuthenticationRoundAcknowledgementControlDetails
    >(msgMessage.varDetails());
    if (!detAcknowledgement.bAccepted())
    {
        std::cerr << "Round command rejected: "
                  << detAcknowledgement.strErrorCode() << " / "
                  << detAcknowledgement.strMessage() << std::endl;
    }
    return detAcknowledgement.bAccepted();
}

class ResultCollector final
{
public:
    void add(const protocol::NodeControlMessage& msgMessage)
    {
        if (msgMessage.typeMessage()
            != protocol::NodeControlMessageType::RoundResult)
        {
            return;
        }

        std::lock_guard<std::mutex> lckResults(m_mtxResults);
        m_vecResults.push_back(std::get<
            protocol::AuthenticationRoundResultControlDetails
        >(msgMessage.varDetails()));
        m_cndResults.notify_all();
    }

    bool bWaitForCount(
        std::size_t nExpectedCount,
        std::chrono::milliseconds durTimeout
    )
    {
        std::unique_lock<std::mutex> lckResults(m_mtxResults);
        return m_cndResults.wait_for(
            lckResults,
            durTimeout,
            [this, nExpectedCount]()
            {
                return m_vecResults.size() >= nExpectedCount;
            }
        );
    }

    std::vector<protocol::AuthenticationRoundResultControlDetails>
        vecResults() const
    {
        std::lock_guard<std::mutex> lckResults(m_mtxResults);
        return m_vecResults;
    }

private:
    mutable std::mutex m_mtxResults;
    std::condition_variable m_cndResults;
    std::vector<protocol::AuthenticationRoundResultControlDetails>
        m_vecResults;
};

bool bConfigureSender(
    core::AuthenticationNodeRuntime& runSender,
    const core::SenderAuthenticationMaterial& matMaterial,
    const std::string& strText
)
{
    const protocol::NodeControlMessage msgSenderResponse =
        runSender.msgHandleControl(
            protocol::TcpClientRole::Manager,
            protocol::NodeControlMessage(
                protocol::SenderAuthenticationConfigControlDetails(
                    "stage6-sender-config",
                    matMaterial.strSenderId(),
                    matMaterial.u64ChainId(),
                    arrBlock(matMaterial.vecChainSeed()),
                    arrBlock(matMaterial.digCommitmentKey()),
                    prmControl(matMaterial.prmRoundParameters())
                )
            )
        );
    const protocol::NodeControlMessage msgPayloadResponse =
        runSender.msgHandleControl(
            protocol::TcpClientRole::Manager,
            protocol::NodeControlMessage(
                protocol::TextPayloadControlDetails(
                    "stage6-text-payload",
                    matMaterial.u64ChainId(),
                    strText
                )
            )
        );
    return bAccepted(
        msgSenderResponse,
        protocol::AuthenticationConfigTarget::Sender
    ) && bAccepted(
        msgPayloadResponse,
        protocol::AuthenticationConfigTarget::TextPayload
    );
}

bool bConfigureReceiver(
    core::AuthenticationNodeRuntime& runReceiver,
    const core::SenderAuthenticationMaterial& matMaterial,
    const std::string& strSenderIpAddress
)
{
    const protocol::NodeControlMessage msgResponse =
        runReceiver.msgHandleControl(
            protocol::TcpClientRole::Manager,
            protocol::NodeControlMessage(
                protocol::ReceiverAuthenticationContextsControlDetails(
                    "stage6-receiver-config",
                    {
                        protocol::
                            ReceiverAuthenticationContextControlDetails(
                                matMaterial.strSenderId(),
                                strSenderIpAddress,
                                matMaterial.u64ChainId(),
                                arrBlock(matMaterial.digCommitmentKey()),
                                prmControl(
                                    matMaterial.prmRoundParameters()
                                ),
                                protocol::TextReceiverPayloadControlDetails(
                                    matMaterial.prmRoundParameters()
                                        .u32TotalPacketCount()
                                )
                            )
                    }
                )
            )
        );
    return bAccepted(
        msgResponse,
        protocol::AuthenticationConfigTarget::Receiver
    );
}

protocol::NodeControlMessage msgRoundCommand(
    const std::string& strRequestId,
    const std::string& strRoundId,
    protocol::AuthenticationRoundCommand cmdCommand,
    std::uint64_t u64TimestampMilliseconds,
    std::uint32_t u32LogicalIntervalIndex
)
{
    return protocol::NodeControlMessage(
        protocol::AuthenticationRoundCommandControlDetails(
            strRequestId,
            strRoundId,
            cmdCommand,
            u64TimestampMilliseconds,
            u32LogicalIntervalIndex
        )
    );
}

bool bRunEndToEnd(
    core::TeslaAuthenticationMode modeAuthentication,
    bool bExercisePauseResume
)
{
    const std::uint32_t u32PacketCount = bExercisePauseResume ? 12U : 8U;
    const std::uint32_t u32PacketsPerInterval = 4;
    const std::uint32_t u32IntervalMilliseconds = 120;
    std::optional<core::ImprovedTeslaParameters> optImprovedParameters;
    if (modeAuthentication == core::TeslaAuthenticationMode::Improved)
    {
        optImprovedParameters.emplace(2, 1);
    }

    const core::AuthenticationRoundParameters prmRound(
        crypto::CryptoAlgorithm::Sha256,
        modeAuthentication,
        u32PacketCount,
        u32PacketsPerInterval,
        1,
        u32IntervalMilliseconds,
        0,
        std::move(optImprovedParameters),
        core::AuthenticationPayloadMode::Text
    );
    const crypto::OpenSslSecureRandomProvider rngProvider;
    core::AuthenticationAuthority autAuthority(rngProvider);
    const core::SenderAuthenticationMaterial matMaterial =
        autAuthority.matIssueSenderMaterial("SENDER-A", prmRound);

    ResultCollector colSenderResults;
    ResultCollector colReceiverResults;
    std::atomic<std::uint32_t> u32SentDatagrams{0};
    std::atomic<std::uint32_t> u32AcceptedDatagrams{0};
    std::atomic<bool> bPrintedRejectedDatagram{false};
    core::AuthenticationNodeRuntime* pReceiverRuntime = nullptr;
    core::AuthenticationNodeRuntime runReceiver(
        "RECEIVER-B",
        [](const protocol::ByteBuffer&)
        {
            return false;
        },
        [&colReceiverResults](
            const protocol::NodeControlMessage& msgMessage
        )
        {
            colReceiverResults.add(msgMessage);
        },
        []()
        {
            return core::TimeSynchronizationStatus(
                true,
                2,
                "Test clock is synchronized"
            );
        }
    );
    pReceiverRuntime = &runReceiver;

    core::AuthenticationNodeRuntime runSender(
        "SENDER-A",
        [
            pReceiverRuntime,
            &u32SentDatagrams,
            &u32AcceptedDatagrams,
            &bPrintedRejectedDatagram,
            u64ExpectedChainId = matMaterial.u64ChainId()
        ](
            const protocol::ByteBuffer& vecDatagram
        )
        {
            ++u32SentDatagrams;
            if (pReceiverRuntime->bHandleDatagram(
                "10.0.0.1",
                vecDatagram,
                u64NowMilliseconds()
            ))
            {
                ++u32AcceptedDatagrams;
            }
            else if (!bPrintedRejectedDatagram.exchange(true))
            {
                const auto resHeader =
                    protocol::UdpAuthenticationPacketCodec::resDecodeHeader(
                        vecDatagram
                    );
                if (std::holds_alternative<
                        protocol::UdpAuthenticationPacketHeader
                    >(resHeader))
                {
                    const auto& hdrPacket = std::get<
                        protocol::UdpAuthenticationPacketHeader
                    >(resHeader);
                    std::cerr
                        << "Rejected datagram header: chainId="
                        << hdrPacket.u64ChainId()
                        << ", expected=" << u64ExpectedChainId
                        << ", receiverRunning="
                        << pReceiverRuntime->bReceiverRoundRunning()
                        << ", contexts="
                        << pReceiverRuntime->nReceiverContextCount()
                        << std::endl;
                }
            }
            // DatagramSender表示Socket发送是否成功，Receiver是否接受不反向影响发送端。
            return true;
        },
        [&colSenderResults](
            const protocol::NodeControlMessage& msgMessage
        )
        {
            colSenderResults.add(msgMessage);
        },
        []()
        {
            return core::TimeSynchronizationStatus(
                true,
                2,
                "Test clock is synchronized"
            );
        }
    );

    if (!bConfigureSender(runSender, matMaterial, "helloworld")
        || !bConfigureReceiver(runReceiver, matMaterial, "10.0.0.1"))
    {
        return false;
    }

    const std::string strRoundId = modeAuthentication
            == core::TeslaAuthenticationMode::Native
        ? "native-stage6-round"
        : "improved-stage6-round";
    const std::uint64_t u64StartTimestamp = u64NowMilliseconds() + 350U;
    const bool bReceiverStarted = bRoundAccepted(
        runReceiver.msgHandleControl(
        protocol::TcpClientRole::Manager,
        msgRoundCommand(
            "start-receiver",
            strRoundId,
            protocol::AuthenticationRoundCommand::Start,
            u64StartTimestamp,
            1
        ))
    );
    const bool bSenderStarted = bRoundAccepted(
        runSender.msgHandleControl(
        protocol::TcpClientRole::Manager,
        msgRoundCommand(
            "start-sender",
            strRoundId,
            protocol::AuthenticationRoundCommand::Start,
            u64StartTimestamp,
            1
        ))
    );
    if (!bReceiverStarted || !bSenderStarted)
    {
        return false;
    }

    if (bExercisePauseResume)
    {
        const std::uint64_t u64PauseTimestamp =
            u64StartTimestamp + 2U * u32IntervalMilliseconds;
        if (!bRoundAccepted(runReceiver.msgHandleControl(
            protocol::TcpClientRole::Manager,
            msgRoundCommand(
                "pause-receiver",
                strRoundId,
                protocol::AuthenticationRoundCommand::Pause,
                u64PauseTimestamp,
                2
            )
        )) || !bRoundAccepted(runSender.msgHandleControl(
            protocol::TcpClientRole::Manager,
            msgRoundCommand(
                "pause-sender",
                strRoundId,
                protocol::AuthenticationRoundCommand::Pause,
                u64PauseTimestamp,
                2
            )
        )))
        {
            return false;
        }

        const std::uint64_t u64ResumeTimestamp =
            u64PauseTimestamp + 350U;
        if (!bRoundAccepted(runReceiver.msgHandleControl(
            protocol::TcpClientRole::Manager,
            msgRoundCommand(
                "resume-receiver",
                strRoundId,
                protocol::AuthenticationRoundCommand::Resume,
                u64ResumeTimestamp,
                3
            )
        )) || !bRoundAccepted(runSender.msgHandleControl(
            protocol::TcpClientRole::Manager,
            msgRoundCommand(
                "resume-sender",
                strRoundId,
                protocol::AuthenticationRoundCommand::Resume,
                u64ResumeTimestamp,
                3
            )
        )))
        {
            return false;
        }
    }

    const bool bResultsReady =
        colSenderResults.bWaitForCount(1, std::chrono::seconds(5))
        && colReceiverResults.bWaitForCount(1, std::chrono::seconds(5));
    runSender.stop();
    runReceiver.stop();
    if (!bResultsReady)
    {
        std::cerr << "Stage 6 result timeout: sender="
                  << colSenderResults.vecResults().size()
                  << ", receiver="
                  << colReceiverResults.vecResults().size()
                  << std::endl;
        return false;
    }

    const auto vecSenderResults = colSenderResults.vecResults();
    const auto vecReceiverResults = colReceiverResults.vecResults();
    const auto& detSender = vecSenderResults.front();
    const auto& detReceiver = vecReceiverResults.front();
    const auto& detRecoveredText = std::get<
        protocol::TextAuthenticationRoundResultDetails
    >(detReceiver.varResultDetails());
    const bool bPassed = detSender.statusResult()
            == protocol::AuthenticationRoundResultStatus::Completed
        && detReceiver.statusResult()
            == protocol::AuthenticationRoundResultStatus::Completed
        && detReceiver.u32AuthenticatedPacketCount() == u32PacketCount
        && detReceiver.u32FailedPacketCount() == 0
        && detReceiver.u32MissingPacketCount() == 0
        && detRecoveredText.strRecoveredText() == "helloworld";
    if (!bPassed)
    {
        std::cerr
            << "Stage 6 result mismatch: senderStatus="
            << static_cast<int>(detSender.statusResult())
            << ", receiverStatus="
            << static_cast<int>(detReceiver.statusResult())
            << ", authenticated="
            << detReceiver.u32AuthenticatedPacketCount()
            << ", failed=" << detReceiver.u32FailedPacketCount()
            << ", missing=" << detReceiver.u32MissingPacketCount()
            << ", text=" << detRecoveredText.strRecoveredText()
            << ", message=" << detReceiver.strMessage()
            << ", sent=" << u32SentDatagrams.load()
            << ", enqueued=" << u32AcceptedDatagrams.load()
            << std::endl;
    }
    return bPassed;
}

bool bRejectSchedulingOverrun()
{
    const core::AuthenticationRoundParameters prmRound(
        crypto::CryptoAlgorithm::Sha256,
        core::TeslaAuthenticationMode::Native,
        2,
        1,
        1,
        20,
        0,
        std::nullopt,
        core::AuthenticationPayloadMode::Text
    );
    const crypto::OpenSslSecureRandomProvider rngProvider;
    core::AuthenticationAuthority autAuthority(rngProvider);
    const core::SenderAuthenticationMaterial matMaterial =
        autAuthority.matIssueSenderMaterial("SLOW-SENDER", prmRound);
    ResultCollector colResults;
    core::AuthenticationNodeRuntime runSender(
        "SLOW-SENDER",
        [](const protocol::ByteBuffer&)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            return true;
        },
        [&colResults](const protocol::NodeControlMessage& msgMessage)
        {
            colResults.add(msgMessage);
        },
        []()
        {
            return core::TimeSynchronizationStatus(
                true,
                1,
                "Test clock is synchronized"
            );
        }
    );

    if (!bConfigureSender(runSender, matMaterial, "slow"))
    {
        return false;
    }

    runSender.msgHandleControl(
        protocol::TcpClientRole::Manager,
        msgRoundCommand(
            "start-slow",
            "scheduling-overrun-round",
            protocol::AuthenticationRoundCommand::Start,
            u64NowMilliseconds() + 300U,
            1
        )
    );
    const bool bResultReady =
        colResults.bWaitForCount(1, std::chrono::seconds(3));
    runSender.stop();
    return bResultReady
        && colResults.vecResults().front().statusResult()
            == protocol::AuthenticationRoundResultStatus::
                InvalidSchedulingOverrun;
}
}

int main()
{
    try
    {
        if (!bRunEndToEnd(
                tesla::core::TeslaAuthenticationMode::Native,
                true
            ))
        {
            std::cerr
                << "FAILED: Native text authentication or pause/resume failed."
                << std::endl;
            return 1;
        }

        if (!bRunEndToEnd(
                tesla::core::TeslaAuthenticationMode::Improved,
                false
            ))
        {
            std::cerr
                << "FAILED: Improved text authentication failed."
                << std::endl;
            return 1;
        }

        if (!bRejectSchedulingOverrun())
        {
            std::cerr
                << "FAILED: Scheduling overrun was not rejected."
                << std::endl;
            return 1;
        }

        std::cout
            << "Stage 6 native/improved text authentication risks passed."
            << std::endl;
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "FAILED: " << exError.what() << std::endl;
        return 1;
    }
}

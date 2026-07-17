#include "tesla/core/AuthenticationFaultInjection.h"
#include "tesla/core/AuthenticationReceiverRuntime.h"
#include "tesla/crypto/CryptoTypes.h"
#include "tesla/metrics/AuthenticationMetrics.h"
#include "tesla/protocol/AttackControl.h"
#include "tesla/protocol/ExperimentControl.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace
{
using namespace tesla;

void require(bool bCondition, const std::string& strMessage)
{
    if (!bCondition)
    {
        throw std::runtime_error(strMessage);
    }
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

protocol::BinaryBlock arrBlock(std::uint8_t u8Value)
{
    protocol::BinaryBlock arrValue{};
    arrValue.fill(u8Value);
    return arrValue;
}

protocol::AttackControlMessage msgRoundTrip(
    const protocol::AttackControlMessage& msgSource
)
{
    const protocol::AttackControlDecodeResult resDecoded =
        protocol::AttackControlJsonCodec::resDecode(
            protocol::AttackControlJsonCodec::strEncode(msgSource)
        );
    require(
        std::holds_alternative<protocol::AttackControlMessage>(resDecoded),
        "robustness control message did not survive JSON round trip"
    );
    return std::get<protocol::AttackControlMessage>(resDecoded);
}

protocol::NodeControlMessage msgNodeRoundTrip(
    const protocol::NodeControlMessage& msgSource
)
{
    const protocol::NodeControlDecodeResult resDecoded =
        protocol::NodeControlJsonCodec::resDecode(
            protocol::NodeControlJsonCodec::strEncode(msgSource)
        );
    require(
        std::holds_alternative<protocol::NodeControlMessage>(resDecoded),
        "node experiment message did not survive JSON round trip"
    );
    return std::get<protocol::NodeControlMessage>(resDecoded);
}

protocol::ByteBuffer vecNativePacket(std::uint32_t u32PacketIndex)
{
    const std::uint32_t u32IntervalIndex = ((u32PacketIndex - 1U) / 4U) + 1U;
    const protocol::UdpAuthenticationPacketContext ctxPacket(
        protocol::UdpAuthenticationMode::Native,
        4,
        1,
        6
    );
    const protocol::UdpDataPacket udpPacket(
        101,
        u32IntervalIndex,
        u32PacketIndex,
        arrBlock(static_cast<std::uint8_t>(u32PacketIndex)),
        std::nullopt,
        protocol::NativeUdpAuthenticationDetails(arrBlock(0xA5))
    );
    return protocol::UdpAuthenticationPacketCodec::vecEncode(
        protocol::UdpAuthenticationPacket(udpPacket),
        ctxPacket
    );
}

core::AuthenticationRoundParameters prmRound()
{
    return core::AuthenticationRoundParameters(
        crypto::CryptoAlgorithm::Sha256,
        core::TeslaAuthenticationMode::Native,
        6,
        4,
        1,
        100,
        0,
        std::nullopt,
        core::AuthenticationPayloadMode::Text
    );
}

void testRobustnessControlRoundTrips()
{
    using namespace protocol;

    const AttackControlMessage msgContext = msgRoundTrip(AttackControlMessage(
        AttackRoundContextControlDetails(
            "context-1",
            "round-10",
            "UAV-101",
            "10.0.0.1",
            101,
            AuthenticationCryptoAlgorithm::Sm3,
            UdpAuthenticationMode::Improved,
            12,
            4,
            100,
            1,
            0,
            2,
            1,
            2
        )
    ));
    const auto& detContext = std::get<AttackRoundContextControlDetails>(
        msgContext.varDetails()
    );
    require(
        detContext.strRoundId() == "round-10"
            && detContext.nTauCount() == 2
            && detContext.algCryptoAlgorithm()
                == AuthenticationCryptoAlgorithm::Sm3
            && detContext.u32IntervalMilliseconds() == 100,
        "public round context fields changed"
    );

    const std::vector<AttackPlanControlDetails> vecPlans{
        AttackPlanControlDetails(
            1,
            "round-10",
            "UAV-101",
            101,
            TamperAttackPlanDetails({1, 3}, 4, 0x55, 2)
        ),
        AttackPlanControlDetails(
            2,
            "round-10",
            "UAV-101",
            101,
            ReplayAttackPlanDetails({2, 4}, 250, 3, 20)
        ),
        AttackPlanControlDetails(
            3,
            "round-10",
            "",
            0,
            DosAttackPlanDetails(200, 500, 96)
        )
    };
    for (const AttackPlanControlDetails& detPlan : vecPlans)
    {
        const AttackControlMessage msgPlan = msgRoundTrip(
            AttackControlMessage(detPlan)
        );
        const auto& detDecoded = std::get<AttackPlanControlDetails>(
            msgPlan.varDetails()
        );
        require(
            detDecoded.u64AttackId() == detPlan.u64AttackId()
                && detDecoded.typeAttack() == detPlan.typeAttack()
                && detDecoded.varPlanDetails().index()
                    == detPlan.varPlanDetails().index(),
            "mode-specific plan details changed variant"
        );
    }

    const AttackControlMessage msgAccepted = msgRoundTrip(AttackControlMessage(
        AttackPlanAcceptedControlDetails(1, "round-10", true, "", "accepted")
    ));
    require(
        std::get<AttackPlanAcceptedControlDetails>(
            msgAccepted.varDetails()
        ).bAccepted(),
        "plan acknowledgement changed"
    );

    const AttackControlMessage msgReady = msgRoundTrip(AttackControlMessage(
        AttackReadyControlDetails(1, "round-10", 1'800'000'000'000ULL)
    ));
    require(
        msgReady.typeMessage() == AttackControlMessageType::Ready,
        "ready message type changed"
    );

    const AttackControlMessage msgStart = msgRoundTrip(AttackControlMessage(
        AttackRoundCommandControlDetails(
            AttackControlMessageType::RoundStart,
            1,
            "round-10",
            1'800'000'000'500ULL
        )
    ));
    require(
        std::get<AttackRoundCommandControlDetails>(
            msgStart.varDetails()
        ).u64ExecutionTimestampMilliseconds() == 1'800'000'000'500ULL,
        "unified start timestamp changed"
    );

    const AttackControlMessage msgStatus = msgRoundTrip(AttackControlMessage(
        AttackExecutionStatusControlDetails(
            1,
            "round-10",
            AttackExecutionState::Running,
            TamperAttackStatusDetails(8, 2, 450),
            0,
            1'800'000'001'000ULL,
            "running"
        )
    ));
    const auto& detStatus = std::get<AttackExecutionStatusControlDetails>(
        msgStatus.varDetails()
    );
    require(
        detStatus.typeAttack() == AttackType::Tamper
            && std::get<TamperAttackStatusDetails>(
                detStatus.varStatusDetails()
            ).u64InjectedPacketCount() == 2,
        "execution status detail changed"
    );
}

void testNodeExperimentControlRoundTrips()
{
    using namespace protocol;

    const std::vector<AuthenticationFaultDetails> vecFaults{
        PacketLossFaultDetails(25.0, 77, 2),
        LogicalDisconnectFaultDetails(3, 500, 2),
        FixedDelayFaultDetails(35)
    };
    for (std::size_t nIndex = 0; nIndex < vecFaults.size(); ++nIndex)
    {
        const NodeControlMessage msgFault = msgNodeRoundTrip(NodeControlMessage(
            FaultInjectionControlDetails(
                "fault-" + std::to_string(nIndex),
                "round-10",
                "UAV-101",
                101,
                vecFaults[nIndex]
            )
        ));
        const auto& detFault = std::get<FaultInjectionControlDetails>(
            msgFault.varDetails()
        );
        require(
            detFault.varFaultDetails().index() == vecFaults[nIndex].index(),
            "fault plan changed variant"
        );
    }

    for (const AttackSourceMappingAction actAction : {
            AttackSourceMappingAction::Install,
            AttackSourceMappingAction::Clear
        })
    {
        const NodeControlMessage msgMapping = msgNodeRoundTrip(NodeControlMessage(
            AttackSourceMappingControlDetails(
                actAction == AttackSourceMappingAction::Install
                    ? "mapping-install"
                    : "mapping-clear",
                "round-10",
                actAction,
                "UAV-101",
                "10.0.0.1",
                "10.0.0.99",
                101,
                actAction == AttackSourceMappingAction::Install
                    ? 1'800'000'005'000ULL
                    : 0
            )
        ));
        require(
            std::get<AttackSourceMappingControlDetails>(
                msgMapping.varDetails()
            ).actAction() == actAction,
            "temporary source mapping action changed"
        );
    }

    const NodeControlMessage msgAcknowledgement = msgNodeRoundTrip(
        NodeControlMessage(ExperimentControlAcknowledgementDetails(
            "fault-0",
            "round-10",
            true,
            "",
            "accepted"
        ))
    );
    require(
        std::get<ExperimentControlAcknowledgementDetails>(
            msgAcknowledgement.varDetails()
        ).bAccepted(),
        "experiment acknowledgement changed"
    );
}

void testRoundArchiveControlRoundTrip()
{
    using namespace metrics;
    using namespace protocol;

    const AuthenticationRoundArchiveConfiguration cfgConfiguration(
        AuthenticationMetricMode::Improved,
        "SHA-256",
        "",
        100,
        100,
        100,
        3,
        100,
        1
    );
    const NodeControlMessage msgArchive = msgNodeRoundTrip(NodeControlMessage(
        MetricEventControlDetails({
            AuthenticationMetricRecord(AuthenticationRoundArchiveSummary(
                1'800'000'000'000ULL,
                "tesla-improved-sha256-p100",
                "round-archive-1",
                "0123456789abcdef",
                "UAV-201",
                "UAV-101",
                101,
                cfgConfiguration,
                "AUTHENTICATION_FAILED",
                true,
                "",
                ReceiverRoundArchiveDetails(
                    98,
                    97,
                    1,
                    2,
                    1,
                    123456,
                    6400,
                    268.75,
                    3200,
                    3168,
                    "aabbccdd"
                )
            )),
            AuthenticationMetricRecord(AuthenticationRoundArchiveSummary(
                1'800'000'000'001ULL,
                "tesla-improved-sha256-p100",
                "round-archive-1",
                "0123456789abcdef",
                "UAV-101",
                "UAV-101",
                101,
                cfgConfiguration,
                "COMPLETED",
                true,
                "",
                SenderRoundArchiveDetails(
                    100,
                    "PACKET_LOSS",
                    "rate=2.500000;protectedGroup=100",
                    42,
                    3200
                )
            ))
        })
    ));

    const auto& detEvent = std::get<MetricEventControlDetails>(
        msgArchive.varDetails()
    );
    require(detEvent.vecRecords().size() == 2, "round archive event was lost");
    const auto& sumArchive = std::get<AuthenticationRoundArchiveSummary>(
        detEvent.vecRecords().front()
    );
    const auto& detReceiver = std::get<ReceiverRoundArchiveDetails>(
        sumArchive.varDetails()
    );
    const auto& sumSender = std::get<AuthenticationRoundArchiveSummary>(
        detEvent.vecRecords().at(1)
    );
    const auto& detSender = std::get<SenderRoundArchiveDetails>(
        sumSender.varDetails()
    );
    require(
        sumArchive.strRunId() == "round-archive-1"
            && sumArchive.strGitCommit() == "0123456789abcdef"
            && sumArchive.cfgConfiguration().u32GroupSize() == 100
            && detReceiver.u32FallbackGroupCount() == 1
            && detReceiver.u64ReceivedAuthBytes() == 6400
            && detSender.strConfiguredFault() == "PACKET_LOSS"
            && detSender.u64RandomSeed() == 42,
        "round archive fields changed during JSON round trip"
    );
}

void testFaultPoliciesAndSafetyLimits()
{
    using namespace core;
    using namespace protocol;

    std::unique_ptr<AuthenticationFaultPolicy> ptrLoss =
        ptrCreateAuthenticationFaultPolicy(
            PacketLossFaultDetails(100.0, 42, 2),
            prmRound()
        );
    require(
        ptrLoss->decDecide(vecNativePacket(1), 1000).dspDisposition()
            == DatagramFaultDisposition::Drop,
        "full loss plan did not drop an eligible packet"
    );
    require(
        ptrLoss->decDecide(vecNativePacket(2), 1010).dspDisposition()
            == DatagramFaultDisposition::Send,
        "loss plan did not protect a group-end authentication packet"
    );

    std::unique_ptr<AuthenticationFaultPolicy> ptrDisconnect =
        ptrCreateAuthenticationFaultPolicy(
            LogicalDisconnectFaultDetails(1, 100, 2),
            prmRound()
        );
    require(
        ptrDisconnect->decDecide(vecNativePacket(1), 2000).dspDisposition()
            == DatagramFaultDisposition::Drop,
        "logical disconnect did not suppress an eligible packet"
    );
    require(
        ptrDisconnect->decDecide(vecNativePacket(2), 2010).dspDisposition()
            == DatagramFaultDisposition::Send,
        "logical disconnect did not protect a group-end authentication packet"
    );

    std::unique_ptr<AuthenticationFaultPolicy> ptrDelay =
        ptrCreateAuthenticationFaultPolicy(FixedDelayFaultDetails(37), prmRound());
    const DatagramFaultDecision decDelay = ptrDelay->decDecide(
        vecNativePacket(1),
        3000
    );
    require(
        decDelay.dspDisposition() == DatagramFaultDisposition::Send
            && decDelay.u32DelayMilliseconds() == 37,
        "fixed delay policy changed its configured delay"
    );

    bool bRejectedUnsafeDelay = false;
    try
    {
        const FixedDelayFaultDetails detUnsafe(10001);
        static_cast<void>(detUnsafe);
    }
    catch (const std::invalid_argument&)
    {
        bRejectedUnsafeDelay = true;
    }
    require(bRejectedUnsafeDelay, "unsafe fixed delay was accepted");

    bool bRejectedMissingExpiry = false;
    try
    {
        const AttackSourceMappingControlDetails detUnsafe(
            "mapping-invalid",
            "round-10",
            AttackSourceMappingAction::Install,
            "UAV-101",
            "10.0.0.1",
            "10.0.0.99",
            101,
            0
        );
        static_cast<void>(detUnsafe);
    }
    catch (const std::invalid_argument&)
    {
        bRejectedMissingExpiry = true;
    }
    require(bRejectedMissingExpiry, "mapping without an expiry was accepted");
}

void testTemporarySourceMappingLifecycle()
{
    core::AuthenticationReceiverRuntime runReceiver(
        [](const core::AuthenticationRuntimeResult&)
        {
        }
    );
    runReceiver.configure({core::ReceiverAuthenticationContext(
        "UAV-101",
        "10.0.0.1",
        101,
        arrBlock(0xCC),
        prmRound(),
        core::TextReceiverPayloadDetails(6)
    )});

    const std::uint64_t u64FirstStart = u64NowMilliseconds() + 500U;
    runReceiver.applyAttackSourceMapping(
        protocol::AttackSourceMappingControlDetails(
            "mapping-lifecycle",
            "round-map-1",
            protocol::AttackSourceMappingAction::Install,
            "UAV-101",
            "10.0.0.1",
            "10.0.0.99",
            101,
            u64FirstStart + 5000U
        )
    );
    runReceiver.start("round-map-1", u64FirstStart, 50);
    require(
        runReceiver.bEnqueueDatagram(
            "10.0.0.99",
            vecNativePacket(1),
            u64FirstStart
        ),
        "installed temporary source mapping was not applied"
    );
    runReceiver.stop();

    const std::uint64_t u64SecondStart = u64NowMilliseconds() + 500U;
    runReceiver.start("round-map-2", u64SecondStart, 50);
    require(
        !runReceiver.bEnqueueDatagram(
            "10.0.0.99",
            vecNativePacket(1),
            u64SecondStart
        ),
        "temporary source mapping survived round stop"
    );
    runReceiver.stop();
}
}

int main()
{
    try
    {
        testRobustnessControlRoundTrips();
        testNodeExperimentControlRoundTrips();
        testRoundArchiveControlRoundTrip();
        testFaultPoliciesAndSafetyLimits();
        testTemporarySourceMappingLifecycle();
        std::cout << "Stage 10 robustness tests passed\n";
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "Stage 10 robustness tests failed: "
                  << exError.what() << '\n';
        return 1;
    }
}

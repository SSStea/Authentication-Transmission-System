#include "tesla/core/AuthenticationObservationStore.h"
#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationReceiverRuntime.h"
#include "tesla/core/AuthenticationSenderRuntime.h"
#include "tesla/core/KsRsMatrix.h"
#include "tesla/core/SamdAggregator.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/workload/TextWorkload.h"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
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

protocol::PacketObservationControlDetails detPacket(
    std::uint64_t u64EventId,
    std::string strRoundId,
    protocol::PacketAuthenticationStatus statusAuthentication =
        protocol::PacketAuthenticationStatus::Failed
)
{
    return protocol::PacketObservationControlDetails(
        u64EventId,
        1784070000000ULL + u64EventId,
        std::move(strRoundId),
        "UAV-101",
        "192.168.10.101",
        "192.168.10.200",
        "239.10.10.10",
        protocol::PacketObservationDirection::Rx,
        protocol::PacketSourceType::AttackInjection,
        10001,
        1,
        static_cast<std::uint32_t>(u64EventId),
        4,
        1,
        protocol::AuthenticationCryptoAlgorithm::Sha256,
        protocol::UdpAuthenticationMode::Native,
        statusAuthentication,
        "candidate-" + std::to_string(u64EventId),
        1,
        "test packet",
        protocol::DataPacketObservationDetails(
            arrBlock(static_cast<std::uint8_t>(u64EventId)),
            std::nullopt,
            protocol::NativePacketObservationDetails(arrBlock(0xA5))
        ),
        protocol::ByteBuffer{1, 2, 3, static_cast<std::uint8_t>(u64EventId)}
    );
}

protocol::PacketFailureControlDetails detFailure(
    std::uint64_t u64EventId,
    std::uint64_t u64PacketEventId,
    std::string strRoundId,
    protocol::AuthenticationFailureType typeFailure =
        protocol::AuthenticationFailureType::MacFailed
)
{
    return protocol::PacketFailureControlDetails(
        u64EventId,
        u64PacketEventId,
        1784071000000ULL + u64EventId,
        protocol::ObservationSeverity::Error,
        typeFailure,
        std::move(strRoundId),
        "UAV-101",
        "192.168.10.101",
        "192.168.10.200",
        10001,
        1,
        static_cast<std::uint32_t>(u64PacketEventId),
        std::nullopt,
        "candidate-" + std::to_string(u64PacketEventId),
        "test authentication failure",
        "received-tag",
        "calculated-tag",
        {},
        1
    );
}

void testSnapshotJsonRoundTrip()
{
    protocol::AbnormalEventSnapshotControlDetails detSnapshot(
        "snapshot-1",
        1,
        true,
        {detPacket(1, "round-json")},
        {detFailure(101, 1, "round-json")}
    );
    const std::string strJson = protocol::NodeControlJsonCodec::strEncode(
        protocol::NodeControlMessage(detSnapshot)
    );
    const auto resDecoded = protocol::NodeControlJsonCodec::resDecode(strJson);
    require(
        std::holds_alternative<protocol::NodeControlMessage>(resDecoded),
        "abnormal snapshot JSON did not decode"
    );
    const auto& msgDecoded = std::get<protocol::NodeControlMessage>(resDecoded);
    const auto& detDecoded = std::get<
        protocol::AbnormalEventSnapshotControlDetails
    >(msgDecoded.varDetails());
    require(detDecoded.vecPacketEvents().size() == 1, "packet snapshot lost");
    require(detDecoded.vecFailureEvents().size() == 1, "failure snapshot lost");
    require(
        detDecoded.vecPacketEvents().front().vecRawDatagram()
            == protocol::ByteBuffer({1, 2, 3, 1}),
        "snapshot raw datagram changed"
    );
}

void testBoundedObservationStore()
{
    core::AuthenticationObservationStore stoStore(2, 3, 4, 4);
    stoStore.beginRound("round-1");
    stoStore.resAppend(detPacket(1, "round-1"));
    stoStore.resAppend(detFailure(101, 1, "round-1"));
    stoStore.resAppend(detPacket(2, "round-1"));
    stoStore.resAppend(detPacket(3, "round-1"));
    require(stoStore.nPacketCount() == 2, "packet ring limit not enforced");
    require(
        stoStore.vecAbnormalPacketSnapshot().size() == 1
            && stoStore.vecAbnormalPacketSnapshot().front().u64EventId() == 1,
        "abnormal packet was released with normal ring eviction"
    );

    require(
        stoStore.resAppend(detFailure(101, 1, "round-1"))
            == core::ObservationStoreAppendResult::Updated,
        "replayed snapshot failure was not upserted"
    );
    require(stoStore.nStoredFailureCount() == 1, "duplicate failure stored");

    stoStore.resAppend(detFailure(102, 2, "round-1"));
    stoStore.resAppend(detFailure(103, 3, "round-1"));
    require(
        stoStore.resAppend(detFailure(104, 0, "round-1"))
            == core::ObservationStoreAppendResult::AbnormalLimitReached,
        "abnormal limit warning not generated"
    );
    require(
        stoStore.resAppend(detFailure(105, 0, "round-1"))
            == core::ObservationStoreAppendResult::CountOnly,
        "post-limit failure retained full details"
    );
    const auto vecFailures = stoStore.vecFailureSnapshot();
    require(
        std::count_if(
            vecFailures.begin(),
            vecFailures.end(),
            [](const auto& detValue)
            {
                return detValue.typeFailure()
                    == protocol::AuthenticationFailureType::AbnormalRecordLimitReached;
            }
        ) == 1,
        "abnormal limit warning was not unique"
    );
}

void testRoundRetentionAndMatrixTrace()
{
    core::AuthenticationObservationStore stoStore(8, 8, 8, 4);
    stoStore.beginRound("round-1");
    stoStore.resAppend(detFailure(201, 0, "round-1"));
    stoStore.beginRound("round-2");
    stoStore.resAppend(detFailure(202, 0, "round-2"));
    stoStore.beginRound("round-3");
    require(
        stoStore.vecFailureSnapshot().size() == 1
            && stoStore.vecFailureSnapshot().front().strRoundId() == "round-2",
        "store did not retain exactly the current/previous failure window"
    );

    const crypto::OpenSslCryptoProvider crpProvider(
        crypto::CryptoAlgorithm::Sha256
    );
    const core::KsRsMatrix matKsRs(4, 1);
    std::vector<std::optional<crypto::Digest>> vecOriginalSlots;
    for (std::uint8_t u8Value = 1; u8Value <= 4; ++u8Value)
    {
        crypto::Digest digValue{};
        digValue.fill(u8Value);
        vecOriginalSlots.push_back(digValue);
    }

    std::vector<crypto::Digest> vecTau;
    for (std::size_t nRow = 0; nRow < matKsRs.nRowCount(); ++nRow)
    {
        std::vector<crypto::Digest> vecRowMacs;
        for (std::size_t nColumn = 0; nColumn < vecOriginalSlots.size(); ++nColumn)
        {
            if (matKsRs.bRowContains(nRow, nColumn))
            {
                vecRowMacs.push_back(vecOriginalSlots[nColumn].value());
            }
        }
        vecTau.push_back(core::SamdAggregator::digAggregateMacList(
            crpProvider,
            vecRowMacs
        ));
    }

    auto vecTamperedSlots = vecOriginalSlots;
    vecTamperedSlots[2]->fill(0xEE);
    const auto resLocated = core::KsRsVerifier::resVerify(
        crpProvider,
        matKsRs,
        vecTamperedSlots,
        vecTau
    );
    require(
        resLocated.vecBadPositions() == std::vector<std::size_t>({2}),
        "KS+RS did not locate the tampered position"
    );
    require(
        !resLocated.vecLocationSteps().empty(),
        "KS+RS fallback did not expose the actual row trace"
    );
}

void testRuntimeObservationCallbacks()
{
    std::mutex mtxObservations;
    std::condition_variable cndObservations;
    std::vector<protocol::AuthenticationObservation> vecReceiverObservations;
    core::AuthenticationReceiverRuntime runReceiver(
        [](const core::AuthenticationRuntimeResult&)
        {
        },
        [&](const protocol::AuthenticationObservation& varObservation)
        {
            std::lock_guard<std::mutex> lckObservations(mtxObservations);
            vecReceiverObservations.push_back(varObservation);
            cndObservations.notify_all();
        }
    );
    require(
        !runReceiver.bEnqueueDatagram(
            "192.168.10.250",
            protocol::ByteBuffer{1, 2, 3},
            u64NowMilliseconds()
        ),
        "invalid datagram unexpectedly entered the verification queue"
    );
    {
        std::unique_lock<std::mutex> lckObservations(mtxObservations);
        require(
            cndObservations.wait_for(
                lckObservations,
                std::chrono::seconds(1),
                [&vecReceiverObservations]()
                {
                    return !vecReceiverObservations.empty();
                }
            ),
            "low-rate protocol error did not produce a structured event"
        );
    }
    runReceiver.stop();
    {
        std::lock_guard<std::mutex> lckObservations(mtxObservations);
        require(
            std::holds_alternative<protocol::PacketFailureControlDetails>(
                vecReceiverObservations.front()
            )
                && std::get<protocol::PacketFailureControlDetails>(
                    vecReceiverObservations.front()
                ).typeFailure()
                    == protocol::AuthenticationFailureType::ProtocolError,
            "receiver protocol error event has the wrong type"
        );
    }

    const core::AuthenticationRoundParameters prmRound(
        crypto::CryptoAlgorithm::Sha256,
        core::TeslaAuthenticationMode::Native,
        2,
        1,
        1,
        100,
        0,
        std::nullopt,
        core::AuthenticationPayloadMode::Text
    );
    const crypto::OpenSslSecureRandomProvider rngProvider;
    core::AuthenticationAuthority autAuthority(rngProvider);
    core::SenderAuthenticationMaterial matMaterial =
        autAuthority.matIssueSenderMaterial("PC-LOCAL", prmRound);
    const crypto::OpenSslCryptoProvider crpProvider(
        crypto::CryptoAlgorithm::Sha256
    );
    core::SenderAuthenticationContext ctxSender =
        core::SenderAuthenticationContext::ctxCreateVerified(
            std::move(matMaterial),
            crpProvider
        );

    std::vector<protocol::AuthenticationObservation> vecSenderObservations;
    std::vector<core::LocalSenderKeyChainObservation> vecKeyChainObservations;
    core::AuthenticationSenderRuntime runSender(
        [](const protocol::ByteBuffer&)
        {
            return true;
        },
        [](const core::AuthenticationRuntimeResult&)
        {
        },
        [&vecSenderObservations](
            const protocol::AuthenticationObservation& varObservation
        )
        {
            vecSenderObservations.push_back(varObservation);
        },
        [&vecKeyChainObservations](
            const core::LocalSenderKeyChainObservation& varObservation
        )
        {
            vecKeyChainObservations.push_back(varObservation);
        }
    );
    runSender.configure(
        std::move(ctxSender),
        workload::TextWorkload(workload::TextPayload("stage8"), 2)
    );
    require(
        !vecKeyChainObservations.empty()
            && std::holds_alternative<core::LocalSenderKeyChainSnapshot>(
                vecKeyChainObservations.front()
            ),
        "sender configuration did not expose the local private key-chain snapshot"
    );
    runSender.start("stage8-runtime-round", u64NowMilliseconds() + 150U);
    for (int nAttempt = 0;
         nAttempt < 30 && runSender.bIsRunning();
         ++nAttempt)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    runSender.stop();
    require(
        std::count_if(
            vecSenderObservations.begin(),
            vecSenderObservations.end(),
            [](const auto& varObservation)
            {
                return std::holds_alternative<
                    protocol::PacketObservationControlDetails
                >(varObservation);
            }
        ) >= 3,
        "sender did not observe all DATA/DISCLOSE transmissions"
    );
    require(
        std::any_of(
            vecKeyChainObservations.begin(),
            vecKeyChainObservations.end(),
            [](const auto& varObservation)
            {
                const auto* pProgress = std::get_if<
                    core::LocalSenderKeyChainProgress
                >(&varObservation);
                return pProgress != nullptr && pProgress->bCompleted();
            }
        ),
        "sender did not publish completed key-chain disclosure progress"
    );
}
}

int main()
{
    try
    {
        testSnapshotJsonRoundTrip();
        testBoundedObservationStore();
        testRoundRetentionAndMatrixTrace();
        testRuntimeObservationCallbacks();
        std::cout << "Stage 8 observation tests passed\n";
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "Stage 8 observation tests failed: "
                  << exError.what() << '\n';
        return 1;
    }
}

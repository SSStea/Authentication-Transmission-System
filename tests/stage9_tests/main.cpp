#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/core/AuthenticationPacketInput.h"
#include "tesla/core/AuthenticationReceiverRuntime.h"
#include "tesla/core/AuthenticationSenderRuntime.h"
#include "tesla/core/ImprovedTeslaStrategy.h"
#include "tesla/core/NativeTeslaStrategy.h"
#include "tesla/core/ReceiverAuthenticationContextStore.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/metrics/AuthenticationMetrics.h"
#include "tesla/metrics/CommunicationCost.h"
#include "tesla/metrics/PerformanceCounterSampler.h"
#include "tesla/protocol/NodeControlJsonCodec.h"
#include "tesla/protocol/NodeControlMessage.h"
#include "tesla/workload/TextWorkload.h"

#include <algorithm>
#include <chrono>
#include <cmath>
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

bool bNear(double dActual, double dExpected, double dTolerance)
{
    return std::abs(dActual - dExpected) <= dTolerance;
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

core::AuthenticationPacketInput::Message arrMessage(std::uint8_t u8Seed)
{
    core::AuthenticationPacketInput::Message arrResult{};
    for (std::size_t nIndex = 0; nIndex < arrResult.size(); ++nIndex)
    {
        arrResult[nIndex] = static_cast<std::uint8_t>(u8Seed + nIndex);
    }
    return arrResult;
}

core::AuthenticationGroupInput grpInput(std::size_t nPacketCount)
{
    std::vector<core::AuthenticationGroupInput::PacketSlot> vecSlots;
    vecSlots.reserve(nPacketCount);
    for (std::size_t nPosition = 0; nPosition < nPacketCount; ++nPosition)
    {
        vecSlots.emplace_back(core::AuthenticationPacketInput(
            "UAV-101",
            0x0102030405060708ULL,
            3,
            static_cast<std::uint32_t>(101 + nPosition),
            arrMessage(static_cast<std::uint8_t>(0x10 + nPosition))
        ));
    }

    return core::AuthenticationGroupInput(
        "UAV-101",
        0x0102030405060708ULL,
        3,
        7,
        101,
        std::move(vecSlots)
    );
}

crypto::Digest digDataKey(const crypto::CryptoProvider& crpProvider)
{
    const std::string strSeed = "stage9-performance-key";
    return crpProvider.digHash(
        crypto::ByteBuffer(strSeed.begin(), strSeed.end())
    );
}

metrics::HardwarePerformanceCounters ctrUnsupported()
{
    return metrics::HardwarePerformanceCounters(
        metrics::HardwareCounterStatus::NotSupported,
        0,
        0,
        0
    );
}

metrics::VerificationMetricSample smpNative(
    std::uint64_t u64EventId,
    std::uint32_t u32PacketIndex
)
{
    return metrics::VerificationMetricSample(
        u64EventId,
        1784070000000ULL + u64EventId,
        "round-metrics",
        "UAV-101",
        0x0102030405060708ULL,
        1,
        metrics::PerformanceMeasurement(1000 + u64EventId, ctrUnsupported()),
        metrics::NativeVerificationMetricDetails(1, u32PacketIndex)
    );
}

void testCommunicationCostFormulaAndAccumulator()
{
    const metrics::CommunicationCostMetricSummary sumNative =
        metrics::CommunicationCostCalculator::sumNative(
            1,
            "native-formula",
            "UAV-101",
            1,
            100,
            1
        );
    const metrics::CommunicationCostMetricSummary sumImproved =
        metrics::CommunicationCostCalculator::sumImproved(
            1,
            "improved-formula",
            "UAV-101",
            2,
            100,
            1,
            25,
            1
        );
    require(sumNative.u64TotalBytes() == 6432, "native formula is not 6432 B");
    require(sumImproved.u64TotalBytes() == 4064, "improved formula is not 4064 B");

    metrics::CommunicationCostAccumulator accNative(
        metrics::AuthenticationMetricMode::Native
    );
    metrics::CommunicationCostAccumulator accImproved(
        metrics::AuthenticationMetricMode::Improved
    );
    for (std::size_t nPacket = 0; nPacket < 100; ++nPacket)
    {
        accNative.addNativeDataPacket();
        accImproved.addImprovedDataPacket(
            nPacket == 99 ? 25U : 0U,
            nPacket == 99
        );
    }
    accNative.addDisclosedKey();
    accImproved.addDisclosedKey();

    require(
        accNative.sumCreate(1, "native-actual", "UAV-101", 1)
                .u64TotalBytes()
            == sumNative.u64TotalBytes(),
        "native field accumulator differs from the fixed formula"
    );
    require(
        accImproved.sumCreate(1, "improved-actual", "UAV-101", 2)
                .u64TotalBytes()
            == sumImproved.u64TotalBytes(),
        "improved field accumulator differs from the fixed formula"
    );
}

void testEstimatedEnergyBaselineAndClassification()
{
    const double dNativeEnergy = metrics::EstimatedEnergyCalculator::
        dEstimateMicroJoule(7444464, 6432);
    const double dImprovedEnergy = metrics::EstimatedEnergyCalculator::
        dEstimateMicroJoule(1251504, 4064);
    require(bNear(dNativeEnergy, 1595.105712, 0.000001), "native energy baseline changed");
    require(bNear(dImprovedEnergy, 383.002480, 0.000001), "improved energy baseline changed");
    require(
        bNear((1.0 - dImprovedEnergy / dNativeEnergy) * 100.0, 75.9889, 0.001),
        "energy baseline reduction is not approximately 75.99 percent"
    );

    metrics::AuthenticationRoundMetricCollector colFast(
        "round-fast",
        "UAV-101",
        1,
        metrics::AuthenticationMetricMode::Improved,
        4
    );
    const metrics::VerificationMetricSample smpFast(
        100,
        1784070000100ULL,
        "round-fast",
        "UAV-101",
        1,
        4,
        metrics::PerformanceMeasurement(4000, ctrUnsupported()),
        metrics::ImprovedVerificationMetricDetails(
            1,
            1,
            4,
            metrics::VerificationMetricPath::FastGroupPass
        )
    );
    colFast.addVerificationSample(smpFast);
    colFast.addDisclosureKeyMeasurement(
        metrics::PerformanceMeasurement(1000, ctrUnsupported())
    );
    colFast.addReceivedAuthBytes(224);
    const metrics::EstimatedEnergyMetricSummary sumFast =
        colFast.sumCreateEnergySummary(1784070000200ULL, true);
    require(sumFast.u64VerifyTimeNanoseconds() == 5000, "round time was not accumulated");
    require(sumFast.u64ReceivedAuthBytes() == 224, "received fields were not accumulated");
    require(sumFast.bNormalComparisonEligible(), "normal fast round was excluded");
    colFast.markNormalComparisonIneligible();
    require(
        !colFast.sumCreateEnergySummary(1784070000201ULL, true)
             .bNormalComparisonEligible(),
        "round with a structured failure remained in normal comparison"
    );

    metrics::AuthenticationRoundMetricCollector colFallback(
        "round-fallback",
        "UAV-101",
        2,
        metrics::AuthenticationMetricMode::Improved,
        4
    );
    colFallback.addVerificationSample(metrics::VerificationMetricSample(
        101,
        1784070000101ULL,
        "round-fallback",
        "UAV-101",
        2,
        4,
        metrics::PerformanceMeasurement(6000, ctrUnsupported()),
        metrics::ImprovedVerificationMetricDetails(
            1,
            1,
            4,
            metrics::VerificationMetricPath::KsRsFallback
        )
    ));
    require(
        !colFallback.sumCreateEnergySummary(1784070000201ULL, true)
             .bNormalComparisonEligible(),
        "fallback round entered the normal energy comparison"
    );
}

void testMetricStoreAndJsonTransport()
{
    metrics::AuthenticationMetricStore stoMetrics(2);
    require(stoMetrics.bAppend(smpNative(1, 1)), "first metric was rejected");
    require(!stoMetrics.bAppend(smpNative(1, 1)), "duplicate metric was retained");
    require(stoMetrics.bAppend(smpNative(2, 2)), "second metric was rejected");
    require(stoMetrics.bAppend(smpNative(3, 3)), "third metric was rejected");
    const auto vecSnapshot = stoMetrics.vecSnapshot();
    require(vecSnapshot.size() == 2, "metric store bound was not enforced");
    require(
        std::get<metrics::VerificationMetricSample>(vecSnapshot.front())
                .u64EventId()
            == 2,
        "metric store did not evict the oldest record"
    );

    const metrics::EstimatedEnergyMetricSummary sumEnergy(
        1784070000300ULL,
        "round-metrics",
        "UAV-101",
        0x0102030405060708ULL,
        3,
        9000,
        224,
        metrics::EstimatedEnergyCalculator::dEstimateMicroJoule(9000, 224),
        true,
        metrics::ImprovedRoundMetricDetails(1, 0, 0)
    );
    const metrics::CommunicationCostMetricSummary sumCommunication =
        metrics::CommunicationCostCalculator::sumNative(
            1784070000301ULL,
            "round-metrics",
            "UAV-101",
            0x0102030405060708ULL,
            3,
            1
        );
    const protocol::NodeControlMessage msgMetrics(
        protocol::MetricEventControlDetails({
            smpNative(10, 10),
            sumEnergy,
            sumCommunication
        })
    );
    const auto resDecoded = protocol::NodeControlJsonCodec::resDecode(
        protocol::NodeControlJsonCodec::strEncode(msgMetrics)
    );
    require(
        std::holds_alternative<protocol::NodeControlMessage>(resDecoded),
        "metric event JSON did not decode"
    );
    const auto& detDecoded = std::get<protocol::MetricEventControlDetails>(
        std::get<protocol::NodeControlMessage>(resDecoded).varDetails()
    );
    require(detDecoded.vecRecords().size() == 3, "metric JSON lost records");
    require(
        std::get<metrics::EstimatedEnergyMetricSummary>(
            detDecoded.vecRecords()[1]
        ).bNormalComparisonEligible(),
        "energy eligibility changed during JSON transport"
    );
    require(
        std::get<metrics::CommunicationCostMetricSummary>(
            detDecoded.vecRecords()[2]
        ).u64TotalBytes() == 224,
        "communication fields changed during JSON transport"
    );

    const protocol::NodeControlMessage msgEmptySnapshot(
        protocol::MetricSnapshotControlDetails(
            "metric-snapshot-1",
            1,
            true,
            {}
        )
    );
    const auto resSnapshot = protocol::NodeControlJsonCodec::resDecode(
        protocol::NodeControlJsonCodec::strEncode(msgEmptySnapshot)
    );
    require(
        std::holds_alternative<protocol::NodeControlMessage>(resSnapshot)
            && std::get<protocol::NodeControlMessage>(resSnapshot)
                .typeMessage() == protocol::NodeControlMessageType::MetricSnapshot,
        "empty final metric snapshot did not round-trip"
    );
}

void testStrategyPerformanceSampling()
{
    const crypto::OpenSslCryptoProvider crpProvider(
        crypto::CryptoAlgorithm::Sha256
    );
    const crypto::Digest digKey = digDataKey(crpProvider);
    std::unique_ptr<metrics::VerificationPerformanceSampler> ptrSampler =
        metrics::ptrCreateVerificationPerformanceSampler();
    require(ptrSampler != nullptr, "performance sampler factory returned null");

    const core::AuthenticationGroupInput grpNative = grpInput(2);
    const core::NativeTeslaStrategy stgNative(crpProvider);
    const core::TeslaAuthenticationDetails varNative =
        stgNative.authCreateAuthenticationDetails(grpNative, digKey);
    std::vector<std::size_t> vecNativePositions;
    std::vector<metrics::PerformanceMeasurement> vecNativeMeasurements;
    const core::TeslaVerificationResult vfyNative = stgNative.vfyVerify(
        grpNative,
        varNative,
        digKey,
        ptrSampler.get(),
        [&vecNativePositions, &vecNativeMeasurements](
            std::size_t nPosition,
            const metrics::PerformanceMeasurement& mstMeasurement
        )
        {
            vecNativePositions.push_back(nPosition);
            vecNativeMeasurements.push_back(mstMeasurement);
        }
    );
    require(vfyNative.bPassed(), "instrumented native verification failed");
    require(vecNativePositions == std::vector<std::size_t>({0, 1}),
        "native sampler did not report one point per packet");

    const core::AuthenticationGroupInput grpImproved = grpInput(4);
    const core::ImprovedTeslaStrategy stgImproved(crpProvider, 4, 1);
    const core::TeslaAuthenticationDetails varImproved =
        stgImproved.authCreateAuthenticationDetails(grpImproved, digKey);
    std::size_t nImprovedSampleCount = 0;
    const core::TeslaVerificationResult vfyImproved = stgImproved.vfyVerify(
        grpImproved,
        varImproved,
        digKey,
        ptrSampler.get(),
        [&nImprovedSampleCount](
            std::size_t,
            const metrics::PerformanceMeasurement&
        )
        {
            ++nImprovedSampleCount;
        }
    );
    require(vfyImproved.bPassed(), "instrumented improved verification failed");
    require(nImprovedSampleCount == 1, "improved sampler did not report one point per group");
    require(
        std::get<core::ImprovedVerificationDetails>(vfyImproved.varDetails())
                .pathVerification()
            == core::ImprovedVerificationPath::FastGroupPass,
        "normal improved sample did not use the fast path"
    );
}

void testRuntimeMetricPipeline()
{
    const core::AuthenticationRoundParameters prmRound(
        crypto::CryptoAlgorithm::Sha256,
        core::TeslaAuthenticationMode::Native,
        4,
        2,
        1,
        100,
        0,
        std::nullopt,
        core::AuthenticationPayloadMode::Text
    );
    const crypto::OpenSslSecureRandomProvider rngProvider;
    core::AuthenticationAuthority autAuthority(rngProvider);
    core::SenderAuthenticationMaterial matMaterial =
        autAuthority.matIssueSenderMaterial("UAV-PIPELINE", prmRound);

    std::mutex mtxResults;
    std::condition_variable cndResults;
    bool bSenderReported = false;
    bool bReceiverReported = false;
    bool bSenderCompleted = false;
    bool bReceiverCompleted = false;
    std::string strSenderResult;
    std::string strReceiverResult;
    std::string strReceiverFailure;
    std::uint32_t u32AcceptedDatagramCount = 0;
    std::vector<metrics::AuthenticationMetricRecord> vecSenderMetrics;
    std::vector<metrics::AuthenticationMetricRecord> vecReceiverMetrics;

    core::AuthenticationReceiverRuntime runReceiver(
        [
            &mtxResults,
            &cndResults,
            &bReceiverReported,
            &bReceiverCompleted,
            &strReceiverResult
        ](
            const core::AuthenticationRuntimeResult& resResult
        )
        {
            std::lock_guard<std::mutex> lckResults(mtxResults);
            bReceiverReported = true;
            bReceiverCompleted = resResult.statusResult()
                == core::AuthenticationRuntimeResultStatus::Completed;
            strReceiverResult = resResult.strMessage();
            cndResults.notify_all();
        },
        [&mtxResults, &strReceiverFailure](
            const protocol::AuthenticationObservation& varObservation
        )
        {
            const auto* pFailure = std::get_if<
                protocol::PacketFailureControlDetails
            >(&varObservation);
            if (pFailure != nullptr)
            {
                std::lock_guard<std::mutex> lckResults(mtxResults);
                strReceiverFailure = pFailure->strReason();
            }
        },
        [&mtxResults, &vecReceiverMetrics](
            const metrics::AuthenticationMetricRecord& varMetric
        )
        {
            std::lock_guard<std::mutex> lckResults(mtxResults);
            vecReceiverMetrics.push_back(varMetric);
        }
    );
    runReceiver.configure({core::ReceiverAuthenticationContext(
        matMaterial.strSenderId(),
        "10.0.0.1",
        matMaterial.u64ChainId(),
        matMaterial.digCommitmentKey(),
        matMaterial.prmRoundParameters(),
        core::TextReceiverPayloadDetails(4)
    )});

    const crypto::OpenSslCryptoProvider crpProvider(
        crypto::CryptoAlgorithm::Sha256
    );
    core::AuthenticationSenderRuntime runSender(
        [&runReceiver, &mtxResults, &u32AcceptedDatagramCount](
            const protocol::ByteBuffer& vecDatagram
        )
        {
            const bool bAccepted = runReceiver.bEnqueueDatagram(
                "10.0.0.1",
                vecDatagram,
                u64NowMilliseconds()
            );
            if (bAccepted)
            {
                std::lock_guard<std::mutex> lckResults(mtxResults);
                ++u32AcceptedDatagramCount;
            }
            // Sender回调只表示Socket发送成功，Receiver异步入队结果不反向改变发送状态。
            return true;
        },
        [
            &mtxResults,
            &cndResults,
            &bSenderReported,
            &bSenderCompleted,
            &strSenderResult
        ](
            const core::AuthenticationRuntimeResult& resResult
        )
        {
            std::lock_guard<std::mutex> lckResults(mtxResults);
            bSenderReported = true;
            bSenderCompleted = resResult.statusResult()
                == core::AuthenticationRuntimeResultStatus::Completed;
            strSenderResult = resResult.strMessage();
            cndResults.notify_all();
        },
        {},
        {},
        [&mtxResults, &vecSenderMetrics](
            const metrics::AuthenticationMetricRecord& varMetric
        )
        {
            std::lock_guard<std::mutex> lckResults(mtxResults);
            vecSenderMetrics.push_back(varMetric);
        }
    );
    runSender.configure(
        core::SenderAuthenticationContext::ctxCreateVerified(
            std::move(matMaterial),
            crpProvider
        ),
        workload::TextWorkload(workload::TextPayload("stage9"), 4)
    );

    const std::uint64_t u64StartTimestamp = u64NowMilliseconds() + 250U;
    runReceiver.start("stage9-runtime-round", u64StartTimestamp, 2);
    runSender.start("stage9-runtime-round", u64StartTimestamp);
    {
        std::unique_lock<std::mutex> lckResults(mtxResults);
        require(
            cndResults.wait_for(
                lckResults,
                std::chrono::seconds(5),
                [&bSenderReported, &bReceiverReported]()
                {
                    return bSenderReported && bReceiverReported;
                }
            ),
            "runtime metric round did not complete"
        );
    }
    runSender.stop();
    runReceiver.stop();

    std::lock_guard<std::mutex> lckResults(mtxResults);
    require(
        bSenderCompleted,
        "sender runtime failed: " + strSenderResult
    );
    require(
        bReceiverCompleted,
        "receiver runtime failed after accepting "
            + std::to_string(u32AcceptedDatagramCount)
            + " datagrams: " + strReceiverResult
            + "; last failure: " + strReceiverFailure
    );
    require(vecSenderMetrics.size() == 1, "sender did not emit one communication summary");
    const auto& sumCommunication = std::get<
        metrics::CommunicationCostMetricSummary
    >(vecSenderMetrics.front());
    require(sumCommunication.u64TotalBytes() == 320,
        "runtime communication summary counted non-algorithm bytes");

    const std::size_t nVerificationSamples = static_cast<std::size_t>(
        std::count_if(
            vecReceiverMetrics.begin(),
            vecReceiverMetrics.end(),
            [](const auto& varMetric)
            {
                return std::holds_alternative<
                    metrics::VerificationMetricSample
                >(varMetric);
            }
        )
    );
    require(nVerificationSamples == 4,
        "receiver did not emit one native verification sample per packet");
    const auto itrEnergy = std::find_if(
        vecReceiverMetrics.begin(),
        vecReceiverMetrics.end(),
        [](const auto& varMetric)
        {
            return std::holds_alternative<
                metrics::EstimatedEnergyMetricSummary
            >(varMetric);
        }
    );
    require(itrEnergy != vecReceiverMetrics.end(), "receiver did not emit energy summary");
    const auto& sumEnergy = std::get<metrics::EstimatedEnergyMetricSummary>(
        *itrEnergy
    );
    require(sumEnergy.u64ReceivedAuthBytes() == 320,
        "receiver energy summary counted a different field range");
    require(sumEnergy.bNormalComparisonEligible(),
        "completed native round was excluded from normal comparison");
}
}

int main()
{
    try
    {
        testCommunicationCostFormulaAndAccumulator();
        testEstimatedEnergyBaselineAndClassification();
        testMetricStoreAndJsonTransport();
        testStrategyPerformanceSampling();
        testRuntimeMetricPipeline();
        std::cout << "Stage 9 metric tests passed\n";
        return 0;
    }
    catch (const std::exception& exError)
    {
        std::cerr << "Stage 9 metric tests failed: "
                  << exError.what() << '\n';
        return 1;
    }
}

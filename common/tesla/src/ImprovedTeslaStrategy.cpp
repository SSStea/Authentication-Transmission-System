#include "tesla/core/ImprovedTeslaStrategy.h"

#include "tesla/core/ImprovedTeslaDetails.h"
#include "tesla/core/KsRsMatrix.h"
#include "tesla/core/SamdAggregator.h"
#include "tesla/core/TeslaMac.h"
#include "tesla/crypto/CryptoUtilities.h"

#include <numeric>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
ImprovedTeslaStrategy::ImprovedTeslaStrategy(
    const crypto::CryptoProvider& crpProvider,
    std::size_t nGroupSize,
    std::size_t nDetectionThreshold
)
    : m_crpProvider(crpProvider),
      m_matKsRs(nGroupSize, nDetectionThreshold)
{
}

TeslaAuthenticationDetails ImprovedTeslaStrategy::authCreateAuthenticationDetails(
    const AuthenticationGroupInput& grpInput,
    const crypto::Digest& digDataKey
) const
{
    if (grpInput.bHasMissingPackets())
    {
        throw std::invalid_argument("Improved Sender input must not contain missing packets");
    }

    if (grpInput.nPacketSlotCount() > m_matKsRs.nGroupSize())
    {
        throw std::invalid_argument("Improved group exceeds configured KS+RS group size");
    }

    // 发送端先计算逐包MAC，再按矩阵行聚合tau，最后用快速标签绑定整个组。
    const std::vector<std::optional<crypto::Digest>> vecPacketMacSlots =
        vecComputePacketMacSlots(grpInput, digDataKey);
    std::vector<crypto::Digest> vecPacketMacs;
    vecPacketMacs.reserve(vecPacketMacSlots.size());

    for (const std::optional<crypto::Digest>& optPacketMac : vecPacketMacSlots)
    {
        vecPacketMacs.push_back(optPacketMac.value());
    }

    std::vector<crypto::Digest> vecSamdTau = SamdAggregator::vecAggregate(
        m_crpProvider,
        m_matKsRs,
        vecPacketMacs
    );
    const crypto::Digest digFastGroupTag = TeslaMac::digComputeFastGroupTag(
        m_crpProvider,
        digDataKey,
        grpInput,
        vecSamdTau
    );

    return ImprovedAuthenticationDetails(
        std::move(vecSamdTau),
        digFastGroupTag
    );
}

TeslaVerificationResult ImprovedTeslaStrategy::vfyVerify(
    const AuthenticationGroupInput& grpInput,
    const TeslaAuthenticationDetails& varReceivedDetails,
    const crypto::Digest& digDataKey,
    metrics::VerificationPerformanceSampler* pPerformanceSampler,
    VerificationMeasurementHandler fnMeasurementHandler
) const
{
    // variant类型必须与当前策略匹配，防止跨模式错误解释认证字段。
    const ImprovedAuthenticationDetails* pImprovedDetails =
        std::get_if<ImprovedAuthenticationDetails>(&varReceivedDetails);

    if (pImprovedDetails == nullptr)
    {
        throw std::invalid_argument("Improved strategy received native authentication details");
    }

    if (grpInput.nPacketSlotCount() > m_matKsRs.nGroupSize())
    {
        throw std::invalid_argument("Improved group exceeds configured KS+RS group size");
    }

    const bool bMeasure = pPerformanceSampler != nullptr
        && static_cast<bool>(fnMeasurementHandler);
    if (bMeasure)
    {
        pPerformanceSampler->begin();
    }
    const auto fnFinishMeasurement = [&]()
    {
        if (bMeasure)
        {
            fnMeasurementHandler(0, pPerformanceSampler->mstEnd());
        }
    };

    // tau数量不完整或快速标签缺失时，既不能走快速路径也不能安全回退。
    if (
        pImprovedDetails->vecSamdTau().size() != m_matKsRs.nRowCount()
        || !pImprovedDetails->optFastGroupTag().has_value()
    )
    {
        TeslaVerificationResult vfyResult(
            false,
            ImprovedVerificationDetails(
                ImprovedVerificationPath::IncompleteGroupTags,
                false,
                {},
                {},
                false
            )
        );
        fnFinishMeasurement();
        return vfyResult;
    }

    // 完整组优先验证一次快速标签；成功时不再执行任何逐包MAC计算。
    if (!grpInput.bHasMissingPackets())
    {
        const crypto::Digest digCalculatedFastGroupTag = TeslaMac::digComputeFastGroupTag(
            m_crpProvider,
            digDataKey,
            grpInput,
            pImprovedDetails->vecSamdTau()
        );

        if (crypto::CryptoUtilities::bDigestEquals(
                digCalculatedFastGroupTag,
                pImprovedDetails->optFastGroupTag().value()
            ))
        {
            std::vector<std::size_t> vecAuthenticatedPositions(grpInput.nPacketSlotCount());
            std::iota(
                vecAuthenticatedPositions.begin(),
                vecAuthenticatedPositions.end(),
                0
            );

            TeslaVerificationResult vfyResult(
                true,
                ImprovedVerificationDetails(
                    ImprovedVerificationPath::FastGroupPass,
                    true,
                    std::move(vecAuthenticatedPositions),
                    {},
                    false
                )
            );
            fnFinishMeasurement();
            return vfyResult;
        }
    }

    // 快速标签不匹配或存在丢包时，保留原槽位并进入KS+RS定位路径。
    const std::vector<std::optional<crypto::Digest>> vecPacketMacSlots =
        vecComputePacketMacSlots(grpInput, digDataKey);
    KsRsVerificationResult resKsRs = KsRsVerifier::resVerify(
        m_crpProvider,
        m_matKsRs,
        vecPacketMacSlots,
        pImprovedDetails->vecSamdTau()
    );

    TeslaVerificationResult vfyResult(
        false,
        ImprovedVerificationDetails(
            ImprovedVerificationPath::KsRsFallback,
            false,
            resKsRs.vecGoodPositions(),
            resKsRs.vecBadPositions(),
            resKsRs.bDetectionThresholdExceeded(),
            resKsRs.vecLocationSteps()
        )
    );
    fnFinishMeasurement();
    return vfyResult;
}

std::vector<std::optional<crypto::Digest>>
ImprovedTeslaStrategy::vecComputePacketMacSlots(
    const AuthenticationGroupInput& grpInput,
    const crypto::Digest& digDataKey
) const
{
    std::vector<std::optional<crypto::Digest>> vecPacketMacSlots;
    vecPacketMacSlots.reserve(grpInput.nPacketSlotCount());

    // 空槽位原样传播给KS+RS验证器，实际报文才会重算逐包MAC。
    for (const AuthenticationGroupInput::PacketSlot& optPacket : grpInput.vecPacketSlots())
    {
        if (!optPacket.has_value())
        {
            vecPacketMacSlots.push_back(std::nullopt);
            continue;
        }

        vecPacketMacSlots.push_back(TeslaMac::digComputePacketMac(
            m_crpProvider,
            digDataKey,
            optPacket.value()
        ));
    }

    return vecPacketMacSlots;
}
}

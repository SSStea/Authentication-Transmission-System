#include "tesla/core/NativeTeslaStrategy.h"

#include "tesla/core/NativeTeslaDetails.h"
#include "tesla/core/TeslaMac.h"
#include "tesla/crypto/CryptoUtilities.h"

#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
NativeTeslaStrategy::NativeTeslaStrategy(const crypto::CryptoProvider& crpProvider)
    : m_crpProvider(crpProvider)
{
}

TeslaAuthenticationDetails NativeTeslaStrategy::authCreateAuthenticationDetails(
    const AuthenticationGroupInput& grpInput,
    const crypto::Digest& digDataKey
) const
{
    if (grpInput.bHasMissingPackets())
    {
        throw std::invalid_argument("Native Sender input must not contain missing packets");
    }

    // 原生发送端为完整组的每个固定槽位生成一个独立MAC。
    std::vector<std::optional<crypto::Digest>> vecPacketMacs;
    vecPacketMacs.reserve(grpInput.nPacketSlotCount());

    for (const AuthenticationGroupInput::PacketSlot& optPacket : grpInput.vecPacketSlots())
    {
        vecPacketMacs.push_back(TeslaMac::digComputePacketMac(
            m_crpProvider,
            digDataKey,
            optPacket.value()
        ));
    }

    return NativeAuthenticationDetails(std::move(vecPacketMacs));
}

TeslaVerificationResult NativeTeslaStrategy::vfyVerify(
    const AuthenticationGroupInput& grpInput,
    const TeslaAuthenticationDetails& varReceivedDetails,
    const crypto::Digest& digDataKey,
    metrics::VerificationPerformanceSampler* pPerformanceSampler,
    VerificationMeasurementHandler fnMeasurementHandler
) const
{
    // variant类型必须与当前策略匹配，避免把改进模式字段误作逐包MAC解释。
    const NativeAuthenticationDetails* pNativeDetails =
        std::get_if<NativeAuthenticationDetails>(&varReceivedDetails);

    if (pNativeDetails == nullptr)
    {
        throw std::invalid_argument("Native strategy received improved authentication details");
    }

    if (pNativeDetails->vecPacketMacs().size() != grpInput.nPacketSlotCount())
    {
        throw std::invalid_argument("Native MAC slots do not match packet slots");
    }

    bool                            bAllPassed = true;
    std::vector<NativePacketStatus> vecPacketStatuses;
    vecPacketStatuses.reserve(grpInput.nPacketSlotCount());

    // 按固定槽位分别区分丢包、缺MAC、MAC失败和验证通过。
    for (std::size_t nPosition = 0; nPosition < grpInput.nPacketSlotCount(); ++nPosition)
    {
        const AuthenticationGroupInput::PacketSlot& optPacket =
            grpInput.vecPacketSlots()[nPosition];
        const std::optional<crypto::Digest>& optReceivedMac =
            pNativeDetails->vecPacketMacs()[nPosition];

        if (!optPacket.has_value())
        {
            vecPacketStatuses.push_back(NativePacketStatus::MissingPacket);
            bAllPassed = false;
            continue;
        }

        if (!optReceivedMac.has_value())
        {
            vecPacketStatuses.push_back(NativePacketStatus::MissingMac);
            bAllPassed = false;
            continue;
        }

        const bool bMeasure = pPerformanceSampler != nullptr
            && static_cast<bool>(fnMeasurementHandler);
        if (bMeasure)
        {
            pPerformanceSampler->begin();
        }

        const crypto::Digest digCalculatedMac = TeslaMac::digComputePacketMac(
            m_crpProvider,
            digDataKey,
            optPacket.value()
        );
        const bool bMacMatched = crypto::CryptoUtilities::bDigestEquals(
            digCalculatedMac,
            optReceivedMac.value()
        );

        if (bMeasure)
        {
            fnMeasurementHandler(nPosition, pPerformanceSampler->mstEnd());
        }

        if (bMacMatched)
        {
            vecPacketStatuses.push_back(NativePacketStatus::Passed);
        }
        else
        {
            vecPacketStatuses.push_back(NativePacketStatus::MacFailed);
            bAllPassed = false;
        }
    }

    return TeslaVerificationResult(
        bAllPassed,
        NativeVerificationDetails(std::move(vecPacketStatuses))
    );
}
}

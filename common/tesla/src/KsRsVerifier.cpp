#include "tesla/core/KsRsVerifier.h"

#include "tesla/core/SamdAggregator.h"
#include "tesla/crypto/CryptoUtilities.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
KsRsVerificationResult KsRsVerifier::resVerify(
    const crypto::CryptoProvider& crpProvider,
    const KsRsMatrix& matKsRs,
    const std::vector<std::optional<crypto::Digest>>& vecPacketMacSlots,
    const std::vector<crypto::Digest>& vecReceivedTau
)
{
    if (vecPacketMacSlots.empty() || vecPacketMacSlots.size() > matKsRs.nGroupSize())
    {
        throw std::invalid_argument("Packet MAC slots are outside the KS+RS group size");
    }

    if (vecReceivedTau.size() != matKsRs.nRowCount())
    {
        throw std::invalid_argument("Received SAMD tag count does not match the KS+RS matrix");
    }

    // 位置只有被至少一个可重算且匹配的矩阵行覆盖后，才会被标记为已证明。
    std::vector<bool> vecIsGood(vecPacketMacSlots.size(), false);

    for (std::size_t nRowIndex = 0; nRowIndex < matKsRs.nRowCount(); ++nRowIndex)
    {
        bool                        bRowHasMissingMac = false;
        std::vector<std::size_t>    vecRowPositions;
        std::vector<crypto::Digest> vecRowMacs;

        for (std::size_t nColumnIndex = 0;
             nColumnIndex < vecPacketMacSlots.size();
             ++nColumnIndex)
        {
            if (!matKsRs.bRowContains(nRowIndex, nColumnIndex))
            {
                continue;
            }

            vecRowPositions.push_back(nColumnIndex);

            if (!vecPacketMacSlots[nColumnIndex].has_value())
            {
                bRowHasMissingMac = true;
                break;
            }

            vecRowMacs.push_back(vecPacketMacSlots[nColumnIndex].value());
        }

        // 含缺失MAC的行无法完整重算，必须跳过，不能压缩剩余MAC后继续比较。
        if (vecRowPositions.empty() || bRowHasMissingMac)
        {
            continue;
        }

        const crypto::Digest digCalculatedTau = SamdAggregator::digAggregateMacList(
            crpProvider,
            vecRowMacs
        );

        if (crypto::CryptoUtilities::bDigestEquals(digCalculatedTau, vecReceivedTau[nRowIndex]))
        {
            for (std::size_t nPosition : vecRowPositions)
            {
                vecIsGood[nPosition] = true;
            }
        }
    }

    std::vector<std::size_t> vecGoodPositions;
    std::vector<std::size_t> vecBadPositions;

    for (std::size_t nPosition = 0; nPosition < vecIsGood.size(); ++nPosition)
    {
        if (vecIsGood[nPosition])
        {
            vecGoodPositions.push_back(nPosition);
        }
        else
        {
            vecBadPositions.push_back(nPosition);
        }
    }

    // 未被任何匹配行证明的位置统一归入坏位置，再与配置门限比较。
    const bool bThresholdExceeded = vecBadPositions.size() > matKsRs.nDetectionThreshold();

    return KsRsVerificationResult(
        std::move(vecGoodPositions),
        std::move(vecBadPositions),
        bThresholdExceeded
    );
}
}

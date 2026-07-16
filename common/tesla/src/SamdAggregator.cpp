#include "tesla/core/SamdAggregator.h"

#include <stdexcept>

namespace tesla::core
{
crypto::Digest SamdAggregator::digAggregateMacList(
    const crypto::CryptoProvider& crpProvider,
    const std::vector<crypto::Digest>& vecPacketMacs
)
{
    crypto::ByteBuffer vecInput;
    vecInput.reserve(vecPacketMacs.size() * (crypto::DIGEST_SIZE + 1));

    // 0x01作为每个MAC的域标记，随后直接拼接固定32字节原始MAC。
    for (const crypto::Digest& digPacketMac : vecPacketMacs)
    {
        vecInput.push_back(0x01);
        vecInput.insert(vecInput.end(), digPacketMac.begin(), digPacketMac.end());
    }

    return crpProvider.digHash(vecInput);
}

std::vector<crypto::Digest> SamdAggregator::vecAggregate(
    const crypto::CryptoProvider& crpProvider,
    const KsRsMatrix& matKsRs,
    const std::vector<crypto::Digest>& vecPacketMacs
)
{
    if (vecPacketMacs.empty() || vecPacketMacs.size() > matKsRs.nGroupSize())
    {
        throw std::invalid_argument("Packet MAC count is outside the KS+RS group size");
    }

    std::vector<crypto::Digest> vecSamdTau;
    vecSamdTau.reserve(matKsRs.nRowCount());

    // 每条矩阵行独立选择MAC子集并生成一个固定长度tau。
    for (std::size_t nRowIndex = 0; nRowIndex < matKsRs.nRowCount(); ++nRowIndex)
    {
        std::vector<crypto::Digest> vecRowMacs;

        for (std::size_t nColumnIndex = 0;
             nColumnIndex < vecPacketMacs.size();
             ++nColumnIndex)
        {
            if (matKsRs.bRowContains(nRowIndex, nColumnIndex))
            {
                vecRowMacs.push_back(vecPacketMacs[nColumnIndex]);
            }
        }

        vecSamdTau.push_back(digAggregateMacList(crpProvider, vecRowMacs));
    }

    return vecSamdTau;
}
}

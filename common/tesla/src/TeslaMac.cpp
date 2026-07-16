#include "tesla/core/TeslaMac.h"

#include "tesla/core/AuthenticationInputEncoder.h"
#include "tesla/crypto/CryptoUtilities.h"

#include <string>

namespace tesla::core
{
crypto::Digest TeslaMac::digComputeFastGroupTag(
    const crypto::CryptoProvider& crpProvider,
    const crypto::Digest& digDataKey,
    const AuthenticationGroupInput& grpInput,
    const std::vector<crypto::Digest>& vecSamdTau
)
{
    // 快速组标签使用独立派生密钥，并覆盖完整组输入及全部SAMD标签。
    const crypto::Digest digFastGroupKey = digDeriveFastGroupKey(crpProvider, digDataKey);
    const crypto::ByteBuffer vecFastGroupInput =
        AuthenticationInputEncoder::vecEncodeFastGroupInput(grpInput, vecSamdTau);

    return crpProvider.digHmac(
        crypto::CryptoUtilities::vecToByteBuffer(digFastGroupKey),
        vecFastGroupInput
    );
}

crypto::Digest TeslaMac::digComputePacketMac(
    const crypto::CryptoProvider& crpProvider,
    const crypto::Digest& digDataKey,
    const AuthenticationPacketInput& pktInput
)
{
    // 单包MAC使用F'(Ki)=H(Ki)派生密钥，避免直接复用披露的数据密钥。
    const crypto::Digest digPacketMacKey = digDerivePacketMacKey(crpProvider, digDataKey);
    const crypto::ByteBuffer vecMacInput =
        AuthenticationInputEncoder::vecEncodePacketMacInput(pktInput);

    return crpProvider.digHmac(
        crypto::CryptoUtilities::vecToByteBuffer(digPacketMacKey),
        vecMacInput
    );
}

crypto::Digest TeslaMac::digDeriveFastGroupKey(
    const crypto::CryptoProvider& crpProvider,
    const crypto::Digest& digDataKey
)
{
    // 固定域字符串把快速组标签密钥与逐包MAC密钥用途隔离。
    static const std::string strDomain = "FAST_GROUP_TAG";

    const crypto::Digest digPacketMacKey = digDerivePacketMacKey(crpProvider, digDataKey);
    const crypto::ByteBuffer vecDomain(strDomain.begin(), strDomain.end());

    return crpProvider.digHmac(
        crypto::CryptoUtilities::vecToByteBuffer(digPacketMacKey),
        vecDomain
    );
}

crypto::Digest TeslaMac::digDerivePacketMacKey(
    const crypto::CryptoProvider& crpProvider,
    const crypto::Digest& digDataKey
)
{
    return crpProvider.digHash(crypto::CryptoUtilities::vecToByteBuffer(digDataKey));
}
}

#include "tesla/core/AuthenticationAuthority.h"

#include "tesla/crypto/KeyChain.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"

#include <cstddef>
#include <stdexcept>
#include <utility>

namespace tesla::core
{
namespace
{
constexpr std::size_t CHAIN_ID_BYTE_COUNT = 8;
constexpr std::size_t MAX_RANDOM_ATTEMPTS = 128;
}

AuthenticationAuthority::AuthenticationAuthority(
    const crypto::SecureRandomProvider& rngSecureRandomProvider
)
    : m_rngSecureRandomProvider(rngSecureRandomProvider)
{
}

SenderAuthenticationMaterial AuthenticationAuthority::matIssueSenderMaterial(
    std::string strSenderId,
    AuthenticationRoundParameters prmRoundParameters
)
{
    std::lock_guard<std::mutex> lckIssuedMaterials(m_mtxIssuedMaterials);
    const crypto::OpenSslCryptoProvider crpProvider(
        prmRoundParameters.algCryptoAlgorithm()
    );

    for (std::size_t nAttempt = 0; nAttempt < MAX_RANDOM_ATTEMPTS; ++nAttempt)
    {
        const crypto::ByteBuffer vecChainIdBytes =
            m_rngSecureRandomProvider.vecGenerateBytes(CHAIN_ID_BYTE_COUNT);
        const std::uint64_t u64ChainId = u64DecodeChainId(vecChainIdBytes);

        if (u64ChainId == 0 || m_setIssuedChainIds.count(u64ChainId) != 0)
        {
            continue;
        }

        crypto::ByteBuffer vecSeed = m_rngSecureRandomProvider.vecGenerateBytes(
            SenderAuthenticationMaterial::CHAIN_SEED_SIZE
        );
        if (vecSeed.size() != SenderAuthenticationMaterial::CHAIN_SEED_SIZE)
        {
            throw std::runtime_error(
                "Secure random provider returned an invalid key-chain seed size"
            );
        }

        if (m_setIssuedSeeds.count(vecSeed) != 0)
        {
            continue;
        }

        // 完整链仅作为局部临时对象存在，取得K0后即释放，不进入CA持久状态。
        const crypto::KeyChain keyChain = crypto::KeyChain::keyCreate(
            crpProvider,
            vecSeed,
            prmRoundParameters.nDataIntervalCount()
        );
        const crypto::Digest digCommitmentKey = keyChain.digCommitmentKey();

        if (m_setIssuedCommitmentKeys.count(digCommitmentKey) != 0)
        {
            continue;
        }

        m_setIssuedChainIds.insert(u64ChainId);
        m_setIssuedSeeds.insert(vecSeed);
        m_setIssuedCommitmentKeys.insert(digCommitmentKey);

        return SenderAuthenticationMaterial(
            std::move(strSenderId),
            u64ChainId,
            std::move(vecSeed),
            digCommitmentKey,
            std::move(prmRoundParameters)
        );
    }

    throw std::runtime_error(
        "Unable to issue unique authentication material from secure random source"
    );
}

ReceiverAuthenticationContext AuthenticationAuthority::ctxCreateReceiverContext(
    const SenderAuthenticationMaterial& matMaterial,
    std::string strSenderIpAddress
) const
{
    if (matMaterial.prmRoundParameters().modePayload()
        != AuthenticationPayloadMode::Text)
    {
        throw std::invalid_argument(
            "File Receiver context requires its original byte count"
        );
    }

    return ctxCreateReceiverContext(
        matMaterial,
        std::move(strSenderIpAddress),
        TextReceiverPayloadDetails(
            matMaterial.prmRoundParameters().u32TotalPacketCount()
        )
    );
}

ReceiverAuthenticationContext AuthenticationAuthority::ctxCreateReceiverContext(
    const SenderAuthenticationMaterial& matMaterial,
    std::string strSenderIpAddress,
    ReceiverPayloadDetails varPayloadDetails
) const
{
    return ReceiverAuthenticationContext(
        matMaterial.strSenderId(),
        std::move(strSenderIpAddress),
        matMaterial.u64ChainId(),
        matMaterial.digCommitmentKey(),
        matMaterial.prmRoundParameters(),
        std::move(varPayloadDetails)
    );
}

std::uint64_t AuthenticationAuthority::u64DecodeChainId(
    const crypto::ByteBuffer& vecChainIdBytes
)
{
    if (vecChainIdBytes.size() != CHAIN_ID_BYTE_COUNT)
    {
        throw std::runtime_error(
            "Secure random provider returned an invalid chain ID byte count"
        );
    }

    std::uint64_t u64ChainId = 0;
    for (std::uint8_t u8Byte : vecChainIdBytes)
    {
        u64ChainId = (u64ChainId << 8U) | u8Byte;
    }

    return u64ChainId;
}
}

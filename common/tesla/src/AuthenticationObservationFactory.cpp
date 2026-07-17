#include "tesla/core/AuthenticationObservationFactory.h"

#include "tesla/crypto/OpenSslCryptoProvider.h"

#include <utility>
#include <variant>

namespace tesla::core
{
std::string AuthenticationObservationFactory::strCandidateHash(
    const protocol::ByteBuffer& vecRawDatagram
)
{
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";
    const crypto::OpenSslCryptoProvider crpProvider(
        crypto::CryptoAlgorithm::Sha256
    );
    const crypto::Digest digCandidate = crpProvider.digHash(vecRawDatagram);
    std::string strHash(digCandidate.size() * 2U, '0');

    for (std::size_t nIndex = 0; nIndex < digCandidate.size(); ++nIndex)
    {
        strHash[nIndex * 2U] =
            HEX_DIGITS[(digCandidate[nIndex] >> 4U) & 0x0FU];
        strHash[nIndex * 2U + 1U] =
            HEX_DIGITS[digCandidate[nIndex] & 0x0FU];
    }

    return strHash;
}

protocol::PacketPayloadObservationDetails
AuthenticationObservationFactory::varPayloadDetails(
    const protocol::UdpAuthenticationPacket& udpPacket
)
{
    if (!udpPacket.bIsDataPacket())
    {
        return protocol::DisclosurePacketObservationDetails(
            std::get<protocol::UdpDisclosurePacket>(
                udpPacket.varDetails()
            ).arrDisclosedKey()
        );
    }

    const protocol::UdpDataPacket& udpData = std::get<
        protocol::UdpDataPacket
    >(udpPacket.varDetails());
    protocol::PacketModeObservationDetails varModeDetails =
        protocol::NativePacketObservationDetails(protocol::BinaryBlock{});

    if (const auto* pNative = std::get_if<
            protocol::NativeUdpAuthenticationDetails
        >(&udpData.varAuthenticationDetails()))
    {
        varModeDetails = protocol::NativePacketObservationDetails(
            pNative->arrPacketMac()
        );
    }
    else
    {
        const protocol::ImprovedUdpAuthenticationDetails& detImproved =
            std::get<protocol::ImprovedUdpAuthenticationDetails>(
                udpData.varAuthenticationDetails()
            );
        std::vector<protocol::BinaryBlock> vecTau;
        std::optional<protocol::BinaryBlock> optFastGroupTag;
        if (detImproved.optGroupDetails().has_value())
        {
            vecTau = detImproved.optGroupDetails()->vecSamdTau();
            optFastGroupTag =
                detImproved.optGroupDetails()->arrFastGroupTag();
        }
        varModeDetails = protocol::ImprovedPacketObservationDetails(
            std::move(vecTau),
            std::move(optFastGroupTag)
        );
    }

    return protocol::DataPacketObservationDetails(
        udpData.arrMessage(),
        udpData.optDisclosedKey(),
        std::move(varModeDetails)
    );
}

protocol::AuthenticationCryptoAlgorithm AuthenticationObservationFactory::algMap(
    crypto::CryptoAlgorithm algAlgorithm
) noexcept
{
    switch (algAlgorithm)
    {
    case crypto::CryptoAlgorithm::Sha256:
        return protocol::AuthenticationCryptoAlgorithm::Sha256;
    case crypto::CryptoAlgorithm::Sm3:
        return protocol::AuthenticationCryptoAlgorithm::Sm3;
    case crypto::CryptoAlgorithm::Sha3_256:
        return protocol::AuthenticationCryptoAlgorithm::Sha3_256;
    }

    return protocol::AuthenticationCryptoAlgorithm::Sha256;
}

protocol::UdpAuthenticationMode AuthenticationObservationFactory::modeMap(
    TeslaAuthenticationMode modeAuthentication
) noexcept
{
    return modeAuthentication == TeslaAuthenticationMode::Native
        ? protocol::UdpAuthenticationMode::Native
        : protocol::UdpAuthenticationMode::Improved;
}
}

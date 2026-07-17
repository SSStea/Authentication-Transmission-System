#pragma once

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/protocol/MonitorControl.h"
#include "tesla/protocol/UdpAuthenticationPacket.h"

#include <string>

namespace tesla::core
{
/** @brief 将真实UDP报文映射为监控详情，并为候选版本计算固定SHA-256标识。 */
class AuthenticationObservationFactory final
{
public:
    static std::string strCandidateHash(
        const protocol::ByteBuffer& vecRawDatagram
    );
    static protocol::PacketPayloadObservationDetails varPayloadDetails(
        const protocol::UdpAuthenticationPacket& udpPacket
    );
    static protocol::AuthenticationCryptoAlgorithm algMap(
        crypto::CryptoAlgorithm algAlgorithm
    ) noexcept;
    static protocol::UdpAuthenticationMode modeMap(
        TeslaAuthenticationMode modeAuthentication
    ) noexcept;

private:
    AuthenticationObservationFactory() = delete;
};
}

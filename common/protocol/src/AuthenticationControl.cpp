#include "tesla/protocol/AuthenticationControl.h"

#include <array>
#include <cstddef>
#include <stdexcept>
#include <utility>

namespace tesla::protocol
{
namespace
{
void validateText(const std::string& strValue, const char* pName, bool bAllowEmpty = false)
{
    constexpr std::size_t MAX_TEXT_LENGTH = 1024;
    if ((!bAllowEmpty && strValue.empty()) || strValue.size() > MAX_TEXT_LENGTH)
    {
        throw std::invalid_argument(std::string(pName) + " has an invalid length");
    }
}

std::uint8_t u8DecodeHexCharacter(char chValue)
{
    if (chValue >= '0' && chValue <= '9')
    {
        return static_cast<std::uint8_t>(chValue - '0');
    }

    if (chValue >= 'a' && chValue <= 'f')
    {
        return static_cast<std::uint8_t>(chValue - 'a' + 10);
    }

    if (chValue >= 'A' && chValue <= 'F')
    {
        return static_cast<std::uint8_t>(chValue - 'A' + 10);
    }

    throw std::invalid_argument("Authentication hex value contains an invalid character");
}

std::string strEncodeBytes(const std::uint8_t* pBytes, std::size_t nByteCount)
{
    static constexpr std::array<char, 16> arrHex = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    std::string strResult;
    strResult.reserve(nByteCount * 2);

    for (std::size_t nIndex = 0; nIndex < nByteCount; ++nIndex)
    {
        const std::uint8_t u8Value = pBytes[nIndex];
        strResult.push_back(arrHex[(u8Value >> 4U) & 0x0FU]);
        strResult.push_back(arrHex[u8Value & 0x0FU]);
    }

    return strResult;
}
}

ImprovedTeslaControlParameters::ImprovedTeslaControlParameters(
    std::uint32_t u32GroupSize,
    std::uint32_t u32DetectionThreshold
)
    : m_u32GroupSize(u32GroupSize),
      m_u32DetectionThreshold(u32DetectionThreshold)
{
    if (m_u32GroupSize == 0 || m_u32DetectionThreshold == 0)
    {
        throw std::invalid_argument("Improved TESLA parameters must be positive");
    }
}

std::uint32_t ImprovedTeslaControlParameters::u32GroupSize() const noexcept
{
    return m_u32GroupSize;
}

std::uint32_t ImprovedTeslaControlParameters::u32DetectionThreshold() const noexcept
{
    return m_u32DetectionThreshold;
}

AuthenticationRoundControlParameters::AuthenticationRoundControlParameters(
    AuthenticationCryptoAlgorithm algCryptoAlgorithm,
    UdpAuthenticationMode modeAuthentication,
    std::uint32_t u32TotalPacketCount,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32DisclosureDelay,
    std::uint32_t u32IntervalMilliseconds,
    std::uint64_t u64StartTimestampMilliseconds,
    std::uint32_t u32ChainLength,
    std::optional<ImprovedTeslaControlParameters> optImprovedParameters
)
    : m_algCryptoAlgorithm(algCryptoAlgorithm),
      m_modeAuthentication(modeAuthentication),
      m_u32TotalPacketCount(u32TotalPacketCount),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u32IntervalMilliseconds(u32IntervalMilliseconds),
      m_u64StartTimestampMilliseconds(u64StartTimestampMilliseconds),
      m_u32ChainLength(u32ChainLength),
      m_optImprovedParameters(std::move(optImprovedParameters))
{
    if (m_u32TotalPacketCount == 0
        || m_u32PacketsPerInterval == 0
        || m_u32DisclosureDelay == 0
        || m_u32IntervalMilliseconds == 0
        || m_u32ChainLength < 2)
    {
        throw std::invalid_argument("Authentication round control values are invalid");
    }

    if (m_modeAuthentication == UdpAuthenticationMode::Native
        && m_optImprovedParameters.has_value())
    {
        throw std::invalid_argument("Native TESLA control must not contain improved values");
    }

    if (m_modeAuthentication == UdpAuthenticationMode::Improved
        && !m_optImprovedParameters.has_value())
    {
        throw std::invalid_argument("Improved TESLA control requires improved values");
    }
}

AuthenticationCryptoAlgorithm
AuthenticationRoundControlParameters::algCryptoAlgorithm() const noexcept
{
    return m_algCryptoAlgorithm;
}

UdpAuthenticationMode
AuthenticationRoundControlParameters::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

std::uint32_t AuthenticationRoundControlParameters::u32TotalPacketCount() const noexcept
{
    return m_u32TotalPacketCount;
}

std::uint32_t AuthenticationRoundControlParameters::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t AuthenticationRoundControlParameters::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint32_t
AuthenticationRoundControlParameters::u32IntervalMilliseconds() const noexcept
{
    return m_u32IntervalMilliseconds;
}

std::uint64_t
AuthenticationRoundControlParameters::u64StartTimestampMilliseconds() const noexcept
{
    return m_u64StartTimestampMilliseconds;
}

std::uint32_t AuthenticationRoundControlParameters::u32ChainLength() const noexcept
{
    return m_u32ChainLength;
}

const std::optional<ImprovedTeslaControlParameters>&
AuthenticationRoundControlParameters::optImprovedParameters() const noexcept
{
    return m_optImprovedParameters;
}

SenderAuthenticationConfigControlDetails::SenderAuthenticationConfigControlDetails(
    std::string strRequestId,
    std::string strSenderId,
    std::uint64_t u64ChainId,
    BinaryBlock arrChainSeed,
    BinaryBlock arrCommitmentKey,
    AuthenticationRoundControlParameters prmRoundParameters
)
    : m_strRequestId(std::move(strRequestId)),
      m_strSenderId(std::move(strSenderId)),
      m_u64ChainId(u64ChainId),
      m_arrChainSeed(std::move(arrChainSeed)),
      m_arrCommitmentKey(std::move(arrCommitmentKey)),
      m_prmRoundParameters(std::move(prmRoundParameters))
{
    validateText(m_strRequestId, "Control request ID");
    validateText(m_strSenderId, "Sender ID");

    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Sender authentication chain ID must not be zero");
    }
}

const std::string&
SenderAuthenticationConfigControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::string&
SenderAuthenticationConfigControlDetails::strSenderId() const noexcept
{
    return m_strSenderId;
}

std::uint64_t SenderAuthenticationConfigControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const BinaryBlock&
SenderAuthenticationConfigControlDetails::arrChainSeed() const noexcept
{
    return m_arrChainSeed;
}

const BinaryBlock&
SenderAuthenticationConfigControlDetails::arrCommitmentKey() const noexcept
{
    return m_arrCommitmentKey;
}

const AuthenticationRoundControlParameters&
SenderAuthenticationConfigControlDetails::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}

ReceiverAuthenticationContextControlDetails::
ReceiverAuthenticationContextControlDetails(
    std::string strSenderId,
    std::string strSenderIpAddress,
    std::uint64_t u64ChainId,
    BinaryBlock arrCommitmentKey,
    AuthenticationRoundControlParameters prmRoundParameters
)
    : m_strSenderId(std::move(strSenderId)),
      m_strSenderIpAddress(std::move(strSenderIpAddress)),
      m_u64ChainId(u64ChainId),
      m_arrCommitmentKey(std::move(arrCommitmentKey)),
      m_prmRoundParameters(std::move(prmRoundParameters))
{
    validateText(m_strSenderId, "Receiver context sender ID");
    validateText(m_strSenderIpAddress, "Receiver context sender IP");

    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Receiver authentication chain ID must not be zero");
    }
}

const std::string&
ReceiverAuthenticationContextControlDetails::strSenderId() const noexcept
{
    return m_strSenderId;
}

const std::string&
ReceiverAuthenticationContextControlDetails::strSenderIpAddress() const noexcept
{
    return m_strSenderIpAddress;
}

std::uint64_t
ReceiverAuthenticationContextControlDetails::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const BinaryBlock&
ReceiverAuthenticationContextControlDetails::arrCommitmentKey() const noexcept
{
    return m_arrCommitmentKey;
}

const AuthenticationRoundControlParameters&
ReceiverAuthenticationContextControlDetails::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}

ReceiverAuthenticationContextsControlDetails::
ReceiverAuthenticationContextsControlDetails(
    std::string strRequestId,
    std::vector<ReceiverAuthenticationContextControlDetails> vecContexts
)
    : m_strRequestId(std::move(strRequestId)),
      m_vecContexts(std::move(vecContexts))
{
    validateText(m_strRequestId, "Control request ID");

    if (m_vecContexts.empty())
    {
        throw std::invalid_argument(
            "Receiver authentication configuration must contain at least one context"
        );
    }
}

const std::string&
ReceiverAuthenticationContextsControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

const std::vector<ReceiverAuthenticationContextControlDetails>&
ReceiverAuthenticationContextsControlDetails::vecContexts() const noexcept
{
    return m_vecContexts;
}

AuthenticationConfigAcknowledgementControlDetails::
AuthenticationConfigAcknowledgementControlDetails(
    std::string strRequestId,
    AuthenticationConfigTarget targetConfig,
    bool bAccepted,
    std::string strErrorCode,
    std::string strMessage
)
    : m_strRequestId(std::move(strRequestId)),
      m_targetConfig(targetConfig),
      m_bAccepted(bAccepted),
      m_strErrorCode(std::move(strErrorCode)),
      m_strMessage(std::move(strMessage))
{
    validateText(m_strRequestId, "Control request ID");
    validateText(m_strErrorCode, "Authentication config error code", m_bAccepted);
    validateText(m_strMessage, "Authentication config acknowledgement message");

    if (m_bAccepted && !m_strErrorCode.empty())
    {
        throw std::invalid_argument(
            "Accepted authentication configuration must not contain an error code"
        );
    }
}

const std::string&
AuthenticationConfigAcknowledgementControlDetails::strRequestId() const noexcept
{
    return m_strRequestId;
}

AuthenticationConfigTarget
AuthenticationConfigAcknowledgementControlDetails::targetConfig() const noexcept
{
    return m_targetConfig;
}

bool AuthenticationConfigAcknowledgementControlDetails::bAccepted() const noexcept
{
    return m_bAccepted;
}

const std::string&
AuthenticationConfigAcknowledgementControlDetails::strErrorCode() const noexcept
{
    return m_strErrorCode;
}

const std::string&
AuthenticationConfigAcknowledgementControlDetails::strMessage() const noexcept
{
    return m_strMessage;
}

std::string AuthenticationControlValueCodec::strEncodeChainId(
    std::uint64_t u64ChainId
)
{
    std::array<std::uint8_t, 8> arrBytes{};
    for (std::size_t nIndex = 0; nIndex < arrBytes.size(); ++nIndex)
    {
        const std::size_t nShift = (arrBytes.size() - 1U - nIndex) * 8U;
        arrBytes[nIndex] = static_cast<std::uint8_t>(u64ChainId >> nShift);
    }

    return strEncodeBytes(arrBytes.data(), arrBytes.size());
}

std::uint64_t AuthenticationControlValueCodec::u64DecodeChainId(
    const std::string& strChainId
)
{
    if (strChainId.size() != 16)
    {
        throw std::invalid_argument(
            "Authentication chain ID must contain 16 hex characters"
        );
    }

    std::uint64_t u64Result = 0;
    for (char chValue : strChainId)
    {
        u64Result = (u64Result << 4U) | u8DecodeHexCharacter(chValue);
    }

    return u64Result;
}

std::string AuthenticationControlValueCodec::strEncodeBlock(
    const BinaryBlock& arrBlock
)
{
    return strEncodeBytes(arrBlock.data(), arrBlock.size());
}

BinaryBlock AuthenticationControlValueCodec::arrDecodeBlock(
    const std::string& strBlock
)
{
    if (strBlock.size() != BINARY_BLOCK_SIZE * 2)
    {
        throw std::invalid_argument(
            "Authentication binary block must contain exactly 64 hex characters"
        );
    }

    BinaryBlock arrResult{};
    for (std::size_t nIndex = 0; nIndex < arrResult.size(); ++nIndex)
    {
        const std::uint8_t u8High = u8DecodeHexCharacter(strBlock[nIndex * 2]);
        const std::uint8_t u8Low = u8DecodeHexCharacter(strBlock[nIndex * 2 + 1]);
        arrResult[nIndex] = static_cast<std::uint8_t>((u8High << 4U) | u8Low);
    }

    return arrResult;
}
}

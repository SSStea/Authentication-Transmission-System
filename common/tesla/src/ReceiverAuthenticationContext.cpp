#include "tesla/core/ReceiverAuthenticationContext.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
ReceiverAuthenticationContext::ReceiverAuthenticationContext(
    std::string strSenderId,
    std::string strSenderIpAddress,
    std::uint64_t u64ChainId,
    crypto::Digest digCommitmentKey,
    AuthenticationRoundParameters prmRoundParameters
)
    : m_strSenderId(std::move(strSenderId)),
      m_strSenderIpAddress(std::move(strSenderIpAddress)),
      m_u64ChainId(u64ChainId),
      m_digCommitmentKey(std::move(digCommitmentKey)),
      m_prmRoundParameters(std::move(prmRoundParameters))
{
    if (m_strSenderId.empty())
    {
        throw std::invalid_argument("Receiver context sender ID must not be empty");
    }

    if (m_strSenderIpAddress.empty())
    {
        throw std::invalid_argument("Receiver context sender IP address must not be empty");
    }

    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Receiver context chain ID must not be zero");
    }
}

const std::string& ReceiverAuthenticationContext::strSenderId() const noexcept
{
    return m_strSenderId;
}

const std::string& ReceiverAuthenticationContext::strSenderIpAddress() const noexcept
{
    return m_strSenderIpAddress;
}

std::uint64_t ReceiverAuthenticationContext::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const crypto::Digest& ReceiverAuthenticationContext::digCommitmentKey() const noexcept
{
    return m_digCommitmentKey;
}

const AuthenticationRoundParameters&
ReceiverAuthenticationContext::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}
}

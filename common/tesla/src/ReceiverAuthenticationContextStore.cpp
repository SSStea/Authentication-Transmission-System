#include "tesla/core/ReceiverAuthenticationContextStore.h"

#include "tesla/workload/FileWorkload.h"

#include <stdexcept>
#include <utility>

namespace tesla::core
{
TextReceiverPayloadDetails::TextReceiverPayloadDetails(
    std::uint32_t u32RepeatCount
)
    : m_u32RepeatCount(u32RepeatCount)
{
    if (m_u32RepeatCount == 0)
    {
        throw std::invalid_argument("Text Receiver repeat count must be positive");
    }
}

std::uint32_t TextReceiverPayloadDetails::u32RepeatCount() const noexcept
{
    return m_u32RepeatCount;
}

FileReceiverPayloadDetails::FileReceiverPayloadDetails(
    std::uint64_t u64OriginalByteCount
)
    : m_u64OriginalByteCount(u64OriginalByteCount)
{
    if (m_u64OriginalByteCount == 0
        || m_u64OriginalByteCount > workload::FileWorkload::MAXIMUM_FILE_SIZE)
    {
        throw std::invalid_argument(
            "File Receiver byte count is outside the bounded range"
        );
    }
}

std::uint64_t FileReceiverPayloadDetails::u64OriginalByteCount() const noexcept
{
    return m_u64OriginalByteCount;
}

ReceiverAuthenticationContext::ReceiverAuthenticationContext(
    std::string strSenderId,
    std::string strSenderIpAddress,
    std::uint64_t u64ChainId,
    crypto::Digest digCommitmentKey,
    AuthenticationRoundParameters prmRoundParameters,
    ReceiverPayloadDetails varPayloadDetails
)
    : m_strSenderId(std::move(strSenderId)),
      m_strSenderIpAddress(std::move(strSenderIpAddress)),
      m_u64ChainId(u64ChainId),
      m_digCommitmentKey(std::move(digCommitmentKey)),
      m_prmRoundParameters(std::move(prmRoundParameters)),
      m_varPayloadDetails(std::move(varPayloadDetails))
{
    if (m_strSenderId.empty())
    {
        throw std::invalid_argument("Receiver context sender ID must not be empty");
    }

    if (m_strSenderIpAddress.empty())
    {
        throw std::invalid_argument(
            "Receiver context sender IP address must not be empty"
        );
    }

    if (m_u64ChainId == 0)
    {
        throw std::invalid_argument("Receiver context chain ID must not be zero");
    }

    if (std::holds_alternative<TextReceiverPayloadDetails>(m_varPayloadDetails))
    {
        const std::uint32_t u32RepeatCount = std::get<TextReceiverPayloadDetails>(
            m_varPayloadDetails
        ).u32RepeatCount();
        if (m_prmRoundParameters.modePayload() != AuthenticationPayloadMode::Text
            || u32RepeatCount != m_prmRoundParameters.u32TotalPacketCount())
        {
            throw std::invalid_argument(
                "Text Receiver payload does not match its round parameters"
            );
        }
    }
    else
    {
        const std::uint64_t u64OriginalByteCount = std::get<
            FileReceiverPayloadDetails
        >(m_varPayloadDetails).u64OriginalByteCount();
        const std::uint64_t u64PacketCount =
            (u64OriginalByteCount + workload::FileWorkload::MESSAGE_SIZE - 1U)
            / workload::FileWorkload::MESSAGE_SIZE;
        if (m_prmRoundParameters.modePayload() != AuthenticationPayloadMode::File
            || u64PacketCount != m_prmRoundParameters.u32TotalPacketCount())
        {
            throw std::invalid_argument(
                "File Receiver payload does not match its round parameters"
            );
        }
    }
}

const std::string& ReceiverAuthenticationContext::strSenderId() const noexcept
{
    return m_strSenderId;
}

const std::string&
ReceiverAuthenticationContext::strSenderIpAddress() const noexcept
{
    return m_strSenderIpAddress;
}

std::uint64_t ReceiverAuthenticationContext::u64ChainId() const noexcept
{
    return m_u64ChainId;
}

const crypto::Digest&
ReceiverAuthenticationContext::digCommitmentKey() const noexcept
{
    return m_digCommitmentKey;
}

const AuthenticationRoundParameters&
ReceiverAuthenticationContext::prmRoundParameters() const noexcept
{
    return m_prmRoundParameters;
}

const ReceiverPayloadDetails&
ReceiverAuthenticationContext::varPayloadDetails() const noexcept
{
    return m_varPayloadDetails;
}

void ReceiverAuthenticationContextStore::replaceAll(
    std::vector<ReceiverAuthenticationContext> vecContexts
)
{
    std::map<std::string, std::string> mapSenderIdByIpAddress;
    std::map<std::string, std::string> mapIpAddressBySenderId;
    std::map<SenderChainKey, ReceiverAuthenticationContext> mapContextBySenderChain;

    // 所有映射先在局部容器验证，任何一个冲突都不会影响当前正在使用的上下文。
    for (ReceiverAuthenticationContext& ctxContext : vecContexts)
    {
        const std::string& strSenderId = ctxContext.strSenderId();
        const std::string& strIpAddress = ctxContext.strSenderIpAddress();

        const auto [itrIp, bIpInserted] = mapSenderIdByIpAddress.emplace(
            strIpAddress,
            strSenderId
        );
        if (!bIpInserted && itrIp->second != strSenderId)
        {
            throw std::invalid_argument(
                "One source IP address cannot map to multiple sender IDs"
            );
        }

        const auto [itrSender, bSenderInserted] = mapIpAddressBySenderId.emplace(
            strSenderId,
            strIpAddress
        );
        if (!bSenderInserted && itrSender->second != strIpAddress)
        {
            throw std::invalid_argument(
                "One sender ID cannot map to multiple source IP addresses"
            );
        }

        const SenderChainKey keyContext(strSenderId, ctxContext.u64ChainId());
        const auto [itrContext, bContextInserted] = mapContextBySenderChain.emplace(
            keyContext,
            std::move(ctxContext)
        );
        static_cast<void>(itrContext);

        if (!bContextInserted)
        {
            throw std::invalid_argument(
                "Receiver authentication contexts contain a duplicate sender-chain pair"
            );
        }
    }

    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    m_mapSenderIdByIpAddress.swap(mapSenderIdByIpAddress);
    m_mapIpAddressBySenderId.swap(mapIpAddressBySenderId);
    m_mapContextBySenderChain.swap(mapContextBySenderChain);
}

ReceiverAuthenticationContextLookupResult ReceiverAuthenticationContextStore::resFind(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    const auto itrSender = m_mapSenderIdByIpAddress.find(strSourceIpAddress);

    // 必须先通过实际来源IP确定Sender，不能信任报文内自报的senderId。
    if (itrSender == m_mapSenderIdByIpAddress.end())
    {
        return ReceiverAuthenticationContextLookupError::UnknownSourceIp;
    }

    const auto itrContext = m_mapContextBySenderChain.find(
        SenderChainKey(itrSender->second, u64ChainId)
    );
    if (itrContext == m_mapContextBySenderChain.end())
    {
        return ReceiverAuthenticationContextLookupError::UnknownChainId;
    }

    return itrContext->second;
}

std::size_t ReceiverAuthenticationContextStore::nSize() const
{
    std::lock_guard<std::mutex> lckContexts(m_mtxContexts);
    return m_mapContextBySenderChain.size();
}
}

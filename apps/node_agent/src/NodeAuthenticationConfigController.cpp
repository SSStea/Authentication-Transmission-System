#include "tesla/node_agent/NodeAuthenticationConfigController.h"

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/core/ImprovedTeslaParameters.h"
#include "tesla/core/SenderAuthenticationMaterial.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"

#include <algorithm>
#include <exception>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

namespace tesla::node_agent
{
namespace
{
crypto::CryptoAlgorithm algMap(
    protocol::AuthenticationCryptoAlgorithm algControl
)
{
    switch (algControl)
    {
    case protocol::AuthenticationCryptoAlgorithm::Sha256:
        return crypto::CryptoAlgorithm::Sha256;
    case protocol::AuthenticationCryptoAlgorithm::Sm3:
        return crypto::CryptoAlgorithm::Sm3;
    case protocol::AuthenticationCryptoAlgorithm::Sha3_256:
        return crypto::CryptoAlgorithm::Sha3_256;
    }

    throw std::invalid_argument("Unsupported authentication crypto algorithm");
}

core::TeslaAuthenticationMode modeMap(
    protocol::UdpAuthenticationMode modeControl
)
{
    return modeControl == protocol::UdpAuthenticationMode::Native
        ? core::TeslaAuthenticationMode::Native
        : core::TeslaAuthenticationMode::Improved;
}

core::AuthenticationRoundParameters prmMap(
    const protocol::AuthenticationRoundControlParameters& prmControl
)
{
    std::optional<core::ImprovedTeslaParameters> optImprovedParameters;
    if (prmControl.optImprovedParameters().has_value())
    {
        const protocol::ImprovedTeslaControlParameters& prmImproved =
            prmControl.optImprovedParameters().value();
        optImprovedParameters.emplace(
            prmImproved.u32GroupSize(),
            prmImproved.u32DetectionThreshold()
        );
    }

    core::AuthenticationRoundParameters prmResult(
        algMap(prmControl.algCryptoAlgorithm()),
        modeMap(prmControl.modeAuthentication()),
        prmControl.u32TotalPacketCount(),
        prmControl.u32PacketsPerInterval(),
        prmControl.u32DisclosureDelay(),
        prmControl.u32IntervalMilliseconds(),
        prmControl.u64StartTimestampMilliseconds(),
        std::move(optImprovedParameters)
    );

    // chainLength由本地可信公式重新计算，不能直接采用远端传入值。
    if (prmResult.u32ChainLength() != prmControl.u32ChainLength())
    {
        throw std::invalid_argument(
            "Configured key-chain length does not match packet schedule"
        );
    }

    return prmResult;
}

crypto::Digest digMap(const protocol::BinaryBlock& arrBlock)
{
    crypto::Digest digResult{};
    std::copy(arrBlock.begin(), arrBlock.end(), digResult.begin());
    return digResult;
}

crypto::ByteBuffer vecMap(const protocol::BinaryBlock& arrBlock)
{
    return crypto::ByteBuffer(arrBlock.begin(), arrBlock.end());
}

protocol::NodeControlMessage msgAcknowledgement(
    const std::string& strRequestId,
    protocol::AuthenticationConfigTarget targetConfig,
    bool bAccepted,
    std::string strErrorCode,
    std::string strMessage
)
{
    return protocol::NodeControlMessage(
        protocol::AuthenticationConfigAcknowledgementControlDetails(
            strRequestId,
            targetConfig,
            bAccepted,
            std::move(strErrorCode),
            std::move(strMessage)
        )
    );
}
}

NodeAuthenticationConfigController::NodeAuthenticationConfigController(
    std::string strNodeName
)
    : m_strNodeName(std::move(strNodeName))
{
    if (m_strNodeName.empty())
    {
        throw std::invalid_argument(
            "Authentication config controller requires a node name"
        );
    }
}

protocol::NodeControlMessage NodeAuthenticationConfigController::msgHandle(
    protocol::TcpClientRole roleClient,
    const protocol::NodeControlMessage& msgMessage
)
{
    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::SenderAuthenticationConfig)
    {
        const protocol::SenderAuthenticationConfigControlDetails& detConfig =
            std::get<protocol::SenderAuthenticationConfigControlDetails>(
                msgMessage.varDetails()
            );

        if (roleClient == protocol::TcpClientRole::Monitor)
        {
            return msgAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Sender,
                false,
                "MONITOR_CONFIG_FORBIDDEN",
                "Monitor clients cannot change authentication configuration"
            );
        }

        return msgApplySenderConfig(detConfig);
    }

    if (msgMessage.typeMessage()
        == protocol::NodeControlMessageType::ReceiverAuthenticationContexts)
    {
        const protocol::ReceiverAuthenticationContextsControlDetails& detConfig =
            std::get<protocol::ReceiverAuthenticationContextsControlDetails>(
                msgMessage.varDetails()
            );

        if (roleClient == protocol::TcpClientRole::Monitor)
        {
            return msgAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Receiver,
                false,
                "MONITOR_CONFIG_FORBIDDEN",
                "Monitor clients cannot change authentication configuration"
            );
        }

        return msgApplyReceiverConfig(detConfig);
    }

    return protocol::NodeControlMessage(protocol::ErrorResponseControlDetails(
        "",
        "UNSUPPORTED_AUTH_CONFIG",
        "Authentication config controller received an unsupported message"
    ));
}

bool NodeAuthenticationConfigController::bHasSenderContext() const
{
    std::lock_guard<std::mutex> lckSenderContext(m_mtxSenderContext);
    return m_optSenderContext.has_value();
}

std::optional<std::uint64_t>
NodeAuthenticationConfigController::optSenderChainId() const
{
    std::lock_guard<std::mutex> lckSenderContext(m_mtxSenderContext);
    if (!m_optSenderContext.has_value())
    {
        return std::nullopt;
    }

    return m_optSenderContext->matMaterial().u64ChainId();
}

std::size_t NodeAuthenticationConfigController::nReceiverContextCount() const
{
    return m_stoReceiverContexts.nSize();
}

core::ReceiverAuthenticationContextLookupResult
NodeAuthenticationConfigController::resFindReceiverContext(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    return m_stoReceiverContexts.resFind(strSourceIpAddress, u64ChainId);
}

protocol::NodeControlMessage
NodeAuthenticationConfigController::msgApplySenderConfig(
    const protocol::SenderAuthenticationConfigControlDetails& detConfig
)
{
    try
    {
        if (detConfig.strSenderId() != m_strNodeName)
        {
            throw std::invalid_argument(
                "Sender authentication configuration targets another node"
            );
        }

        core::AuthenticationRoundParameters prmParameters = prmMap(
            detConfig.prmRoundParameters()
        );
        const crypto::OpenSslCryptoProvider crpProvider(
            prmParameters.algCryptoAlgorithm()
        );
        core::SenderAuthenticationContext ctxCandidate =
            core::SenderAuthenticationContext::ctxCreateVerified(
                core::SenderAuthenticationMaterial(
                    detConfig.strSenderId(),
                    detConfig.u64ChainId(),
                    vecMap(detConfig.arrChainSeed()),
                    digMap(detConfig.arrCommitmentKey()),
                    std::move(prmParameters)
                ),
                crpProvider
            );

        // 候选上下文完全验证后才进入短临界区替换旧配置。
        {
            std::lock_guard<std::mutex> lckSenderContext(m_mtxSenderContext);
            m_optSenderContext = std::move(ctxCandidate);
        }

        return msgAcknowledgement(
            detConfig.strRequestId(),
            protocol::AuthenticationConfigTarget::Sender,
            true,
            "",
            "Sender authentication configuration accepted"
        );
    }
    catch (const std::exception& exError)
    {
        return msgAcknowledgement(
            detConfig.strRequestId(),
            protocol::AuthenticationConfigTarget::Sender,
            false,
            "INVALID_AUTH_CONFIG",
            exError.what()
        );
    }
}

protocol::NodeControlMessage
NodeAuthenticationConfigController::msgApplyReceiverConfig(
    const protocol::ReceiverAuthenticationContextsControlDetails& detConfig
)
{
    try
    {
        std::vector<core::ReceiverAuthenticationContext> vecCandidateContexts;
        vecCandidateContexts.reserve(detConfig.vecContexts().size());

        for (const protocol::ReceiverAuthenticationContextControlDetails& detContext
            : detConfig.vecContexts())
        {
            vecCandidateContexts.emplace_back(
                detContext.strSenderId(),
                detContext.strSenderIpAddress(),
                detContext.u64ChainId(),
                digMap(detContext.arrCommitmentKey()),
                prmMap(detContext.prmRoundParameters())
            );
        }

        // Store内部也采用候选映射整体交换，保证多Sender配置原子生效。
        m_stoReceiverContexts.replaceAll(std::move(vecCandidateContexts));

        return msgAcknowledgement(
            detConfig.strRequestId(),
            protocol::AuthenticationConfigTarget::Receiver,
            true,
            "",
            "Receiver authentication contexts accepted"
        );
    }
    catch (const std::exception& exError)
    {
        return msgAcknowledgement(
            detConfig.strRequestId(),
            protocol::AuthenticationConfigTarget::Receiver,
            false,
            "INVALID_AUTH_CONFIG",
            exError.what()
        );
    }
}
}

#include "tesla/core/AuthenticationNodeRuntime.h"

#include "tesla/core/AuthenticationReceiverRuntime.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/core/AuthenticationSenderRuntime.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/protocol/AuthenticationControl.h"
#include "tesla/workload/TextWorkload.h"

#include <algorithm>
#include <exception>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
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

TeslaAuthenticationMode modeMap(protocol::UdpAuthenticationMode modeControl)
{
    return modeControl == protocol::UdpAuthenticationMode::Native
        ? TeslaAuthenticationMode::Native
        : TeslaAuthenticationMode::Improved;
}

AuthenticationPayloadMode modePayloadMap(
    protocol::AuthenticationPayloadMode modeControl
)
{
    return modeControl == protocol::AuthenticationPayloadMode::Text
        ? AuthenticationPayloadMode::Text
        : AuthenticationPayloadMode::File;
}

AuthenticationRoundParameters prmMap(
    const protocol::AuthenticationRoundControlParameters& prmControl
)
{
    std::optional<ImprovedTeslaParameters> optImprovedParameters;
    if (prmControl.optImprovedParameters().has_value())
    {
        const protocol::ImprovedTeslaControlParameters& prmImproved =
            prmControl.optImprovedParameters().value();
        optImprovedParameters.emplace(
            prmImproved.u32GroupSize(),
            prmImproved.u32DetectionThreshold()
        );
    }

    AuthenticationRoundParameters prmResult(
        algMap(prmControl.algCryptoAlgorithm()),
        modeMap(prmControl.modeAuthentication()),
        prmControl.u32TotalPacketCount(),
        prmControl.u32PacketsPerInterval(),
        prmControl.u32DisclosureDelay(),
        prmControl.u32IntervalMilliseconds(),
        prmControl.u64StartTimestampMilliseconds(),
        std::move(optImprovedParameters),
        modePayloadMap(prmControl.modePayload())
    );

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

protocol::AuthenticationRoundResultStatus statusMap(
    AuthenticationRuntimeResultStatus statusResult
)
{
    switch (statusResult)
    {
    case AuthenticationRuntimeResultStatus::Completed:
        return protocol::AuthenticationRoundResultStatus::Completed;
    case AuthenticationRuntimeResultStatus::AuthenticationFailed:
        return protocol::AuthenticationRoundResultStatus::AuthenticationFailed;
    case AuthenticationRuntimeResultStatus::VerificationTimeout:
        return protocol::AuthenticationRoundResultStatus::VerificationTimeout;
    case AuthenticationRuntimeResultStatus::InvalidSchedulingOverrun:
        return protocol::AuthenticationRoundResultStatus::
            InvalidSchedulingOverrun;
    case AuthenticationRuntimeResultStatus::Stopped:
        return protocol::AuthenticationRoundResultStatus::Stopped;
    case AuthenticationRuntimeResultStatus::ProtocolIncomplete:
        return protocol::AuthenticationRoundResultStatus::ProtocolIncomplete;
    case AuthenticationRuntimeResultStatus::TimeUnsynchronized:
        return protocol::AuthenticationRoundResultStatus::TimeUnsynchronized;
    }

    throw std::invalid_argument("Unknown authentication runtime result status");
}

protocol::NodeControlMessage msgConfigAcknowledgement(
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

protocol::NodeControlMessage msgRoundAcknowledgement(
    const protocol::AuthenticationRoundCommandControlDetails& detCommand,
    bool bAccepted,
    std::string strErrorCode,
    std::string strMessage
)
{
    return protocol::NodeControlMessage(
        protocol::AuthenticationRoundAcknowledgementControlDetails(
            detCommand.strRequestId(),
            detCommand.strRoundId(),
            detCommand.cmdCommand(),
            bAccepted,
            std::move(strErrorCode),
            std::move(strMessage)
        )
    );
}
}

class AuthenticationNodeRuntime::Impl final
{
public:
    Impl(
        std::string strNodeName,
        DatagramSender fnDatagramSender,
        ControlEventHandler fnControlEventHandler,
        TimeSynchronizationProvider fnTimeSynchronizationProvider
    )
        : m_strNodeName(std::move(strNodeName)),
          m_fnControlEventHandler(std::move(fnControlEventHandler)),
          m_fnTimeSynchronizationProvider(
              std::move(fnTimeSynchronizationProvider)
          ),
          m_runSender(
              std::move(fnDatagramSender),
              [this](const AuthenticationRuntimeResult& resResult)
              {
                  emitResult(
                      resResult,
                      protocol::AuthenticationRoundResultRole::Sender
                  );
              }
          ),
          m_runReceiver(
              [this](const AuthenticationRuntimeResult& resResult)
              {
                  emitResult(
                      resResult,
                      protocol::AuthenticationRoundResultRole::Receiver
                  );
              }
          )
    {
        if (m_strNodeName.empty()
            || !m_fnControlEventHandler
            || !m_fnTimeSynchronizationProvider)
        {
            throw std::invalid_argument(
                "Authentication node runtime requires identity and callbacks"
            );
        }
    }

    protocol::NodeControlMessage msgHandleControl(
        protocol::TcpClientRole roleClient,
        const protocol::NodeControlMessage& msgMessage
    )
    {
        if (bIsMutationMessage(msgMessage.typeMessage())
            && roleClient == protocol::TcpClientRole::Monitor)
        {
            // 权限检查先于配置解析和状态机调用，MONITOR不能触发任何写操作。
            if (msgMessage.typeMessage()
                == protocol::NodeControlMessageType::SenderAuthenticationConfig)
            {
                const auto& detConfig = std::get<
                    protocol::SenderAuthenticationConfigControlDetails
                >(msgMessage.varDetails());
                return msgConfigAcknowledgement(
                    detConfig.strRequestId(),
                    protocol::AuthenticationConfigTarget::Sender,
                    false,
                    "MONITOR_CONFIG_FORBIDDEN",
                    "Monitor clients cannot change sender authentication state"
                );
            }

            if (msgMessage.typeMessage()
                == protocol::NodeControlMessageType::ReceiverAuthenticationContexts)
            {
                const auto& detConfig = std::get<
                    protocol::ReceiverAuthenticationContextsControlDetails
                >(msgMessage.varDetails());
                return msgConfigAcknowledgement(
                    detConfig.strRequestId(),
                    protocol::AuthenticationConfigTarget::Receiver,
                    false,
                    "MONITOR_CONFIG_FORBIDDEN",
                    "Monitor clients cannot change receiver authentication state"
                );
            }

            if (msgMessage.typeMessage()
                == protocol::NodeControlMessageType::TextPayloadConfig)
            {
                const auto& detPayload = std::get<
                    protocol::TextPayloadControlDetails
                >(msgMessage.varDetails());
                return msgConfigAcknowledgement(
                    detPayload.strRequestId(),
                    protocol::AuthenticationConfigTarget::TextPayload,
                    false,
                    "MONITOR_CONFIG_FORBIDDEN",
                    "Monitor clients cannot change the authentication payload"
                );
            }

            const auto& detCommand = std::get<
                protocol::AuthenticationRoundCommandControlDetails
            >(msgMessage.varDetails());
            return msgRoundAcknowledgement(
                detCommand,
                false,
                "MONITOR_CONTROL_FORBIDDEN",
                "Monitor clients cannot control authentication rounds"
            );
        }

        switch (msgMessage.typeMessage())
        {
        case protocol::NodeControlMessageType::SenderAuthenticationConfig:
            return msgApplySenderConfig(std::get<
                protocol::SenderAuthenticationConfigControlDetails
            >(msgMessage.varDetails()));
        case protocol::NodeControlMessageType::ReceiverAuthenticationContexts:
            return msgApplyReceiverConfig(std::get<
                protocol::ReceiverAuthenticationContextsControlDetails
            >(msgMessage.varDetails()));
        case protocol::NodeControlMessageType::TextPayloadConfig:
            return msgApplyTextPayload(std::get<
                protocol::TextPayloadControlDetails
            >(msgMessage.varDetails()));
        case protocol::NodeControlMessageType::RoundStart:
        case protocol::NodeControlMessageType::RoundPause:
        case protocol::NodeControlMessageType::RoundResume:
        case protocol::NodeControlMessageType::RoundStop:
            return msgApplyRoundCommand(std::get<
                protocol::AuthenticationRoundCommandControlDetails
            >(msgMessage.varDetails()));
        default:
            return protocol::NodeControlMessage(
                protocol::ErrorResponseControlDetails(
                    "",
                    "UNSUPPORTED_AUTH_CONTROL",
                    "Authentication runtime received an unsupported control message"
                )
            );
        }
    }

    bool bHandleDatagram(
        const std::string& strSourceIpAddress,
        const protocol::ByteBuffer& vecDatagram,
        std::uint64_t u64ReceiveTimestampMilliseconds
    )
    {
        return m_runReceiver.bEnqueueDatagram(
            strSourceIpAddress,
            vecDatagram,
            u64ReceiveTimestampMilliseconds
        );
    }

    void stop() noexcept
    {
        m_runSender.stop();
        m_runReceiver.stop();
    }

    bool bHasSenderContext() const
    {
        std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
        return m_optSenderContext.has_value();
    }

    std::optional<std::uint64_t> optSenderChainId() const
    {
        std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
        return m_optSenderContext.has_value()
            ? std::optional<std::uint64_t>(
                m_optSenderContext->matMaterial().u64ChainId()
            )
            : std::nullopt;
    }

    bool bSenderRunning() const
    {
        return m_runSender.bIsRunning();
    }

    bool bReceiverRoundRunning() const
    {
        return m_runReceiver.bIsRunning();
    }

    bool bRoundPaused() const
    {
        return m_runSender.bIsPaused() || m_runReceiver.bIsPaused();
    }

    std::size_t nReceiverContextCount() const
    {
        return m_runReceiver.nContextCount();
    }

    std::size_t nDroppedReceiverQueueDatagramCount() const
    {
        return m_runReceiver.nDroppedQueueDatagramCount();
    }

    ReceiverAuthenticationContextLookupResult resFindReceiverContext(
        const std::string& strSourceIpAddress,
        std::uint64_t u64ChainId
    ) const
    {
        return m_runReceiver.resFindContext(
            strSourceIpAddress,
            u64ChainId
        );
    }

private:
    bool bIsMutationMessage(protocol::NodeControlMessageType typeMessage) const
    {
        return typeMessage
                == protocol::NodeControlMessageType::SenderAuthenticationConfig
            || typeMessage
                == protocol::NodeControlMessageType::ReceiverAuthenticationContexts
            || typeMessage
                == protocol::NodeControlMessageType::TextPayloadConfig
            || typeMessage == protocol::NodeControlMessageType::RoundStart
            || typeMessage == protocol::NodeControlMessageType::RoundPause
            || typeMessage == protocol::NodeControlMessageType::RoundResume
            || typeMessage == protocol::NodeControlMessageType::RoundStop;
    }

    protocol::NodeControlMessage msgApplySenderConfig(
        const protocol::SenderAuthenticationConfigControlDetails& detConfig
    )
    {
        try
        {
            if (m_runSender.bIsRunning())
            {
                throw std::logic_error(
                    "Sender configuration cannot change during an active round"
                );
            }

            if (detConfig.strSenderId() != m_strNodeName)
            {
                throw std::invalid_argument(
                    "Sender authentication configuration targets another node"
                );
            }

            AuthenticationRoundParameters prmParameters = prmMap(
                detConfig.prmRoundParameters()
            );
            const crypto::OpenSslCryptoProvider crpProvider(
                prmParameters.algCryptoAlgorithm()
            );
            SenderAuthenticationContext ctxCandidate =
                SenderAuthenticationContext::ctxCreateVerified(
                    SenderAuthenticationMaterial(
                        detConfig.strSenderId(),
                        detConfig.u64ChainId(),
                        vecMap(detConfig.arrChainSeed()),
                        digMap(detConfig.arrCommitmentKey()),
                        std::move(prmParameters)
                    ),
                    crpProvider
                );

            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            m_optSenderContext = std::move(ctxCandidate);
            m_optTextWorkload.reset();
            return msgConfigAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Sender,
                true,
                "",
                "Sender authentication configuration accepted"
            );
        }
        catch (const std::exception& exError)
        {
            return msgConfigAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Sender,
                false,
                "INVALID_AUTH_CONFIG",
                exError.what()
            );
        }
    }

    protocol::NodeControlMessage msgApplyReceiverConfig(
        const protocol::ReceiverAuthenticationContextsControlDetails& detConfig
    )
    {
        try
        {
            if (m_runReceiver.bIsRunning())
            {
                throw std::logic_error(
                    "Receiver configuration cannot change during an active round"
                );
            }

            std::vector<ReceiverAuthenticationContext> vecContexts;
            vecContexts.reserve(detConfig.vecContexts().size());
            for (const protocol::ReceiverAuthenticationContextControlDetails&
                detContext : detConfig.vecContexts())
            {
                vecContexts.emplace_back(
                    detContext.strSenderId(),
                    detContext.strSenderIpAddress(),
                    detContext.u64ChainId(),
                    digMap(detContext.arrCommitmentKey()),
                    prmMap(detContext.prmRoundParameters())
                );
            }

            m_runReceiver.configure(std::move(vecContexts));
            return msgConfigAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Receiver,
                true,
                "",
                "Receiver authentication contexts accepted"
            );
        }
        catch (const std::exception& exError)
        {
            return msgConfigAcknowledgement(
                detConfig.strRequestId(),
                protocol::AuthenticationConfigTarget::Receiver,
                false,
                "INVALID_AUTH_CONFIG",
                exError.what()
            );
        }
    }

    protocol::NodeControlMessage msgApplyTextPayload(
        const protocol::TextPayloadControlDetails& detPayload
    )
    {
        try
        {
            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            if (!m_optSenderContext.has_value())
            {
                throw std::logic_error(
                    "Sender authentication configuration is missing"
                );
            }

            if (m_optSenderContext->matMaterial().u64ChainId()
                != detPayload.u64ChainId())
            {
                throw std::invalid_argument(
                    "Text payload chain ID does not match the sender context"
                );
            }

            workload::TextWorkload wrkCandidate(
                workload::TextPayload(detPayload.strUtf8Text()),
                m_optSenderContext->matMaterial().prmRoundParameters()
                    .u32TotalPacketCount()
            );
            m_runSender.configure(
                m_optSenderContext.value(),
                wrkCandidate
            );
            m_optTextWorkload = std::move(wrkCandidate);

            return msgConfigAcknowledgement(
                detPayload.strRequestId(),
                protocol::AuthenticationConfigTarget::TextPayload,
                true,
                "",
                "Text payload accepted and sender schedule prepared"
            );
        }
        catch (const std::exception& exError)
        {
            return msgConfigAcknowledgement(
                detPayload.strRequestId(),
                protocol::AuthenticationConfigTarget::TextPayload,
                false,
                "INVALID_TEXT_PAYLOAD",
                exError.what()
            );
        }
    }

    protocol::NodeControlMessage msgApplyRoundCommand(
        const protocol::AuthenticationRoundCommandControlDetails& detCommand
    )
    {
        try
        {
            if (detCommand.cmdCommand() == protocol::AuthenticationRoundCommand::Start)
            {
                const TimeSynchronizationStatus stsTime =
                    m_fnTimeSynchronizationProvider();
                if (!stsTime.bSynchronized())
                {
                    return msgRoundAcknowledgement(
                        detCommand,
                        false,
                        "TIME_UNSYNCHRONIZED",
                        stsTime.strMessage()
                    );
                }

                if (!m_runReceiver.bIsConfigured()
                    && !m_runSender.bIsConfigured())
                {
                    throw std::logic_error(
                        "Node has no prepared sender or receiver context"
                    );
                }

                if (m_runReceiver.bIsConfigured())
                {
                    m_runReceiver.start(
                        detCommand.strRoundId(),
                        detCommand.u64ExecutionTimestampMilliseconds(),
                        stsTime.u32ToleranceMilliseconds()
                    );
                }

                if (m_runSender.bIsConfigured())
                {
                    m_runSender.start(
                        detCommand.strRoundId(),
                        detCommand.u64ExecutionTimestampMilliseconds()
                    );
                }
            }
            else if (detCommand.cmdCommand()
                == protocol::AuthenticationRoundCommand::Pause)
            {
                if (m_runSender.bIsRunning())
                {
                    m_runSender.requestPause(
                        detCommand.strRoundId(),
                        detCommand.u32LogicalIntervalIndex(),
                        detCommand.u64ExecutionTimestampMilliseconds()
                    );
                }

                if (m_runReceiver.bIsRunning())
                {
                    m_runReceiver.requestPause(
                        detCommand.strRoundId(),
                        detCommand.u32LogicalIntervalIndex(),
                        detCommand.u64ExecutionTimestampMilliseconds()
                    );
                }
            }
            else if (detCommand.cmdCommand()
                == protocol::AuthenticationRoundCommand::Resume)
            {
                if (m_runSender.bIsRunning())
                {
                    m_runSender.resume(
                        detCommand.strRoundId(),
                        detCommand.u32LogicalIntervalIndex(),
                        detCommand.u64ExecutionTimestampMilliseconds()
                    );
                }

                if (m_runReceiver.bIsRunning())
                {
                    m_runReceiver.resume(
                        detCommand.strRoundId(),
                        detCommand.u32LogicalIntervalIndex(),
                        detCommand.u64ExecutionTimestampMilliseconds()
                    );
                }
            }
            else
            {
                m_runSender.stop();
                m_runReceiver.stop();
            }

            return msgRoundAcknowledgement(
                detCommand,
                true,
                "",
                "Authentication round command accepted"
            );
        }
        catch (const std::exception& exError)
        {
            if (detCommand.cmdCommand()
                == protocol::AuthenticationRoundCommand::Start)
            {
                m_runSender.stop();
                m_runReceiver.stop();
            }

            return msgRoundAcknowledgement(
                detCommand,
                false,
                "ROUND_COMMAND_REJECTED",
                exError.what()
            );
        }
    }

    void emitResult(
        const AuthenticationRuntimeResult& resResult,
        protocol::AuthenticationRoundResultRole roleResult
    ) noexcept
    {
        try
        {
            m_fnControlEventHandler(protocol::NodeControlMessage(
                protocol::AuthenticationRoundResultControlDetails(
                    resResult.strRoundId(),
                    resResult.strSenderId(),
                    resResult.u64ChainId(),
                    roleResult,
                    statusMap(resResult.statusResult()),
                    resResult.u32ExpectedPacketCount(),
                    resResult.u32ReceivedPacketCount(),
                    resResult.u32AuthenticatedPacketCount(),
                    resResult.u32FailedPacketCount(),
                    resResult.u32MissingPacketCount(),
                    resResult.strRecoveredText(),
                    resResult.strMessage()
                )
            ));
        }
        catch (...)
        {
            // 平台事件发送失败不得反向终止算法线程。
        }
    }

    std::string m_strNodeName;
    ControlEventHandler m_fnControlEventHandler;
    TimeSynchronizationProvider m_fnTimeSynchronizationProvider;
    mutable std::mutex m_mtxConfig;
    std::optional<SenderAuthenticationContext> m_optSenderContext;
    std::optional<workload::TextWorkload> m_optTextWorkload;
    AuthenticationSenderRuntime m_runSender;
    AuthenticationReceiverRuntime m_runReceiver;
};

AuthenticationNodeRuntime::AuthenticationNodeRuntime(
    std::string strNodeName,
    DatagramSender fnDatagramSender,
    ControlEventHandler fnControlEventHandler,
    TimeSynchronizationProvider fnTimeSynchronizationProvider
)
    : m_ptrImpl(std::make_unique<Impl>(
          std::move(strNodeName),
          std::move(fnDatagramSender),
          std::move(fnControlEventHandler),
          std::move(fnTimeSynchronizationProvider)
      ))
{
}

AuthenticationNodeRuntime::~AuthenticationNodeRuntime() = default;

protocol::NodeControlMessage AuthenticationNodeRuntime::msgHandleControl(
    protocol::TcpClientRole roleClient,
    const protocol::NodeControlMessage& msgMessage
)
{
    return m_ptrImpl->msgHandleControl(roleClient, msgMessage);
}

bool AuthenticationNodeRuntime::bHandleDatagram(
    const std::string& strSourceIpAddress,
    const protocol::ByteBuffer& vecDatagram,
    std::uint64_t u64ReceiveTimestampMilliseconds
)
{
    return m_ptrImpl->bHandleDatagram(
        strSourceIpAddress,
        vecDatagram,
        u64ReceiveTimestampMilliseconds
    );
}

void AuthenticationNodeRuntime::stop() noexcept
{
    m_ptrImpl->stop();
}

bool AuthenticationNodeRuntime::bHasSenderContext() const
{
    return m_ptrImpl->bHasSenderContext();
}

bool AuthenticationNodeRuntime::bSenderRunning() const
{
    return m_ptrImpl->bSenderRunning();
}

bool AuthenticationNodeRuntime::bReceiverRoundRunning() const
{
    return m_ptrImpl->bReceiverRoundRunning();
}

bool AuthenticationNodeRuntime::bRoundPaused() const
{
    return m_ptrImpl->bRoundPaused();
}

std::optional<std::uint64_t> AuthenticationNodeRuntime::optSenderChainId() const
{
    return m_ptrImpl->optSenderChainId();
}

std::size_t AuthenticationNodeRuntime::nReceiverContextCount() const
{
    return m_ptrImpl->nReceiverContextCount();
}

std::size_t
AuthenticationNodeRuntime::nDroppedReceiverQueueDatagramCount() const
{
    return m_ptrImpl->nDroppedReceiverQueueDatagramCount();
}

ReceiverAuthenticationContextLookupResult
AuthenticationNodeRuntime::resFindReceiverContext(
    const std::string& strSourceIpAddress,
    std::uint64_t u64ChainId
) const
{
    return m_ptrImpl->resFindReceiverContext(
        strSourceIpAddress,
        u64ChainId
    );
}
}

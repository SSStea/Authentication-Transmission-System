#include "tesla/core/AuthenticationNodeRuntime.h"

#include "tesla/core/AuthenticationReceiverRuntime.h"
#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/core/AuthenticationSenderRuntime.h"
#include "tesla/core/SenderAuthenticationContext.h"
#include "tesla/crypto/OpenSslCryptoProvider.h"
#include "tesla/protocol/AuthenticationControl.h"
#include "tesla/workload/TextWorkload.h"

#include <algorithm>
#include <chrono>
#include <exception>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <utility>
#include <variant>
#include <vector>

namespace tesla::core
{
namespace
{
#ifndef TESLA_GIT_COMMIT
#define TESLA_GIT_COMMIT "unknown"
#endif

using ArchiveContextKey = std::pair<std::string, std::uint64_t>;

struct ArchiveContext final
{
    metrics::AuthenticationRoundArchiveConfiguration cfgConfiguration;
    std::string                                       strConfiguredFault;
    std::string                                       strConfiguredFaultValue;
    std::uint64_t                                     u64RandomSeed;
};

std::uint64_t u64NowMilliseconds() noexcept
{
    return static_cast<std::uint64_t>(std::chrono::duration_cast<
        std::chrono::milliseconds
    >(std::chrono::system_clock::now().time_since_epoch()).count());
}

std::string strCryptoAlgorithm(crypto::CryptoAlgorithm algCrypto)
{
    switch (algCrypto)
    {
    case crypto::CryptoAlgorithm::Sha256:
        return "SHA-256";
    case crypto::CryptoAlgorithm::Sm3:
        return "SM3";
    case crypto::CryptoAlgorithm::Sha3_256:
        return "SHA3-256";
    }

    throw std::invalid_argument("Unknown archive crypto algorithm");
}

metrics::AuthenticationRoundArchiveConfiguration cfgArchive(
    const AuthenticationRoundParameters& prmRound
)
{
    const std::optional<ImprovedTeslaParameters>& optImproved =
        prmRound.optImprovedParameters();
    return metrics::AuthenticationRoundArchiveConfiguration(
        prmRound.modeAuthentication() == TeslaAuthenticationMode::Native
            ? metrics::AuthenticationMetricMode::Native
            : metrics::AuthenticationMetricMode::Improved,
        strCryptoAlgorithm(prmRound.algCryptoAlgorithm()),
        "",
        prmRound.u32TotalPacketCount(),
        prmRound.u32PacketsPerInterval(),
        prmRound.u32IntervalMilliseconds(),
        prmRound.u32DisclosureDelay(),
        optImproved.has_value() ? optImproved->u32GroupSize() : 0,
        optImproved.has_value() ? optImproved->u32DetectionThreshold() : 0
    );
}

metrics::AuthenticationRoundArchiveConfiguration cfgWithPayloadHash(
    const metrics::AuthenticationRoundArchiveConfiguration& cfgConfiguration,
    std::string strPayloadHash
)
{
    return metrics::AuthenticationRoundArchiveConfiguration(
        cfgConfiguration.modeAuthentication(),
        cfgConfiguration.strCryptoAlgorithm(),
        std::move(strPayloadHash),
        cfgConfiguration.u32PacketCount(),
        cfgConfiguration.u32PacketsPerInterval(),
        cfgConfiguration.u32IntervalMilliseconds(),
        cfgConfiguration.u32DisclosureDelay(),
        cfgConfiguration.u32GroupSize(),
        cfgConfiguration.u32DetectionThreshold()
    );
}

/** @brief 第29.5节payloadHash固定使用SHA-256，与本轮认证密码套件独立。 */
std::string strPayloadSha256(const crypto::ByteBuffer& vecPayload)
{
    const crypto::OpenSslCryptoProvider crpSha256(
        crypto::CryptoAlgorithm::Sha256
    );
    const crypto::Digest digPayload = crpSha256.digHash(vecPayload);
    static constexpr char HEX_DIGITS[] = "0123456789abcdef";

    std::string strResult;
    strResult.reserve(digPayload.size() * 2U);
    for (const std::uint8_t u8Byte : digPayload)
    {
        strResult.push_back(HEX_DIGITS[(u8Byte >> 4U) & 0x0FU]);
        strResult.push_back(HEX_DIGITS[u8Byte & 0x0FU]);
    }
    return strResult;
}

std::string strPayloadSha256(const std::string& strPayload)
{
    return strPayloadSha256(crypto::ByteBuffer(
        strPayload.begin(),
        strPayload.end()
    ));
}

std::string strArchiveStatus(AuthenticationRuntimeResultStatus statusResult)
{
    switch (statusResult)
    {
    case AuthenticationRuntimeResultStatus::Completed:
        return "COMPLETED";
    case AuthenticationRuntimeResultStatus::AuthenticationFailed:
        return "AUTHENTICATION_FAILED";
    case AuthenticationRuntimeResultStatus::VerificationTimeout:
        return "VERIFICATION_TIMEOUT";
    case AuthenticationRuntimeResultStatus::InvalidSchedulingOverrun:
        return "INVALID_SCHEDULING_OVERRUN";
    case AuthenticationRuntimeResultStatus::Stopped:
        return "STOPPED";
    case AuthenticationRuntimeResultStatus::ProtocolIncomplete:
        return "PROTOCOL_INCOMPLETE";
    case AuthenticationRuntimeResultStatus::TimeUnsynchronized:
        return "TIME_UNSYNCHRONIZED";
    }

    throw std::invalid_argument("Unknown archive round status");
}

bool bValidArchiveSample(AuthenticationRuntimeResultStatus statusResult) noexcept
{
    return statusResult == AuthenticationRuntimeResultStatus::Completed
        || statusResult == AuthenticationRuntimeResultStatus::AuthenticationFailed;
}

std::string strExperimentId(
    const metrics::AuthenticationRoundArchiveConfiguration& cfgConfiguration
)
{
    return std::string("tesla-")
        + (cfgConfiguration.modeAuthentication()
                == metrics::AuthenticationMetricMode::Native
            ? "native" : "improved")
        + "-" + cfgConfiguration.strCryptoAlgorithm()
        + "-p" + std::to_string(cfgConfiguration.u32PacketCount())
        + "-ppi" + std::to_string(cfgConfiguration.u32PacketsPerInterval())
        + "-i" + std::to_string(cfgConfiguration.u32IntervalMilliseconds())
        + "-d" + std::to_string(cfgConfiguration.u32DisclosureDelay())
        + "-g" + std::to_string(cfgConfiguration.u32GroupSize())
        + "-t" + std::to_string(cfgConfiguration.u32DetectionThreshold());
}

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

protocol::BinaryBlock arrMap(const crypto::Digest& digValue)
{
    protocol::BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

ReceiverPayloadDetails varMapReceiverPayload(
    const protocol::ReceiverPayloadControlDetails& varPayloadDetails
)
{
    if (std::holds_alternative<
            protocol::TextReceiverPayloadControlDetails
        >(varPayloadDetails))
    {
        return TextReceiverPayloadDetails(
            std::get<protocol::TextReceiverPayloadControlDetails>(
                varPayloadDetails
            ).u32RepeatCount()
        );
    }

    return FileReceiverPayloadDetails(
        std::get<protocol::FileReceiverPayloadControlDetails>(
            varPayloadDetails
        ).u64OriginalByteCount()
    );
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
        TimeSynchronizationProvider fnTimeSynchronizationProvider,
        RecoveredFileHandler fnRecoveredFileHandler,
        ObservationHandler fnObservationHandler,
        LocalKeyChainHandler fnLocalKeyChainHandler,
        MetricHandler fnMetricHandler,
        std::string strLocalIpAddress
    )
        : m_strNodeName(std::move(strNodeName)),
          m_fnControlEventHandler(std::move(fnControlEventHandler)),
          m_fnTimeSynchronizationProvider(
              std::move(fnTimeSynchronizationProvider)
          ),
          m_fnRecoveredFileHandler(std::move(fnRecoveredFileHandler)),
          m_fnObservationHandler(std::move(fnObservationHandler)),
          m_fnLocalKeyChainHandler(std::move(fnLocalKeyChainHandler)),
          m_fnMetricHandler(std::move(fnMetricHandler)),
          m_runSender(
              std::move(fnDatagramSender),
              [this](const AuthenticationRuntimeResult& resResult)
              {
                  emitResult(
                      resResult,
                      protocol::AuthenticationRoundResultRole::Sender
                  );
              },
              [this](const protocol::AuthenticationObservation& varObservation)
              {
                  processObservation(varObservation);
              },
              [this](const LocalSenderKeyChainObservation& varObservation)
              {
                  processLocalKeyChainObservation(varObservation);
              },
              [this](const metrics::AuthenticationMetricRecord& varMetric)
              {
                  processMetric(varMetric);
              },
              std::move(strLocalIpAddress)
          ),
          m_runReceiver(
              [this](const AuthenticationRuntimeResult& resResult)
              {
                  emitResult(
                      resResult,
                      protocol::AuthenticationRoundResultRole::Receiver
                  );
              },
              [this](const protocol::AuthenticationObservation& varObservation)
              {
                  processObservation(varObservation);
              },
              [this](const metrics::AuthenticationMetricRecord& varMetric)
              {
                  processMetric(varMetric);
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
        case protocol::NodeControlMessageType::FaultInjectionConfig:
            return msgApplyFault(std::get<
                protocol::FaultInjectionControlDetails
            >(msgMessage.varDetails()));
        case protocol::NodeControlMessageType::AttackSourceMapping:
            return msgApplyAttackSourceMapping(std::get<
                protocol::AttackSourceMappingControlDetails
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

    protocol::NodeControlMessage msgApplyFilePayload(
        protocol::TcpClientRole roleClient,
        const std::string& strRequestId,
        std::uint64_t u64ChainId,
        workload::FileWorkload wrkFile
    )
    {
        if (roleClient == protocol::TcpClientRole::Monitor)
        {
            return msgConfigAcknowledgement(
                strRequestId,
                protocol::AuthenticationConfigTarget::FilePayload,
                false,
                "MONITOR_FILE_FORBIDDEN",
                "Monitor clients cannot upload authentication files"
            );
        }

        try
        {
            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            if (!m_optSenderContext.has_value())
            {
                throw std::logic_error(
                    "Sender authentication configuration is missing"
                );
            }

            const SenderAuthenticationMaterial& matMaterial =
                m_optSenderContext->matMaterial();
            if (matMaterial.u64ChainId() != u64ChainId)
            {
                throw std::invalid_argument(
                    "File payload chain ID does not match the sender context"
                );
            }

            if (matMaterial.prmRoundParameters().modePayload()
                    != AuthenticationPayloadMode::File
                || wrkFile.u32PacketCount()
                    != matMaterial.prmRoundParameters().u32TotalPacketCount())
            {
                throw std::invalid_argument(
                    "File payload size does not match the sender configuration"
                );
            }

            const std::string strPayloadHash = strPayloadSha256(
                wrkFile.vecFileBytes()
            );
            m_runSender.configure(
                m_optSenderContext.value(),
                SenderPayloadWorkload(std::move(wrkFile))
            );
            const ArchiveContextKey keyArchive(
                matMaterial.strSenderId(),
                matMaterial.u64ChainId()
            );
            auto itrArchive = m_mapArchiveContexts.find(keyArchive);
            if (itrArchive != m_mapArchiveContexts.end())
            {
                itrArchive->second.cfgConfiguration = cfgWithPayloadHash(
                    itrArchive->second.cfgConfiguration,
                    strPayloadHash
                );
            }
            return msgConfigAcknowledgement(
                strRequestId,
                protocol::AuthenticationConfigTarget::FilePayload,
                true,
                "",
                "File payload accepted and sender schedule prepared"
            );
        }
        catch (const std::exception& exError)
        {
            return msgConfigAcknowledgement(
                strRequestId,
                protocol::AuthenticationConfigTarget::FilePayload,
                false,
                "INVALID_FILE_PAYLOAD",
                exError.what()
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
            || typeMessage
                == protocol::NodeControlMessageType::FaultInjectionConfig
            || typeMessage
                == protocol::NodeControlMessageType::AttackSourceMapping
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

            ArchiveContext ctxArchive{
                cfgArchive(ctxCandidate.matMaterial().prmRoundParameters()),
                "NONE",
                "",
                0
            };

            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            // 新链配置先使旧载荷失效，必须收到同一chainId的新载荷后才能启动。
            m_runSender.resetConfiguration();
            m_optSenderContext = std::move(ctxCandidate);
            for (auto itrArchive = m_mapArchiveContexts.begin();
                itrArchive != m_mapArchiveContexts.end();)
            {
                // 本节点同一时刻只保留一条Sender链，防止长期运行累积过期归档上下文。
                if (itrArchive->first.first == detConfig.strSenderId()
                    && itrArchive->first.second != detConfig.u64ChainId())
                {
                    itrArchive = m_mapArchiveContexts.erase(itrArchive);
                }
                else
                {
                    ++itrArchive;
                }
            }
            m_mapArchiveContexts.insert_or_assign(
                ArchiveContextKey(detConfig.strSenderId(), detConfig.u64ChainId()),
                std::move(ctxArchive)
            );
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
            std::vector<std::pair<ArchiveContextKey, ArchiveContext>>
                vecArchiveContexts;
            vecContexts.reserve(detConfig.vecContexts().size());
            vecArchiveContexts.reserve(detConfig.vecContexts().size());
            for (const protocol::ReceiverAuthenticationContextControlDetails&
                detContext : detConfig.vecContexts())
            {
                ReceiverAuthenticationContext ctxReceiver(
                    detContext.strSenderId(),
                    detContext.strSenderIpAddress(),
                    detContext.u64ChainId(),
                    digMap(detContext.arrCommitmentKey()),
                    prmMap(detContext.prmRoundParameters()),
                    varMapReceiverPayload(detContext.varPayloadDetails())
                );
                vecArchiveContexts.emplace_back(
                    ArchiveContextKey(
                        detContext.strSenderId(),
                        detContext.u64ChainId()
                    ),
                    ArchiveContext{
                        cfgArchive(ctxReceiver.prmRoundParameters()),
                        "NOT_DISTRIBUTED",
                        "",
                        0
                    }
                );
                vecContexts.push_back(std::move(ctxReceiver));
            }

            m_runReceiver.configure(std::move(vecContexts));
            {
                std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
                std::set<ArchiveContextKey> setActiveArchiveKeys;
                for (const auto& parArchive : vecArchiveContexts)
                {
                    setActiveArchiveKeys.insert(parArchive.first);
                }
                if (m_optSenderContext.has_value())
                {
                    const SenderAuthenticationMaterial& matLocal =
                        m_optSenderContext->matMaterial();
                    setActiveArchiveKeys.emplace(
                        matLocal.strSenderId(),
                        matLocal.u64ChainId()
                    );
                }

                // Receiver配置是完整快照；淘汰旧链可同时限制内存并避免轮次ID误关联。
                for (auto itrArchive = m_mapArchiveContexts.begin();
                    itrArchive != m_mapArchiveContexts.end();)
                {
                    if (setActiveArchiveKeys.find(itrArchive->first)
                        == setActiveArchiveKeys.end())
                    {
                        itrArchive = m_mapArchiveContexts.erase(itrArchive);
                    }
                    else
                    {
                        ++itrArchive;
                    }
                }
                for (auto& parArchive : vecArchiveContexts)
                {
                    m_mapArchiveContexts.insert_or_assign(
                        std::move(parArchive.first),
                        std::move(parArchive.second)
                    );
                }
            }
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
                SenderPayloadWorkload(std::move(wrkCandidate))
            );
            const SenderAuthenticationMaterial& matMaterial =
                m_optSenderContext->matMaterial();
            auto itrArchive = m_mapArchiveContexts.find(ArchiveContextKey(
                matMaterial.strSenderId(),
                matMaterial.u64ChainId()
            ));
            if (itrArchive != m_mapArchiveContexts.end())
            {
                itrArchive->second.cfgConfiguration = cfgWithPayloadHash(
                    itrArchive->second.cfgConfiguration,
                    strPayloadSha256(detPayload.strUtf8Text())
                );
            }

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

    protocol::NodeControlMessage msgApplyFault(
        const protocol::FaultInjectionControlDetails& detFault
    )
    {
        try
        {
            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            if (!m_optSenderContext.has_value()
                || !m_runSender.bIsConfigured())
            {
                throw std::logic_error(
                    "Fault plan requires a prepared sender payload"
                );
            }

            const SenderAuthenticationMaterial& matMaterial =
                m_optSenderContext->matMaterial();
            if (detFault.strTargetSenderId() != matMaterial.strSenderId()
                || detFault.u64ChainId() != matMaterial.u64ChainId())
            {
                throw std::invalid_argument(
                    "Fault plan does not target this sender context"
                );
            }

            m_runSender.configureFault(detFault.varFaultDetails());
            const ArchiveContextKey keyArchive(
                detFault.strTargetSenderId(),
                detFault.u64ChainId()
            );
            auto itrArchive = m_mapArchiveContexts.find(keyArchive);
            if (itrArchive != m_mapArchiveContexts.end())
            {
                ArchiveContext& ctxArchive = itrArchive->second;
                ctxArchive.u64RandomSeed = 0;
                if (const auto* pLoss = std::get_if<
                        protocol::PacketLossFaultDetails
                    >(&detFault.varFaultDetails()))
                {
                    ctxArchive.strConfiguredFault = "PACKET_LOSS";
                    ctxArchive.strConfiguredFaultValue =
                        "rate=" + std::to_string(pLoss->dLossRatePercent())
                        + ";protectedGroup="
                        + std::to_string(pLoss->u32ProtectedGroupSize());
                    ctxArchive.u64RandomSeed = pLoss->u64RandomSeed();
                }
                else if (const auto* pDisconnect = std::get_if<
                        protocol::LogicalDisconnectFaultDetails
                    >(&detFault.varFaultDetails()))
                {
                    ctxArchive.strConfiguredFault = "LOGICAL_DISCONNECT";
                    ctxArchive.strConfiguredFaultValue =
                        "startPacket="
                        + std::to_string(pDisconnect->u32StartPacketIndex())
                        + ";durationMs="
                        + std::to_string(pDisconnect->u32DurationMilliseconds())
                        + ";protectedGroup="
                        + std::to_string(pDisconnect->u32ProtectedGroupSize());
                }
                else
                {
                    const auto& detDelay = std::get<
                        protocol::FixedDelayFaultDetails
                    >(detFault.varFaultDetails());
                    ctxArchive.strConfiguredFault = "FIXED_DELAY";
                    ctxArchive.strConfiguredFaultValue =
                        "delayMs="
                        + std::to_string(detDelay.u32DelayMilliseconds());
                }
            }
            return protocol::NodeControlMessage(
                protocol::ExperimentControlAcknowledgementDetails(
                    detFault.strRequestId(),
                    detFault.strRoundId(),
                    true,
                    "",
                    "Authentication fault plan accepted"
                )
            );
        }
        catch (const std::exception& exError)
        {
            return protocol::NodeControlMessage(
                protocol::ExperimentControlAcknowledgementDetails(
                    detFault.strRequestId(),
                    detFault.strRoundId(),
                    false,
                    "FAULT_PLAN_REJECTED",
                    exError.what()
                )
            );
        }
    }

    protocol::NodeControlMessage msgApplyAttackSourceMapping(
        const protocol::AttackSourceMappingControlDetails& detMapping
    )
    {
        try
        {
            m_runReceiver.applyAttackSourceMapping(detMapping);
            return protocol::NodeControlMessage(
                protocol::ExperimentControlAcknowledgementDetails(
                    detMapping.strRequestId(),
                    detMapping.strRoundId(),
                    true,
                    "",
                    detMapping.actAction()
                            == protocol::AttackSourceMappingAction::Install
                        ? "Temporary attack source mapping installed"
                        : "Temporary attack source mapping cleared"
                )
            );
        }
        catch (const std::exception& exError)
        {
            return protocol::NodeControlMessage(
                protocol::ExperimentControlAcknowledgementDetails(
                    detMapping.strRequestId(),
                    detMapping.strRoundId(),
                    false,
                    "ATTACK_SOURCE_MAPPING_REJECTED",
                    exError.what()
                )
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

                m_stoObservations.beginRound(detCommand.strRoundId());

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
                m_runSender.clearFault();
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

    std::optional<metrics::AuthenticationRoundArchiveSummary> optCreateArchive(
        const AuthenticationRuntimeResult& resResult,
        protocol::AuthenticationRoundResultRole roleResult
    ) const
    {
        ArchiveContext ctxArchive = [&]()
        {
            std::lock_guard<std::mutex> lckConfig(m_mtxConfig);
            const auto itrArchive = m_mapArchiveContexts.find(ArchiveContextKey(
                resResult.strSenderId(),
                resResult.u64ChainId()
            ));
            if (itrArchive == m_mapArchiveContexts.end())
            {
                throw std::logic_error("Round archive configuration is missing");
            }

            return itrArchive->second;
        }();

        bool bValidSample = bValidArchiveSample(resResult.statusResult());
        std::string strInvalidReason = bValidSample
            ? std::string()
            : resResult.strMessage();
        metrics::AuthenticationRoundArchiveDetails varArchiveDetails =
            metrics::SenderRoundArchiveDetails(0, "NONE", "", 0, 0);
        metrics::AuthenticationRoundArchiveConfiguration cfgFinal =
            ctxArchive.cfgConfiguration;

        if (roleResult == protocol::AuthenticationRoundResultRole::Sender)
        {
            std::uint64_t u64FileSize = 0;
            if (const auto* pFile = std::get_if<
                    FileSenderAuthenticationRuntimeResultDetails
                >(&resResult.varResultDetails()))
            {
                u64FileSize = pFile->u64OriginalByteCount();
            }

            varArchiveDetails = metrics::SenderRoundArchiveDetails(
                resResult.u32ReceivedPacketCount(),
                ctxArchive.strConfiguredFault,
                ctxArchive.strConfiguredFaultValue,
                ctxArchive.u64RandomSeed,
                u64FileSize
            );
        }
        else
        {
            std::uint32_t u32FallbackGroupCount = 0;
            std::uint64_t u64VerifyTimeNanoseconds = 0;
            std::uint64_t u64ReceivedAuthBytes = 0;
            double dEstimatedEnergyMicroJoule = 0.0;
            bool bEnergySummaryFound = false;
            const std::vector<metrics::AuthenticationMetricRecord> vecMetrics =
                m_stoMetrics.vecSnapshot();
            for (auto itrMetric = vecMetrics.rbegin();
                itrMetric != vecMetrics.rend(); ++itrMetric)
            {
                const auto* pEnergy = std::get_if<
                    metrics::EstimatedEnergyMetricSummary
                >(&*itrMetric);
                if (pEnergy == nullptr
                    || pEnergy->strRoundId() != resResult.strRoundId()
                    || pEnergy->strSenderId() != resResult.strSenderId()
                    || pEnergy->u64ChainId() != resResult.u64ChainId())
                {
                    continue;
                }

                u64VerifyTimeNanoseconds = pEnergy->u64VerifyTimeNanoseconds();
                u64ReceivedAuthBytes = pEnergy->u64ReceivedAuthBytes();
                dEstimatedEnergyMicroJoule =
                    pEnergy->dEstimatedEnergyMicroJoule();
                if (const auto* pImproved = std::get_if<
                        metrics::ImprovedRoundMetricDetails
                    >(&pEnergy->varDetails()))
                {
                    u32FallbackGroupCount =
                        pImproved->u32FallbackGroupCount();
                }
                bEnergySummaryFound = true;
                break;
            }

            if (!bEnergySummaryFound)
            {
                bValidSample = false;
                strInvalidReason = "METRIC_SUMMARY_UNAVAILABLE";
            }

            std::uint64_t u64FileSize = 0;
            std::uint64_t u64RecoveredFileSize = 0;
            std::string strRecoveredFileHash;
            if (const auto* pFile = std::get_if<
                    FileReceiverAuthenticationRuntimeResultDetails
                >(&resResult.varResultDetails()))
            {
                u64FileSize = pFile->u64OriginalByteCount();
                u64RecoveredFileSize = pFile->vecRecoveredFileBytes().size();
                if (pFile->optRecoveredSha256().has_value())
                {
                    strRecoveredFileHash =
                        protocol::AuthenticationControlValueCodec::strEncodeBlock(
                            arrMap(pFile->optRecoveredSha256().value())
                        );
                }
            }
            else if (const auto* pText = std::get_if<
                         TextAuthenticationRuntimeResultDetails
                     >(&resResult.varResultDetails());
                     pText != nullptr && !pText->strRecoveredText().empty())
            {
                cfgFinal = cfgWithPayloadHash(
                    cfgFinal,
                    strPayloadSha256(pText->strRecoveredText())
                );
            }

            if (!strRecoveredFileHash.empty())
            {
                cfgFinal = cfgWithPayloadHash(
                    cfgFinal,
                    strRecoveredFileHash
                );
            }

            varArchiveDetails = metrics::ReceiverRoundArchiveDetails(
                resResult.u32ReceivedPacketCount(),
                resResult.u32AuthenticatedPacketCount(),
                resResult.u32FailedPacketCount(),
                resResult.u32MissingPacketCount(),
                u32FallbackGroupCount,
                u64VerifyTimeNanoseconds,
                u64ReceivedAuthBytes,
                dEstimatedEnergyMicroJoule,
                u64FileSize,
                u64RecoveredFileSize,
                std::move(strRecoveredFileHash)
            );
        }

        return metrics::AuthenticationRoundArchiveSummary(
            u64NowMilliseconds(),
            strExperimentId(ctxArchive.cfgConfiguration),
            resResult.strRoundId(),
            TESLA_GIT_COMMIT,
            m_strNodeName,
            resResult.strSenderId(),
            resResult.u64ChainId(),
            std::move(cfgFinal),
            strArchiveStatus(resResult.statusResult()),
            bValidSample,
            std::move(strInvalidReason),
            std::move(varArchiveDetails)
        );
    }

    void emitResult(
        const AuthenticationRuntimeResult& resResult,
        protocol::AuthenticationRoundResultRole roleResult
    ) noexcept
    {
        try
        {
            protocol::AuthenticationRoundResultStatus statusResult = statusMap(
                resResult.statusResult()
            );
            std::string strMessage = resResult.strMessage();
            protocol::AuthenticationRoundResultDetails varResultDetails =
                protocol::TextAuthenticationRoundResultDetails("");

            if (std::holds_alternative<TextAuthenticationRuntimeResultDetails>(
                    resResult.varResultDetails()
                ))
            {
                varResultDetails =
                    protocol::TextAuthenticationRoundResultDetails(
                        std::get<TextAuthenticationRuntimeResultDetails>(
                            resResult.varResultDetails()
                        ).strRecoveredText()
                    );
            }
            else if (std::holds_alternative<
                FileSenderAuthenticationRuntimeResultDetails
            >(resResult.varResultDetails()))
            {
                varResultDetails =
                    protocol::FileSenderAuthenticationRoundResultDetails(
                        std::get<
                            FileSenderAuthenticationRuntimeResultDetails
                        >(resResult.varResultDetails()).u64OriginalByteCount()
                    );
            }
            else
            {
                const FileReceiverAuthenticationRuntimeResultDetails& detFile =
                    std::get<FileReceiverAuthenticationRuntimeResultDetails>(
                        resResult.varResultDetails()
                );
                if (resResult.statusResult()
                        == AuthenticationRuntimeResultStatus::Completed
                    && (!m_fnRecoveredFileHandler
                        || !m_fnRecoveredFileHandler(
                            resResult.strRoundId(),
                            resResult.strSenderId(),
                            resResult.u64ChainId(),
                            detFile.vecRecoveredFileBytes()
                        )))
                {
                    statusResult = protocol::AuthenticationRoundResultStatus::
                        ProtocolIncomplete;
                    strMessage =
                        "Receiver authenticated the file but atomic persistence failed";
                }

                std::optional<protocol::BinaryBlock> optRecoveredSha256;
                if (detFile.optRecoveredSha256().has_value())
                {
                    optRecoveredSha256 = arrMap(
                        detFile.optRecoveredSha256().value()
                    );
                }
                varResultDetails =
                    protocol::FileReceiverAuthenticationRoundResultDetails(
                        detFile.u64OriginalByteCount(),
                        detFile.vecRecoveredFileBytes().size(),
                        std::move(optRecoveredSha256)
                    );
            }

            try
            {
                const auto optArchive = optCreateArchive(resResult, roleResult);
                if (optArchive.has_value())
                {
                    processMetric(metrics::AuthenticationMetricRecord(
                        std::move(optArchive.value())
                    ));
                }
            }
            catch (...)
            {
                // 归档失败不得阻断协议要求的最终轮次结果上报。
            }

            m_fnControlEventHandler(protocol::NodeControlMessage(
                protocol::AuthenticationRoundResultControlDetails(
                    resResult.strRoundId(),
                    resResult.strSenderId(),
                    resResult.u64ChainId(),
                    roleResult,
                    statusResult,
                    resResult.u32ExpectedPacketCount(),
                    resResult.u32ReceivedPacketCount(),
                    resResult.u32AuthenticatedPacketCount(),
                    resResult.u32FailedPacketCount(),
                    resResult.u32MissingPacketCount(),
                    std::move(varResultDetails),
                    std::move(strMessage)
                )
            ));
        }
        catch (...)
        {
            // 平台事件发送失败不得反向终止算法线程。
        }
    }

    void processObservation(
        const protocol::AuthenticationObservation& varObservation
    ) noexcept
    {
        try
        {
            m_stoObservations.resAppend(varObservation);
            if (m_fnObservationHandler)
            {
                m_fnObservationHandler(varObservation);
            }
        }
        catch (...)
        {
            // 观察数据存储或平台展示失败不得改变认证状态机结果。
        }
    }

    void processLocalKeyChainObservation(
        const LocalSenderKeyChainObservation& varObservation
    ) noexcept
    {
        if (!m_fnLocalKeyChainHandler)
        {
            return;
        }

        try
        {
            m_fnLocalKeyChainHandler(varObservation);
        }
        catch (...)
        {
            // 完整密钥链仅用于PC本地展示，回调异常不能进入网络路径。
        }
    }

    void processMetric(
        const metrics::AuthenticationMetricRecord& varMetric
    ) noexcept
    {
        try
        {
            m_stoMetrics.bAppend(varMetric);
            if (m_fnMetricHandler)
            {
                m_fnMetricHandler(varMetric);
            }
        }
        catch (...)
        {
            // 指标存储或平台展示失败不得改变认证状态机结果。
        }
    }

public:
    std::vector<protocol::PacketObservationControlDetails>
    vecPacketObservationSnapshot() const
    {
        return m_stoObservations.vecPacketSnapshot();
    }

    std::vector<protocol::PacketFailureControlDetails>
    vecFailureObservationSnapshot() const
    {
        return m_stoObservations.vecFailureSnapshot();
    }

    std::vector<protocol::PacketObservationControlDetails>
    vecAbnormalPacketObservationSnapshot() const
    {
        return m_stoObservations.vecAbnormalPacketSnapshot();
    }

    std::vector<protocol::ImprovedGroupObservationControlDetails>
    vecGroupObservationSnapshot() const
    {
        return m_stoObservations.vecGroupSnapshot();
    }

    std::vector<protocol::DosSummaryControlDetails> vecDosSummarySnapshot() const
    {
        return m_stoObservations.vecDosSummarySnapshot();
    }

    std::vector<metrics::AuthenticationMetricRecord> vecMetricSnapshot() const
    {
        return m_stoMetrics.vecSnapshot();
    }

private:

    std::string m_strNodeName;
    ControlEventHandler m_fnControlEventHandler;
    TimeSynchronizationProvider m_fnTimeSynchronizationProvider;
    RecoveredFileHandler m_fnRecoveredFileHandler;
    ObservationHandler m_fnObservationHandler;
    LocalKeyChainHandler m_fnLocalKeyChainHandler;
    MetricHandler m_fnMetricHandler;
    AuthenticationObservationStore m_stoObservations;
    metrics::AuthenticationMetricStore m_stoMetrics;
    mutable std::mutex m_mtxConfig;
    std::optional<SenderAuthenticationContext> m_optSenderContext;
    std::map<ArchiveContextKey, ArchiveContext> m_mapArchiveContexts;
    AuthenticationSenderRuntime m_runSender;
    AuthenticationReceiverRuntime m_runReceiver;
};

AuthenticationNodeRuntime::AuthenticationNodeRuntime(
    std::string strNodeName,
    DatagramSender fnDatagramSender,
    ControlEventHandler fnControlEventHandler,
    TimeSynchronizationProvider fnTimeSynchronizationProvider,
    RecoveredFileHandler fnRecoveredFileHandler,
    ObservationHandler fnObservationHandler,
    LocalKeyChainHandler fnLocalKeyChainHandler,
    MetricHandler fnMetricHandler,
    std::string strLocalIpAddress
)
    : m_ptrImpl(std::make_unique<Impl>(
          std::move(strNodeName),
          std::move(fnDatagramSender),
          std::move(fnControlEventHandler),
          std::move(fnTimeSynchronizationProvider),
          std::move(fnRecoveredFileHandler),
          std::move(fnObservationHandler),
          std::move(fnLocalKeyChainHandler),
          std::move(fnMetricHandler),
          std::move(strLocalIpAddress)
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

protocol::NodeControlMessage AuthenticationNodeRuntime::msgApplyFilePayload(
    protocol::TcpClientRole roleClient,
    const std::string& strRequestId,
    std::uint64_t u64ChainId,
    workload::FileWorkload wrkFile
)
{
    return m_ptrImpl->msgApplyFilePayload(
        roleClient,
        strRequestId,
        u64ChainId,
        std::move(wrkFile)
    );
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

std::vector<protocol::PacketObservationControlDetails>
AuthenticationNodeRuntime::vecPacketObservationSnapshot() const
{
    return m_ptrImpl->vecPacketObservationSnapshot();
}

std::vector<protocol::PacketFailureControlDetails>
AuthenticationNodeRuntime::vecFailureObservationSnapshot() const
{
    return m_ptrImpl->vecFailureObservationSnapshot();
}

std::vector<protocol::PacketObservationControlDetails>
AuthenticationNodeRuntime::vecAbnormalPacketObservationSnapshot() const
{
    return m_ptrImpl->vecAbnormalPacketObservationSnapshot();
}

std::vector<protocol::ImprovedGroupObservationControlDetails>
AuthenticationNodeRuntime::vecGroupObservationSnapshot() const
{
    return m_ptrImpl->vecGroupObservationSnapshot();
}

std::vector<protocol::DosSummaryControlDetails>
AuthenticationNodeRuntime::vecDosSummarySnapshot() const
{
    return m_ptrImpl->vecDosSummarySnapshot();
}

std::vector<metrics::AuthenticationMetricRecord>
AuthenticationNodeRuntime::vecMetricSnapshot() const
{
    return m_ptrImpl->vecMetricSnapshot();
}
}

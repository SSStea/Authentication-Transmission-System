#include "ManagerAuthenticationController.h"

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/protocol/NodeControlJsonCodec.h"

#include <QDateTime>
#include <QStringList>
#include <QUuid>

#include <algorithm>
#include <exception>
#include <limits>
#include <stdexcept>
#include <utility>
#include <variant>

namespace
{
using namespace tesla;

crypto::CryptoAlgorithm algCore(
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

    throw std::invalid_argument("Unsupported authentication algorithm");
}

core::TeslaAuthenticationMode modeCore(
    protocol::UdpAuthenticationMode modeControl
)
{
    return modeControl == protocol::UdpAuthenticationMode::Native
        ? core::TeslaAuthenticationMode::Native
        : core::TeslaAuthenticationMode::Improved;
}

protocol::BinaryBlock arrBlock(const crypto::ByteBuffer& vecBytes)
{
    if (vecBytes.size() != protocol::BINARY_BLOCK_SIZE)
    {
        throw std::invalid_argument("Authentication block must contain 32 bytes");
    }

    protocol::BinaryBlock arrResult{};
    std::copy(vecBytes.begin(), vecBytes.end(), arrResult.begin());
    return arrResult;
}

protocol::BinaryBlock arrBlock(const crypto::Digest& digValue)
{
    protocol::BinaryBlock arrResult{};
    std::copy(digValue.begin(), digValue.end(), arrResult.begin());
    return arrResult;
}

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
}
}

ManagerTextRoundConfiguration::ManagerTextRoundConfiguration(
    tesla::protocol::UdpAuthenticationMode modeAuthentication,
    tesla::protocol::AuthenticationCryptoAlgorithm algCryptoAlgorithm,
    std::uint32_t u32TextRepeatCount,
    std::uint32_t u32PacketsPerInterval,
    std::uint32_t u32DisclosureDelay,
    std::uint32_t u32IntervalMilliseconds,
    std::optional<tesla::protocol::ImprovedTeslaControlParameters>
        optImprovedParameters,
    QString strText
)
    : m_modeAuthentication(modeAuthentication),
      m_algCryptoAlgorithm(algCryptoAlgorithm),
      m_u32TextRepeatCount(u32TextRepeatCount),
      m_u32PacketsPerInterval(u32PacketsPerInterval),
      m_u32DisclosureDelay(u32DisclosureDelay),
      m_u32IntervalMilliseconds(u32IntervalMilliseconds),
      m_optImprovedParameters(std::move(optImprovedParameters)),
      m_strText(std::move(strText))
{
    const QByteArray arrText = m_strText.toUtf8();
    if (m_u32TextRepeatCount == 0 || m_u32PacketsPerInterval == 0
        || m_u32DisclosureDelay == 0 || m_u32IntervalMilliseconds == 0)
    {
        throw std::invalid_argument(
            "Text authentication counts and timing must be positive"
        );
    }

    if (arrText.isEmpty()
        || arrText.size() > static_cast<qsizetype>(
            tesla::protocol::BINARY_BLOCK_SIZE
        )
        || arrText.contains('\0'))
    {
        throw std::invalid_argument(
            "Text payload must contain 1 to 32 UTF-8 bytes without zero bytes"
        );
    }

    if (m_modeAuthentication == tesla::protocol::UdpAuthenticationMode::Native
        && m_optImprovedParameters.has_value())
    {
        throw std::invalid_argument(
            "Native TESLA must not contain improved parameters"
        );
    }

    if (m_modeAuthentication
            == tesla::protocol::UdpAuthenticationMode::Improved
        && !m_optImprovedParameters.has_value())
    {
        throw std::invalid_argument(
            "Improved TESLA requires grouping parameters"
        );
    }
}

tesla::protocol::UdpAuthenticationMode
ManagerTextRoundConfiguration::modeAuthentication() const noexcept
{
    return m_modeAuthentication;
}

tesla::protocol::AuthenticationCryptoAlgorithm
ManagerTextRoundConfiguration::algCryptoAlgorithm() const noexcept
{
    return m_algCryptoAlgorithm;
}

std::uint32_t
ManagerTextRoundConfiguration::u32TextRepeatCount() const noexcept
{
    return m_u32TextRepeatCount;
}

std::uint32_t
ManagerTextRoundConfiguration::u32PacketsPerInterval() const noexcept
{
    return m_u32PacketsPerInterval;
}

std::uint32_t
ManagerTextRoundConfiguration::u32DisclosureDelay() const noexcept
{
    return m_u32DisclosureDelay;
}

std::uint32_t
ManagerTextRoundConfiguration::u32IntervalMilliseconds() const noexcept
{
    return m_u32IntervalMilliseconds;
}

const std::optional<tesla::protocol::ImprovedTeslaControlParameters>&
ManagerTextRoundConfiguration::optImprovedParameters() const noexcept
{
    return m_optImprovedParameters;
}

const QString& ManagerTextRoundConfiguration::strText() const noexcept
{
    return m_strText;
}

ManagerAuthenticationController::ManagerAuthenticationController(
    ManagerNetworkController& ctlNetwork,
    QObject* pParent
)
    : QObject(pParent),
      m_ctlNetwork(ctlNetwork),
      m_autAuthority(m_rngSecureRandom),
      m_bConfigurationRejected(false),
      m_bConfigurationReady(false),
      m_bRoundRunning(false),
      m_bRoundPaused(false),
      m_u32IntervalMilliseconds(0),
      m_u32LastLogicalInterval(0),
      m_u32TimelineFirstInterval(1),
      m_u32PauseAfterInterval(0),
      m_u64TimelineStartTimestampMilliseconds(0),
      m_u64PauseTimestampMilliseconds(0),
      m_nExpectedResultCount(0)
{
    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::nodeControlJsonReceived,
        this,
        &ManagerAuthenticationController::processNodeControlJson
    );
}

bool ManagerAuthenticationController::bPrepareTextRound(
    const ManagerTextRoundConfiguration& cfgRound,
    const QSet<QString>& setSelectedSenderEndpoints,
    const QVector<ManagerNodeSnapshot>& vecNodeSnapshots,
    QString& strError
)
{
    try
    {
        if (m_bRoundRunning)
        {
            throw std::logic_error(
                "An active authentication round must be stopped first"
            );
        }

        resetPreparedRound();
        std::map<QString, ManagerNodeSnapshot> mapSnapshots;
        for (const ManagerNodeSnapshot& snpNode : vecNodeSnapshots)
        {
            if (snpNode.roleNode() != tesla::protocol::NodeRole::Attacker
                && snpNode.stateConnection()
                    == ManagerConnectionState::Connected)
            {
                mapSnapshots.emplace(snpNode.strEndpointKey(), snpNode);
                m_setParticipantEndpoints.insert(snpNode.strEndpointKey());
            }
        }

        if (setSelectedSenderEndpoints.isEmpty())
        {
            throw std::invalid_argument("Select at least one connected Sender");
        }
        if (m_setParticipantEndpoints.isEmpty())
        {
            throw std::invalid_argument(
                "No connected authentication participant is available"
            );
        }
        if (m_setParticipantEndpoints.size() < 2)
        {
            throw std::invalid_argument(
                "Text authentication requires at least two connected nodes"
            );
        }

        std::optional<tesla::core::ImprovedTeslaParameters>
            optImprovedCore;
        if (cfgRound.optImprovedParameters().has_value())
        {
            optImprovedCore.emplace(
                cfgRound.optImprovedParameters()->u32GroupSize(),
                cfgRound.optImprovedParameters()->u32DetectionThreshold()
            );
        }

        const tesla::core::AuthenticationRoundParameters prmTemplate(
            algCore(cfgRound.algCryptoAlgorithm()),
            modeCore(cfgRound.modeAuthentication()),
            cfgRound.u32TextRepeatCount(),
            cfgRound.u32PacketsPerInterval(),
            cfgRound.u32DisclosureDelay(),
            cfgRound.u32IntervalMilliseconds(),
            0,
            optImprovedCore,
            tesla::core::AuthenticationPayloadMode::Text
        );
        m_u32IntervalMilliseconds = cfgRound.u32IntervalMilliseconds();
        m_u32LastLogicalInterval = static_cast<std::uint32_t>(
            prmTemplate.nDataIntervalCount()
        ) + cfgRound.u32DisclosureDelay();

        for (const QString& strEndpointKey : setSelectedSenderEndpoints)
        {
            const auto itrSnapshot = mapSnapshots.find(strEndpointKey);
            if (itrSnapshot == mapSnapshots.end())
            {
                throw std::invalid_argument(
                    "Every selected Sender must remain connected"
                );
            }

            tesla::core::SenderAuthenticationMaterial matMaterial =
                m_autAuthority.matIssueSenderMaterial(
                    itrSnapshot->second.strNodeName().toStdString(),
                    prmTemplate
                );
            m_vecSenderTargets.push_back(SenderTarget{
                strEndpointKey,
                itrSnapshot->second.strIpAddress(),
                std::move(matMaterial)
            });
        }

        for (const SenderTarget& tgtSender : m_vecSenderTargets)
        {
            const tesla::core::SenderAuthenticationMaterial& matMaterial =
                tgtSender.matMaterial;

            const QString strSenderRequestId =
                strCreateRequestId(QStringLiteral("sender-config"));
            if (!bSendRequired(
                    tgtSender.strEndpointKey,
                    tesla::protocol::NodeControlMessage(
                        tesla::protocol::
                            SenderAuthenticationConfigControlDetails(
                                strSenderRequestId.toStdString(),
                                matMaterial.strSenderId(),
                                matMaterial.u64ChainId(),
                                arrBlock(matMaterial.vecChainSeed()),
                                arrBlock(matMaterial.digCommitmentKey()),
                                prmControlParameters(
                                    matMaterial.prmRoundParameters()
                                )
                            )
                    ),
                    strSenderRequestId,
                    strError
                ))
            {
                resetPreparedRound();
                return false;
            }

            const QString strPayloadRequestId =
                strCreateRequestId(QStringLiteral("text-payload"));
            if (!bSendRequired(
                    tgtSender.strEndpointKey,
                    tesla::protocol::NodeControlMessage(
                        tesla::protocol::TextPayloadControlDetails(
                            strPayloadRequestId.toStdString(),
                            matMaterial.u64ChainId(),
                            cfgRound.strText().toUtf8().toStdString()
                        )
                    ),
                    strPayloadRequestId,
                    strError
                ))
            {
                resetPreparedRound();
                return false;
            }
        }

        for (const QString& strEndpointKey : m_setParticipantEndpoints)
        {
            std::vector<
                tesla::protocol::ReceiverAuthenticationContextControlDetails
            > vecReceiverContexts;
            for (const SenderTarget& tgtSender : m_vecSenderTargets)
            {
                // Sender节点不验证自己的组播，避免把本地回环策略误判为丢包。
                if (tgtSender.strEndpointKey == strEndpointKey)
                {
                    continue;
                }

                const tesla::core::SenderAuthenticationMaterial& matMaterial =
                    tgtSender.matMaterial;
                vecReceiverContexts.emplace_back(
                    matMaterial.strSenderId(),
                    tgtSender.strIpAddress.toStdString(),
                    matMaterial.u64ChainId(),
                    arrBlock(matMaterial.digCommitmentKey()),
                    prmControlParameters(matMaterial.prmRoundParameters())
                );
            }

            if (vecReceiverContexts.empty())
            {
                // 纯Sender不需要启动Receiver运行时；其余节点仍接收该Sender。
                continue;
            }

            const QString strReceiverRequestId =
                strCreateRequestId(QStringLiteral("receiver-config"));
            if (!bSendRequired(
                    strEndpointKey,
                    tesla::protocol::NodeControlMessage(
                        tesla::protocol::
                            ReceiverAuthenticationContextsControlDetails(
                                strReceiverRequestId.toStdString(),
                                vecReceiverContexts
                            )
                    ),
                    strReceiverRequestId,
                    strError
                ))
            {
                resetPreparedRound();
                return false;
            }

            m_nExpectedResultCount += vecReceiverContexts.size();
        }
        m_nExpectedResultCount += m_vecSenderTargets.size();

        emit configurationStateChanged(
            false,
            QStringLiteral("配置已下发，等待 %1 个节点确认")
                .arg(m_setPendingConfigurationRequests.size())
        );
        return true;
    }
    catch (const std::exception& exError)
    {
        resetPreparedRound();
        strError = QString::fromUtf8(exError.what());
        return false;
    }
}

bool ManagerAuthenticationController::bStartRound(QString& strError)
{
    if (!m_bConfigurationReady || m_bRoundRunning)
    {
        strError = QStringLiteral("配置尚未全部确认或轮次已在运行");
        return false;
    }

    m_strRoundId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    m_u64TimelineStartTimestampMilliseconds = u64NowMilliseconds() + 2000U;
    m_u32TimelineFirstInterval = 1;
    m_u32PauseAfterInterval = 0;
    m_u64PauseTimestampMilliseconds = 0;
    m_setReceivedResultKeys.clear();
    if (!bBroadcastRoundCommand(
            tesla::protocol::AuthenticationRoundCommand::Start,
            m_u64TimelineStartTimestampMilliseconds,
            1,
            strError
        ))
    {
        QString strRollbackError;
        bBroadcastRoundCommand(
            tesla::protocol::AuthenticationRoundCommand::Stop,
            0,
            0,
            strRollbackError
        );
        m_strRoundId.clear();
        return false;
    }

    m_bRoundRunning = true;
    m_bRoundPaused = false;
    emit roundStateChanged(true, false);
    return true;
}

bool ManagerAuthenticationController::bPauseRound(QString& strError)
{
    if (!m_bRoundRunning || m_bRoundPaused)
    {
        strError = QStringLiteral("当前轮次不处于可暂停状态");
        return false;
    }

    const std::uint64_t u64Now = u64NowMilliseconds();
    const std::uint64_t u64Elapsed =
        u64Now > m_u64TimelineStartTimestampMilliseconds
        ? u64Now - m_u64TimelineStartTimestampMilliseconds
        : 0;
    const std::uint32_t u32CurrentInterval =
        m_u32TimelineFirstInterval
        + static_cast<std::uint32_t>(
            u64Elapsed / m_u32IntervalMilliseconds
        );
    const std::uint32_t u32PauseAfterInterval =
        u32CurrentInterval + 1U;
    if (u32PauseAfterInterval >= m_u32LastLogicalInterval)
    {
        strError = QStringLiteral("轮次已接近结束，无法再安排暂停边界");
        return false;
    }

    const std::uint64_t u64PauseTimestamp =
        m_u64TimelineStartTimestampMilliseconds
        + static_cast<std::uint64_t>(
            u32PauseAfterInterval - m_u32TimelineFirstInterval + 1U
        ) * m_u32IntervalMilliseconds;
    if (!bBroadcastRoundCommand(
            tesla::protocol::AuthenticationRoundCommand::Pause,
            u64PauseTimestamp,
            u32PauseAfterInterval,
            strError
        ))
    {
        return false;
    }

    m_u32PauseAfterInterval = u32PauseAfterInterval;
    m_u64PauseTimestampMilliseconds = u64PauseTimestamp;
    m_bRoundPaused = true;
    emit roundStateChanged(true, true);
    return true;
}

bool ManagerAuthenticationController::bResumeRound(QString& strError)
{
    if (!m_bRoundRunning || !m_bRoundPaused
        || m_u32PauseAfterInterval == 0)
    {
        strError = QStringLiteral("当前轮次不处于可继续状态");
        return false;
    }

    const std::uint32_t u32ResumeInterval =
        m_u32PauseAfterInterval + 1U;
    const std::uint64_t u64ResumeTimestamp = std::max(
        u64NowMilliseconds() + 2000U,
        m_u64PauseTimestampMilliseconds + 2000U
    );
    if (!bBroadcastRoundCommand(
            tesla::protocol::AuthenticationRoundCommand::Resume,
            u64ResumeTimestamp,
            u32ResumeInterval,
            strError
        ))
    {
        return false;
    }

    m_u32TimelineFirstInterval = u32ResumeInterval;
    m_u64TimelineStartTimestampMilliseconds = u64ResumeTimestamp;
    m_bRoundPaused = false;
    emit roundStateChanged(true, false);
    return true;
}

bool ManagerAuthenticationController::bStopRound(QString& strError)
{
    if (!m_bRoundRunning)
    {
        strError = QStringLiteral("当前没有运行中的认证轮次");
        return false;
    }

    if (!bBroadcastRoundCommand(
            tesla::protocol::AuthenticationRoundCommand::Stop,
            0,
            0,
            strError
        ))
    {
        return false;
    }

    m_bRoundRunning = false;
    m_bRoundPaused = false;
    emit roundStateChanged(false, false);
    return true;
}

bool ManagerAuthenticationController::bConfigurationReady() const noexcept
{
    return m_bConfigurationReady;
}

bool ManagerAuthenticationController::bRoundRunning() const noexcept
{
    return m_bRoundRunning;
}

bool ManagerAuthenticationController::bRoundPaused() const noexcept
{
    return m_bRoundPaused;
}

void ManagerAuthenticationController::processNodeControlJson(
    const QString& strEndpointKey,
    const QString& strJson
)
{
    using namespace tesla::protocol;

    const NodeControlDecodeResult resMessage =
        NodeControlJsonCodec::resDecode(strJson.toStdString());
    if (!std::holds_alternative<NodeControlMessage>(resMessage))
    {
        return;
    }

    const NodeControlMessage& msgMessage =
        std::get<NodeControlMessage>(resMessage);
    if (msgMessage.typeMessage()
        == NodeControlMessageType::AuthenticationConfigAcknowledgement)
    {
        const AuthenticationConfigAcknowledgementControlDetails& detAck =
            std::get<AuthenticationConfigAcknowledgementControlDetails>(
                msgMessage.varDetails()
            );
        const QString strRequestId =
            QString::fromStdString(detAck.strRequestId());
        if (!m_setPendingConfigurationRequests.remove(strRequestId))
        {
            return;
        }

        if (!detAck.bAccepted())
        {
            m_bConfigurationRejected = true;
            emit configurationStateChanged(
                false,
                QStringLiteral("节点拒绝配置：%1")
                    .arg(QString::fromStdString(detAck.strMessage()))
            );
        }
        else if (m_setPendingConfigurationRequests.isEmpty()
                 && !m_bConfigurationRejected)
        {
            m_bConfigurationReady = true;
            emit configurationStateChanged(
                true,
                QStringLiteral("全部Sender和Receiver配置已确认")
            );
        }
        return;
    }

    if (msgMessage.typeMessage()
        == NodeControlMessageType::RoundCommandAcknowledgement)
    {
        const AuthenticationRoundAcknowledgementControlDetails& detAck =
            std::get<AuthenticationRoundAcknowledgementControlDetails>(
                msgMessage.varDetails()
            );
        if (!detAck.bAccepted())
        {
            emit resultMessage(QStringLiteral("节点拒绝轮次命令：%1")
                .arg(QString::fromStdString(detAck.strMessage())));
        }
        return;
    }

    if (msgMessage.typeMessage() == NodeControlMessageType::RoundResult)
    {
        const AuthenticationRoundResultControlDetails& detResult =
            std::get<AuthenticationRoundResultControlDetails>(
                msgMessage.varDetails()
            );
        if (QString::fromStdString(detResult.strRoundId()) != m_strRoundId)
        {
            return;
        }

        const QString strResultKey =
            strEndpointKey + QStringLiteral("|")
            + QString::number(static_cast<int>(detResult.roleResult()))
            + QStringLiteral("|")
            + QString::fromStdString(detResult.strSenderId()) + QStringLiteral("|")
            + QString::number(detResult.u64ChainId());
        m_setReceivedResultKeys.insert(strResultKey);
        emit resultMessage(
            QStringLiteral(
                "%1 / chainId=%2：认证 %3/%4，失败 %5，缺失 %6，恢复文本“%7”；%8"
            )
                .arg(QString::fromStdString(detResult.strSenderId()))
                .arg(detResult.u64ChainId())
                .arg(detResult.u32AuthenticatedPacketCount())
                .arg(detResult.u32ExpectedPacketCount())
                .arg(detResult.u32FailedPacketCount())
                .arg(detResult.u32MissingPacketCount())
                .arg(QString::fromStdString(detResult.strRecoveredText()))
                .arg(QString::fromStdString(detResult.strMessage()))
        );

        if (m_bRoundRunning
            && m_setReceivedResultKeys.size()
                >= static_cast<qsizetype>(m_nExpectedResultCount))
        {
            m_bRoundRunning = false;
            m_bRoundPaused = false;
            emit roundStateChanged(false, false);
            emit resultMessage(QStringLiteral(
                "本轮所有Sender与Receiver结果均已返回"
            ));
        }
    }
}

bool ManagerAuthenticationController::bSendRequired(
    const QString& strEndpointKey,
    const tesla::protocol::NodeControlMessage& msgMessage,
    const QString& strRequestId,
    QString& strError
)
{
    m_setPendingConfigurationRequests.insert(strRequestId);
    if (m_ctlNetwork.bSendNodeControl(strEndpointKey, msgMessage))
    {
        return true;
    }

    m_setPendingConfigurationRequests.remove(strRequestId);
    strError = QStringLiteral("向节点 %1 下发认证配置失败")
        .arg(strEndpointKey);
    return false;
}

bool ManagerAuthenticationController::bBroadcastRoundCommand(
    tesla::protocol::AuthenticationRoundCommand cmdCommand,
    std::uint64_t u64ExecutionTimestampMilliseconds,
    std::uint32_t u32LogicalIntervalIndex,
    QString& strError
)
{
    QStringList listFailedEndpoints;
    for (const QString& strEndpointKey : m_setParticipantEndpoints)
    {
        const QString strRequestId = strCreateRequestId(
            QStringLiteral("round-command")
        );
        const tesla::protocol::NodeControlMessage msgCommand(
            tesla::protocol::AuthenticationRoundCommandControlDetails(
                strRequestId.toStdString(),
                m_strRoundId.toStdString(),
                cmdCommand,
                u64ExecutionTimestampMilliseconds,
                u32LogicalIntervalIndex
            )
        );
        if (!m_ctlNetwork.bSendNodeControl(strEndpointKey, msgCommand))
        {
            listFailedEndpoints.append(strEndpointKey);
        }
    }

    if (!listFailedEndpoints.isEmpty())
    {
        strError = QStringLiteral("向以下节点下发轮次命令失败：%1")
            .arg(listFailedEndpoints.join(QStringLiteral("、")));
        return false;
    }

    return true;
}

tesla::protocol::AuthenticationRoundControlParameters
ManagerAuthenticationController::prmControlParameters(
    const tesla::core::AuthenticationRoundParameters& prmParameters
) const
{
    std::optional<tesla::protocol::ImprovedTeslaControlParameters>
        optImprovedParameters;
    if (prmParameters.optImprovedParameters().has_value())
    {
        optImprovedParameters.emplace(
            prmParameters.optImprovedParameters()->u32GroupSize(),
            prmParameters.optImprovedParameters()->u32DetectionThreshold()
        );
    }

    tesla::protocol::AuthenticationCryptoAlgorithm algControl =
        tesla::protocol::AuthenticationCryptoAlgorithm::Sha256;
    if (prmParameters.algCryptoAlgorithm()
        == tesla::crypto::CryptoAlgorithm::Sm3)
    {
        algControl = tesla::protocol::AuthenticationCryptoAlgorithm::Sm3;
    }
    else if (prmParameters.algCryptoAlgorithm()
        == tesla::crypto::CryptoAlgorithm::Sha3_256)
    {
        algControl =
            tesla::protocol::AuthenticationCryptoAlgorithm::Sha3_256;
    }

    return tesla::protocol::AuthenticationRoundControlParameters(
        algControl,
        prmParameters.modeAuthentication()
                == tesla::core::TeslaAuthenticationMode::Native
            ? tesla::protocol::UdpAuthenticationMode::Native
            : tesla::protocol::UdpAuthenticationMode::Improved,
        prmParameters.u32TotalPacketCount(),
        prmParameters.u32PacketsPerInterval(),
        prmParameters.u32DisclosureDelay(),
        prmParameters.u32IntervalMilliseconds(),
        prmParameters.u64StartTimestampMilliseconds(),
        prmParameters.u32ChainLength(),
        std::move(optImprovedParameters),
        tesla::protocol::AuthenticationPayloadMode::Text
    );
}

QString ManagerAuthenticationController::strCreateRequestId(
    const QString& strPrefix
) const
{
    return strPrefix + QStringLiteral("-")
        + QUuid::createUuid().toString(QUuid::WithoutBraces);
}

void ManagerAuthenticationController::resetPreparedRound()
{
    m_vecSenderTargets.clear();
    m_setParticipantEndpoints.clear();
    m_setPendingConfigurationRequests.clear();
    m_setReceivedResultKeys.clear();
    m_bConfigurationRejected = false;
    m_bConfigurationReady = false;
    m_bRoundPaused = false;
    m_strRoundId.clear();
    m_u32IntervalMilliseconds = 0;
    m_u32LastLogicalInterval = 0;
    m_u32TimelineFirstInterval = 1;
    m_u32PauseAfterInterval = 0;
    m_u64TimelineStartTimestampMilliseconds = 0;
    m_u64PauseTimestampMilliseconds = 0;
    m_nExpectedResultCount = 0;
}

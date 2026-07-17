#include "ManagerAttackExperimentController.h"

#include "tesla/protocol/ExperimentControl.h"
#include "tesla/protocol/NodeControlJsonCodec.h"

#include <QDateTime>
#include <QUuid>

#include <exception>
#include <stdexcept>
#include <utility>
#include <variant>

namespace
{
using namespace tesla::protocol;

std::uint64_t u64NowMilliseconds()
{
    return static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch());
}
}

ManagerAttackExperimentController::ManagerAttackExperimentController(
    ManagerNetworkController& ctlNetwork,
    ManagerAuthenticationController& ctlAuthentication,
    QObject* pParent
)
    : QObject(pParent),
      m_ctlNetwork(ctlNetwork),
      m_ctlAuthentication(ctlAuthentication),
      m_nSenderContextIndex(-1),
      m_bContextSent(false),
      m_bPlanPending(false),
      m_bReady(false),
      m_bRunning(false),
      m_bMappingsInstalled(false)
{
    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::attackControlJsonReceived,
        this,
        &ManagerAttackExperimentController::processAttackControlJson
    );
    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::nodeControlJsonReceived,
        this,
        &ManagerAttackExperimentController::processNodeControlJson
    );
    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::nodesChanged,
        this,
        &ManagerAttackExperimentController::handleNodesChanged
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::roundStateChanged,
        this,
        [this](bool bRunning, bool)
        {
            if (!bRunning && (m_bRunning || m_bReady))
            {
                QString strError;
                static_cast<void>(bStopPrepared(false, strError));
            }
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::configurationStateChanged,
        this,
        [this](bool, const QString&)
        {
            if (m_optContext.has_value()
                && QString::fromStdString(m_optContext->strRoundId())
                    != m_ctlAuthentication.strRoundId())
            {
                clearPreparedState(true);
                emit stateChanged();
            }
        }
    );
}

bool ManagerAttackExperimentController::bPrepareContext(
    const QString& strTestEndpointKey,
    int nSenderContextIndex,
    QString& strError
)
{
    try
    {
        if (!m_ctlAuthentication.bConfigurationReady()
            || m_ctlAuthentication.bRoundRunning())
        {
            throw std::logic_error(
                "需要先完成一个尚未启动的认证轮次配置"
            );
        }

        const QVector<AttackRoundContextControlDetails> vecContexts =
            m_ctlAuthentication.vecAttackRoundContexts();
        if (nSenderContextIndex < 0
            || nSenderContextIndex >= vecContexts.size())
        {
            throw std::out_of_range("目标Sender公开上下文无效");
        }

        std::optional<ManagerNodeSnapshot> optTestNode;
        for (const ManagerNodeSnapshot& snpNode : m_ctlNetwork.vecNodeSnapshots())
        {
            if (snpNode.strEndpointKey() == strTestEndpointKey
                && snpNode.roleNode() == NodeRole::Attacker
                && snpNode.stateConnection() == ManagerConnectionState::Connected)
            {
                optTestNode = snpNode;
                break;
            }
        }
        if (!optTestNode.has_value())
        {
            throw std::invalid_argument("需要选择一个已连接的独立测试端");
        }

        const AttackRoundContextControlDetails detContext = vecContexts.at(
            nSenderContextIndex
        );
        if (optTestNode->strIpAddress()
            == QString::fromStdString(detContext.strTargetSenderIp()))
        {
            throw std::invalid_argument(
                "测试端与目标Sender不能使用同一IP"
            );
        }
        if (!optTestNode->bMulticastListening())
        {
            throw std::invalid_argument("测试端尚未进入内部组播监听状态");
        }

        clearPreparedState(true);
        m_strTestEndpointKey = strTestEndpointKey;
        m_strTestSourceIp = optTestNode->strIpAddress();
        m_nSenderContextIndex = nSenderContextIndex;
        m_optContext = detContext;
        if (!m_ctlNetwork.bSendAttackControl(
                m_strTestEndpointKey,
                AttackControlMessage(detContext)
            ))
        {
            clearPreparedState(false);
            throw std::runtime_error("公开上下文下发失败");
        }

        m_bContextSent = true;
        strError.clear();
        emit message(QStringLiteral("公开上下文已下发，请在测试端配置并提交计划"));
        emit stateChanged();
        return true;
    }
    catch (const std::exception& exError)
    {
        strError = QString::fromUtf8(exError.what());
        return false;
    }
}

bool ManagerAttackExperimentController::bStartPrepared(
    std::uint64_t u64StartTimestampMilliseconds,
    QString& strError
)
{
    if (!m_bReady || !m_optPlan.has_value())
    {
        strError = QStringLiteral("认证鲁棒性计划尚未完成确认");
        return false;
    }
    if (u64StartTimestampMilliseconds <= u64NowMilliseconds() + 100U)
    {
        strError = QStringLiteral("统一启动时间过近");
        return false;
    }
    if (!bSendPreparedCommand(
            AttackControlMessageType::RoundStart,
            u64StartTimestampMilliseconds,
            strError
        ))
    {
        return false;
    }

    m_bRunning = true;
    emit stateChanged();
    return true;
}

bool ManagerAttackExperimentController::bStopPrepared(
    bool bEmergency,
    QString& strError
)
{
    if (!m_optPlan.has_value())
    {
        if (m_bContextSent)
        {
            clearPreparedState(true);
            strError.clear();
            emit stateChanged();
            return true;
        }
        strError = QStringLiteral("当前没有可停止的认证鲁棒性计划");
        return false;
    }

    const AttackControlMessageType typeMessage = bEmergency
        ? AttackControlMessageType::EmergencyStop
        : AttackControlMessageType::Stop;
    const bool bSent = bSendPreparedCommand(typeMessage, 0, strError);
    clearSourceMappings();
    m_bRunning = false;
    m_bReady = false;
    m_bPlanPending = false;
    emit stateChanged();
    return bSent;
}

bool ManagerAttackExperimentController::bContextSent() const noexcept
{
    return m_bContextSent;
}

bool ManagerAttackExperimentController::bPlanPending() const noexcept
{
    return m_bPlanPending;
}

bool ManagerAttackExperimentController::bReady() const noexcept
{
    return m_bReady;
}

bool ManagerAttackExperimentController::bRunning() const noexcept
{
    return m_bRunning;
}

QString ManagerAttackExperimentController::strStateText() const
{
    if (m_bRunning)
    {
        return QStringLiteral("异常流量模拟执行中");
    }
    if (m_bReady)
    {
        return QStringLiteral("计划和Receiver映射已就绪");
    }
    if (!m_mapMappingRequestEndpoints.isEmpty())
    {
        return QStringLiteral("等待Receiver确认临时来源映射");
    }
    if (m_bPlanPending)
    {
        return QStringLiteral("已收到计划，正在校验");
    }
    if (m_bContextSent)
    {
        return QStringLiteral("等待测试端提交计划");
    }
    return QStringLiteral("未选择公开上下文");
}

QString ManagerAttackExperimentController::strPlanSummary() const
{
    if (!m_optPlan.has_value())
    {
        return QStringLiteral("尚未收到计划");
    }

    const AttackPlanControlDetails& detPlan = m_optPlan.value();
    if (const auto* pTamper = std::get_if<TamperAttackPlanDetails>(
            &detPlan.varPlanDetails()
        ))
    {
        return QStringLiteral("Message冲突副本：%1个位置，字节%2，掩码0x%3，重复%4次")
            .arg(pTamper->vecPacketIndexes().size())
            .arg(pTamper->u8MessageByteOffset())
            .arg(pTamper->u8XorMask(), 2, 16, QLatin1Char('0'))
            .arg(pTamper->u32RepeatCount());
    }
    if (const auto* pReplay = std::get_if<ReplayAttackPlanDetails>(
            &detPlan.varPlanDetails()
        ))
    {
        return QStringLiteral("延迟重复报文：%1个位置，延迟%2ms，重复%3次")
            .arg(pReplay->vecPacketIndexes().size())
            .arg(pReplay->u32ReplayDelayMilliseconds())
            .arg(pReplay->u32RepeatCount());
    }

    const DosAttackPlanDetails& detDos = std::get<DosAttackPlanDetails>(
        detPlan.varPlanDetails()
    );
    return QStringLiteral("高频无效流量：%1 PPS，%2ms，%3B")
        .arg(detDos.u32RatePacketsPerSecond())
        .arg(detDos.u32DurationMilliseconds())
        .arg(detDos.u32PacketBytes());
}

void ManagerAttackExperimentController::processAttackControlJson(
    const QString& strEndpointKey,
    const QString& strJson
)
{
    if (strEndpointKey != m_strTestEndpointKey)
    {
        return;
    }

    const AttackControlDecodeResult resMessage = AttackControlJsonCodec::resDecode(
        strJson.toStdString()
    );
    if (!std::holds_alternative<AttackControlMessage>(resMessage))
    {
        return;
    }

    const AttackControlMessage& msgMessage = std::get<AttackControlMessage>(
        resMessage
    );
    if (msgMessage.typeMessage() == AttackControlMessageType::Plan)
    {
        const AttackPlanControlDetails& detPlan = std::get<
            AttackPlanControlDetails
        >(msgMessage.varDetails());
        if (m_optPlan.has_value())
        {
            // 重复计划不能覆盖已确认计划或借机清除已安装的Receiver映射。
            static_cast<void>(m_ctlNetwork.bSendAttackControl(
                m_strTestEndpointKey,
                AttackControlMessage(AttackPlanAcceptedControlDetails(
                    detPlan.u64AttackId(),
                    detPlan.strRoundId(),
                    false,
                    "PLAN_ALREADY_ACTIVE",
                    "Another robustness plan is already active"
                ))
            ));
            emit message(QStringLiteral("已拒绝重复提交的认证鲁棒性计划"));
            return;
        }
        if (!m_optContext.has_value()
            || detPlan.strRoundId() != m_optContext->strRoundId()
            || detPlan.strTargetSenderId()
                != m_optContext->strTargetSenderId()
            || detPlan.u64ChainId() != m_optContext->u64ChainId())
        {
            m_optPlan = detPlan;
            rejectCurrentPlan(
                QStringLiteral("PLAN_CONTEXT_MISMATCH"),
                QStringLiteral("计划与当前公开上下文不匹配或已有活动计划")
            );
            return;
        }

        m_optPlan = detPlan;
        m_bPlanPending = true;
        QString strError;
        if (detPlan.typeAttack() != AttackType::Dos
            && !bInstallSourceMappings(strError))
        {
            rejectCurrentPlan(QStringLiteral("MAPPING_FAILED"), strError);
            return;
        }
        if (detPlan.typeAttack() == AttackType::Dos)
        {
            if (!bSendPlanDecision(true, "", "Plan accepted"))
            {
                rejectCurrentPlan(
                    QStringLiteral("PLAN_CONFIRM_FAILED"),
                    QStringLiteral("计划确认返回失败")
                );
            }
        }
        emit message(QStringLiteral("已收到测试端计划：") + strPlanSummary());
        emit stateChanged();
        return;
    }

    if (msgMessage.typeMessage() == AttackControlMessageType::Ready)
    {
        const AttackReadyControlDetails& detReady = std::get<
            AttackReadyControlDetails
        >(msgMessage.varDetails());
        if (m_optPlan.has_value()
            && detReady.u64AttackId() == m_optPlan->u64AttackId()
            && detReady.strRoundId() == m_optPlan->strRoundId())
        {
            m_bPlanPending = false;
            m_bReady = true;
            emit message(QStringLiteral("测试端和Receiver均已完成准备"));
            emit stateChanged();
        }
        return;
    }

    if (msgMessage.typeMessage() == AttackControlMessageType::ExecutionStatus)
    {
        const AttackExecutionStatusControlDetails& detStatus = std::get<
            AttackExecutionStatusControlDetails
        >(msgMessage.varDetails());
        if (!m_optPlan.has_value()
            || detStatus.u64AttackId() != m_optPlan->u64AttackId())
        {
            return;
        }
        m_bRunning = detStatus.stateExecution() == AttackExecutionState::Scheduled
            || detStatus.stateExecution() == AttackExecutionState::Running;
        if (detStatus.stateExecution() == AttackExecutionState::Completed
            || detStatus.stateExecution() == AttackExecutionState::Stopped
            || detStatus.stateExecution() == AttackExecutionState::Failed)
        {
            m_bReady = false;
            m_bPlanPending = false;
            clearSourceMappings();
        }
        emit stateChanged();
        return;
    }

    if (msgMessage.typeMessage() == AttackControlMessageType::ErrorResponse)
    {
        const AttackErrorControlDetails& detError = std::get<
            AttackErrorControlDetails
        >(msgMessage.varDetails());
        emit message(QStringLiteral("测试端返回错误 %1：%2")
            .arg(
                QString::fromStdString(detError.strErrorCode()),
                QString::fromStdString(detError.strMessage())
            ));
    }
}

void ManagerAttackExperimentController::processNodeControlJson(
    const QString& strEndpointKey,
    const QString& strJson
)
{
    const NodeControlDecodeResult resMessage = NodeControlJsonCodec::resDecode(
        strJson.toStdString()
    );
    if (!std::holds_alternative<NodeControlMessage>(resMessage))
    {
        return;
    }
    const NodeControlMessage& msgMessage = std::get<NodeControlMessage>(
        resMessage
    );
    if (msgMessage.typeMessage()
        != NodeControlMessageType::ExperimentControlAcknowledgement)
    {
        return;
    }

    const ExperimentControlAcknowledgementDetails& detAck = std::get<
        ExperimentControlAcknowledgementDetails
    >(msgMessage.varDetails());
    const QString strRequestId = QString::fromStdString(detAck.strRequestId());
    if (!m_mapMappingRequestEndpoints.contains(strRequestId)
        || m_mapMappingRequestEndpoints.value(strRequestId) != strEndpointKey
        || !m_optContext.has_value()
        || detAck.strRoundId() != m_optContext->strRoundId())
    {
        return;
    }
    m_mapMappingRequestEndpoints.remove(strRequestId);
    if (!detAck.bAccepted())
    {
        rejectCurrentPlan(
            QStringLiteral("MAPPING_REJECTED"),
            QStringLiteral("Receiver拒绝临时来源映射：%1")
                .arg(QString::fromStdString(detAck.strMessage()))
        );
        return;
    }

    if (m_mapMappingRequestEndpoints.isEmpty())
    {
        m_bMappingsInstalled = true;
        if (!bSendPlanDecision(true, "", "Plan and source mappings accepted"))
        {
            rejectCurrentPlan(
                QStringLiteral("PLAN_CONFIRM_FAILED"),
                QStringLiteral("无法向测试端返回计划确认")
            );
            return;
        }
        emit message(QStringLiteral("所有Receiver临时来源映射已确认"));
        emit stateChanged();
    }
}

void ManagerAttackExperimentController::handleNodesChanged()
{
    if (m_strTestEndpointKey.isEmpty())
    {
        return;
    }
    QSet<QString> setConnectedEndpoints;
    for (const ManagerNodeSnapshot& snpNode : m_ctlNetwork.vecNodeSnapshots())
    {
        if (snpNode.stateConnection() == ManagerConnectionState::Connected)
        {
            setConnectedEndpoints.insert(snpNode.strEndpointKey());
        }
    }
    if (!setConnectedEndpoints.contains(m_strTestEndpointKey))
    {
        clearPreparedState(true);
        emit message(QStringLiteral("测试端连接中断，临时来源映射已清理"));
        emit stateChanged();
        return;
    }

    QString strDisconnectedReceiver;
    for (const QString& strEndpointKey : m_setReceiverEndpoints)
    {
        if (!setConnectedEndpoints.contains(strEndpointKey))
        {
            strDisconnectedReceiver = strEndpointKey;
            break;
        }
    }
    if (strDisconnectedReceiver.isEmpty())
    {
        return;
    }

    if (m_bRunning)
    {
        QString strIgnoredError;
        static_cast<void>(bSendPreparedCommand(
            AttackControlMessageType::EmergencyStop,
            0,
            strIgnoredError
        ));
        clearSourceMappings();
        m_bRunning = false;
        m_bReady = false;
        m_bPlanPending = false;
        emit message(QStringLiteral(
            "Receiver %1 连接中断，认证鲁棒性执行已紧急停止"
        ).arg(strDisconnectedReceiver));
        emit stateChanged();
    }
    else
    {
        rejectCurrentPlan(
            QStringLiteral("RECEIVER_DISCONNECTED"),
            QStringLiteral("Receiver %1 连接中断，计划已取消")
                .arg(strDisconnectedReceiver)
        );
    }
}

bool ManagerAttackExperimentController::bInstallSourceMappings(
    QString& strError
)
{
    if (!m_optContext.has_value() || !m_optPlan.has_value())
    {
        strError = QStringLiteral("缺少公开上下文或计划");
        return false;
    }

    const QVector<QString> vecReceiverEndpoints =
        m_ctlAuthentication.vecReceiverEndpointKeys(m_nSenderContextIndex);
    for (const QString& strEndpointKey : vecReceiverEndpoints)
    {
        m_setReceiverEndpoints.insert(strEndpointKey);
    }
    if (m_setReceiverEndpoints.isEmpty())
    {
        strError = QStringLiteral("当前目标Sender没有可用Receiver");
        return false;
    }

    const std::uint64_t u64ExpiresAtMilliseconds =
        u64NowMilliseconds() + 3600000U;
    for (const QString& strEndpointKey : m_setReceiverEndpoints)
    {
        const QString strRequestId = strCreateRequestId(
            QStringLiteral("source-map-install")
        );
        const AttackSourceMappingControlDetails detMapping(
            strRequestId.toStdString(),
            m_optContext->strRoundId(),
            AttackSourceMappingAction::Install,
            m_optContext->strTargetSenderId(),
            m_optContext->strTargetSenderIp(),
            m_strTestSourceIp.toStdString(),
            m_optContext->u64ChainId(),
            u64ExpiresAtMilliseconds
        );
        m_mapMappingRequestEndpoints.insert(strRequestId, strEndpointKey);
        if (!m_ctlNetwork.bSendNodeControl(
                strEndpointKey,
                NodeControlMessage(detMapping)
            ))
        {
            m_mapMappingRequestEndpoints.remove(strRequestId);
            strError = QStringLiteral("向Receiver %1下发临时来源映射失败")
                .arg(strEndpointKey);
            clearSourceMappings();
            return false;
        }
    }
    strError.clear();
    return true;
}

bool ManagerAttackExperimentController::bSendPlanDecision(
    bool bAccepted,
    const std::string& strErrorCode,
    const std::string& strMessage
)
{
    if (!m_optPlan.has_value())
    {
        return false;
    }
    return m_ctlNetwork.bSendAttackControl(
        m_strTestEndpointKey,
        AttackControlMessage(AttackPlanAcceptedControlDetails(
            m_optPlan->u64AttackId(),
            m_optPlan->strRoundId(),
            bAccepted,
            strErrorCode,
            strMessage
        ))
    );
}

bool ManagerAttackExperimentController::bSendPreparedCommand(
    AttackControlMessageType typeMessage,
    std::uint64_t u64ExecutionTimestampMilliseconds,
    QString& strError
)
{
    if (!m_optPlan.has_value())
    {
        strError = QStringLiteral("认证鲁棒性计划不存在");
        return false;
    }
    const AttackRoundCommandControlDetails detCommand(
        typeMessage,
        m_optPlan->u64AttackId(),
        m_optPlan->strRoundId(),
        u64ExecutionTimestampMilliseconds
    );
    if (!m_ctlNetwork.bSendAttackControl(
            m_strTestEndpointKey,
            AttackControlMessage(detCommand)
        ))
    {
        strError = QStringLiteral("向测试端下发执行命令失败");
        return false;
    }
    strError.clear();
    return true;
}

void ManagerAttackExperimentController::clearSourceMappings() noexcept
{
    m_mapMappingRequestEndpoints.clear();
    if (!m_optContext.has_value() || m_setReceiverEndpoints.isEmpty())
    {
        m_bMappingsInstalled = false;
        return;
    }

    for (const QString& strEndpointKey : m_setReceiverEndpoints)
    {
        const QString strRequestId = strCreateRequestId(
            QStringLiteral("source-map-clear")
        );
        const AttackSourceMappingControlDetails detMapping(
            strRequestId.toStdString(),
            m_optContext->strRoundId(),
            AttackSourceMappingAction::Clear,
            m_optContext->strTargetSenderId(),
            m_optContext->strTargetSenderIp(),
            m_strTestSourceIp.toStdString(),
            m_optContext->u64ChainId(),
            0
        );
        static_cast<void>(m_ctlNetwork.bSendNodeControl(
            strEndpointKey,
            NodeControlMessage(detMapping)
        ));
    }
    m_setReceiverEndpoints.clear();
    m_bMappingsInstalled = false;
}

void ManagerAttackExperimentController::rejectCurrentPlan(
    const QString& strErrorCode,
    const QString& strMessage
)
{
    static_cast<void>(bSendPlanDecision(
        false,
        strErrorCode.toStdString(),
        strMessage.toStdString()
    ));
    clearSourceMappings();
    m_optPlan.reset();
    m_bPlanPending = false;
    m_bReady = false;
    m_bRunning = false;
    emit message(strMessage);
    emit stateChanged();
}

void ManagerAttackExperimentController::clearPreparedState(
    bool bClearMappings
) noexcept
{
    if (bClearMappings)
    {
        clearSourceMappings();
    }
    m_strTestEndpointKey.clear();
    m_strTestSourceIp.clear();
    m_nSenderContextIndex = -1;
    m_optContext.reset();
    m_optPlan.reset();
    m_setReceiverEndpoints.clear();
    m_mapMappingRequestEndpoints.clear();
    m_bContextSent = false;
    m_bPlanPending = false;
    m_bReady = false;
    m_bRunning = false;
    m_bMappingsInstalled = false;
}

QString ManagerAttackExperimentController::strCreateRequestId(
    const QString& strPrefix
) const
{
    return strPrefix + QLatin1Char('-')
        + QUuid::createUuid().toString(QUuid::WithoutBraces);
}

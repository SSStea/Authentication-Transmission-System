#pragma once

#include "ManagerAuthenticationController.h"
#include "ManagerNetworkController.h"
#include "tesla/protocol/AttackControl.h"

#include <QHash>
#include <QObject>
#include <QSet>
#include <QString>

#include <cstdint>
#include <optional>

/**
 * @brief 管理认证鲁棒性测试的公开上下文、计划确认、临时来源映射和统一启停。
 *
 * 私有认证材料仍由ManagerAuthenticationController持有；本类只处理测试端能够
 * 获得的公开上下文，并把临时来源映射限制在当前轮次和指定Receiver集合内。
 */
class ManagerAttackExperimentController final : public QObject
{
    Q_OBJECT

public:
    explicit ManagerAttackExperimentController(
        ManagerNetworkController& ctlNetwork,
        ManagerAuthenticationController& ctlAuthentication,
        QObject* pParent = nullptr
    );

    bool bPrepareContext(
        const QString& strTestEndpointKey,
        int nSenderContextIndex,
        QString& strError
    );
    bool bStartPrepared(
        std::uint64_t u64StartTimestampMilliseconds,
        QString& strError
    );
    bool bStopPrepared(bool bEmergency, QString& strError);

    bool bContextSent() const noexcept;
    bool bPlanPending() const noexcept;
    bool bReady() const noexcept;
    bool bRunning() const noexcept;
    QString strStateText() const;
    QString strPlanSummary() const;

signals:
    void stateChanged();
    void message(const QString& strMessage);

private:
    void processAttackControlJson(
        const QString& strEndpointKey,
        const QString& strJson
    );
    void processNodeControlJson(
        const QString& strEndpointKey,
        const QString& strJson
    );
    void handleNodesChanged();
    bool bInstallSourceMappings(QString& strError);
    bool bSendPlanDecision(
        bool bAccepted,
        const std::string& strErrorCode,
        const std::string& strMessage
    );
    bool bSendPreparedCommand(
        tesla::protocol::AttackControlMessageType typeMessage,
        std::uint64_t u64ExecutionTimestampMilliseconds,
        QString& strError
    );
    void clearSourceMappings() noexcept;
    void rejectCurrentPlan(
        const QString& strErrorCode,
        const QString& strMessage
    );
    void clearPreparedState(bool bClearMappings) noexcept;
    QString strCreateRequestId(const QString& strPrefix) const;

    ManagerNetworkController&        m_ctlNetwork;
    ManagerAuthenticationController& m_ctlAuthentication;
    QString                          m_strTestEndpointKey;
    QString                          m_strTestSourceIp;
    int                              m_nSenderContextIndex;
    std::optional<tesla::protocol::AttackRoundContextControlDetails>
        m_optContext;
    std::optional<tesla::protocol::AttackPlanControlDetails> m_optPlan;
    QSet<QString>                    m_setReceiverEndpoints;
    QHash<QString, QString>          m_mapMappingRequestEndpoints;
    bool                             m_bContextSent;
    bool                             m_bPlanPending;
    bool                             m_bReady;
    bool                             m_bRunning;
    bool                             m_bMappingsInstalled;
};

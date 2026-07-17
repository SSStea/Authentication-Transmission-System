#pragma once

#include "ManagerNetworkController.h"
#include "tesla/core/AuthenticationAuthority.h"
#include "tesla/crypto/OpenSslSecureRandomProvider.h"
#include "tesla/protocol/ExperimentControl.h"

#include <QObject>
#include <QByteArray>
#include <QSet>
#include <QString>
#include <QVector>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

/**
 * @brief 集中管理端一次文本认证轮次的已校验输入。
 *
 * 载荷、算法和调度参数放在同一个值类型中，CA材料仍由控制器按Sender独立签发。
 */
class ManagerTextRoundConfiguration final
{
public:
    ManagerTextRoundConfiguration(
        tesla::protocol::UdpAuthenticationMode modeAuthentication,
        tesla::protocol::AuthenticationCryptoAlgorithm algCryptoAlgorithm,
        std::uint32_t u32TextRepeatCount,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32IntervalMilliseconds,
        std::optional<tesla::protocol::ImprovedTeslaControlParameters>
            optImprovedParameters,
        QString strText
    );

    tesla::protocol::UdpAuthenticationMode modeAuthentication() const noexcept;
    tesla::protocol::AuthenticationCryptoAlgorithm
        algCryptoAlgorithm() const noexcept;
    std::uint32_t u32TextRepeatCount() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    const std::optional<tesla::protocol::ImprovedTeslaControlParameters>&
        optImprovedParameters() const noexcept;
    const QString& strText() const noexcept;

private:
    tesla::protocol::UdpAuthenticationMode m_modeAuthentication;
    tesla::protocol::AuthenticationCryptoAlgorithm m_algCryptoAlgorithm;
    std::uint32_t m_u32TextRepeatCount;
    std::uint32_t m_u32PacketsPerInterval;
    std::uint32_t m_u32DisclosureDelay;
    std::uint32_t m_u32IntervalMilliseconds;
    std::optional<tesla::protocol::ImprovedTeslaControlParameters>
        m_optImprovedParameters;
    QString m_strText;
};

/** @brief 集中管理端一次文件认证轮次的已校验输入和原始Hash。 */
class ManagerFileRoundConfiguration final
{
public:
    ManagerFileRoundConfiguration(
        tesla::protocol::UdpAuthenticationMode modeAuthentication,
        tesla::protocol::AuthenticationCryptoAlgorithm algCryptoAlgorithm,
        std::uint32_t u32PacketsPerInterval,
        std::uint32_t u32DisclosureDelay,
        std::uint32_t u32IntervalMilliseconds,
        std::optional<tesla::protocol::ImprovedTeslaControlParameters>
            optImprovedParameters,
        std::shared_ptr<const QByteArray> ptrFileBytes,
        QByteArray arrOriginalSha256
    );

    tesla::protocol::UdpAuthenticationMode modeAuthentication() const noexcept;
    tesla::protocol::AuthenticationCryptoAlgorithm
        algCryptoAlgorithm() const noexcept;
    std::uint32_t u32PacketsPerInterval() const noexcept;
    std::uint32_t u32DisclosureDelay() const noexcept;
    std::uint32_t u32IntervalMilliseconds() const noexcept;
    const std::optional<tesla::protocol::ImprovedTeslaControlParameters>&
        optImprovedParameters() const noexcept;
    const std::shared_ptr<const QByteArray>& ptrFileBytes() const noexcept;
    const QByteArray& arrOriginalSha256() const noexcept;

private:
    tesla::protocol::UdpAuthenticationMode m_modeAuthentication;
    tesla::protocol::AuthenticationCryptoAlgorithm m_algCryptoAlgorithm;
    std::uint32_t m_u32PacketsPerInterval;
    std::uint32_t m_u32DisclosureDelay;
    std::uint32_t m_u32IntervalMilliseconds;
    std::optional<tesla::protocol::ImprovedTeslaControlParameters>
        m_optImprovedParameters;
    std::shared_ptr<const QByteArray> m_ptrFileBytes;
    QByteArray m_arrOriginalSha256;
};

/**
 * @brief 管理CA材料、配置确认和统一开始/暂停/继续/停止时间线。
 *
 * 控制器只经ManagerNetworkController发送强类型控制消息，不直接操作Socket。
 */
class ManagerAuthenticationController final : public QObject
{
    Q_OBJECT

public:
    explicit ManagerAuthenticationController(
        ManagerNetworkController& ctlNetwork,
        QObject* pParent = nullptr
    );

    bool bPrepareTextRound(
        const ManagerTextRoundConfiguration& cfgRound,
        const QSet<QString>& setSelectedSenderEndpoints,
        const QVector<ManagerNodeSnapshot>& vecNodeSnapshots,
        QString& strError
    );
    bool bPrepareFileRound(
        const ManagerFileRoundConfiguration& cfgRound,
        const QSet<QString>& setSelectedSenderEndpoints,
        const QVector<ManagerNodeSnapshot>& vecNodeSnapshots,
        QString& strError
    );
    bool bStartRound(QString& strError);
    /** @brief 使用编排器提供的唯一时间启动，保证节点与测试端共享同一时间基准。 */
    bool bStartRoundAt(
        std::uint64_t u64StartTimestampMilliseconds,
        QString& strError
    );
    bool bPauseRound(QString& strError);
    bool bResumeRound(QString& strError);
    bool bStopRound(QString& strError);
    bool bConfigureFaultPlan(
        int nSenderContextIndex,
        tesla::protocol::AuthenticationFaultDetails varFaultDetails,
        QString& strError
    );

    bool bConfigurationReady() const noexcept;
    bool bFaultConfigured() const noexcept;
    bool bFaultPlanPending() const noexcept;
    bool bFaultPlanReady() const noexcept;
    bool bRoundRunning() const noexcept;
    bool bRoundPaused() const noexcept;
    QString strRoundId() const noexcept;
    QVector<tesla::protocol::AttackRoundContextControlDetails>
        vecAttackRoundContexts() const;
    QString strSenderEndpointKey(int nSenderContextIndex) const;
    QVector<QString> vecReceiverEndpointKeys(int nSenderContextIndex) const;

signals:
    void configurationStateChanged(bool bReady, const QString& strMessage);
    void faultPlanStateChanged(bool bReady, const QString& strMessage);
    void roundStateChanged(bool bRunning, bool bPaused);
    void resultMessage(const QString& strMessage);
    void fileComparisonResult(
        const QString& strSenderId,
        quint64 u64ChainId,
        quint64 u64OriginalByteCount,
        quint64 u64RecoveredByteCount,
        const QString& strOriginalSha256,
        const QString& strRecoveredSha256,
        bool bMatches
    );

private:
    struct SenderTarget final
    {
        QString strEndpointKey;
        QString strIpAddress;
        tesla::core::SenderAuthenticationMaterial matMaterial;
    };

    void processNodeControlJson(
        const QString& strEndpointKey,
        const QString& strJson
    );
    void handleNodeStateChanged();
    bool bSendRequired(
        const QString& strEndpointKey,
        const tesla::protocol::NodeControlMessage& msgMessage,
        const QString& strRequestId,
        QString& strError
    );
    bool bBroadcastRoundCommand(
        tesla::protocol::AuthenticationRoundCommand cmdCommand,
        std::uint64_t u64ExecutionTimestampMilliseconds,
        std::uint32_t u32LogicalIntervalIndex,
        QString& strError
    );
    tesla::protocol::AuthenticationRoundControlParameters
        prmControlParameters(
            const tesla::core::AuthenticationRoundParameters& prmParameters
        ) const;
    QString strCreateRequestId(const QString& strPrefix) const;
    void resetPreparedRound();

    ManagerNetworkController& m_ctlNetwork;
    tesla::crypto::OpenSslSecureRandomProvider m_rngSecureRandom;
    tesla::core::AuthenticationAuthority m_autAuthority;
    std::vector<SenderTarget> m_vecSenderTargets;
    QSet<QString> m_setParticipantEndpoints;
    QSet<QString> m_setPendingConfigurationRequests;
    QSet<QString> m_setPendingFaultRequests;
    QSet<QString> m_setReceivedResultKeys;
    bool m_bConfigurationRejected;
    bool m_bConfigurationReady;
    bool m_bFaultConfigured;
    bool m_bFaultRejected;
    bool m_bFaultReady;
    bool m_bRoundRunning;
    bool m_bRoundPaused;
    bool m_bFileRound;
    QString m_strRoundId;
    std::uint32_t m_u32IntervalMilliseconds;
    std::uint32_t m_u32LastLogicalInterval;
    std::uint32_t m_u32TimelineFirstInterval;
    std::uint32_t m_u32PauseAfterInterval;
    std::uint64_t m_u64TimelineStartTimestampMilliseconds;
    std::uint64_t m_u64PauseTimestampMilliseconds;
    std::size_t m_nExpectedResultCount;
    QByteArray m_arrOriginalFileSha256;
    std::uint64_t m_u64OriginalFileByteCount = 0;
};

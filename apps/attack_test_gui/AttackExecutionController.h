#pragma once

#include "tesla/protocol/AttackControl.h"

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QVector>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>

class QUdpSocket;

/** @brief 攻击端本地逐次捕获和发送记录，供GUI显示及CSV/JSON导出。 */
class AttackExecutionRecord final
{
public:
    AttackExecutionRecord(
        std::uint64_t u64AttackId,
        tesla::protocol::AttackType typeAttack,
        std::uint32_t u32PacketIndex,
        std::uint64_t u64CaptureTimestampMilliseconds,
        std::uint64_t u64SendTimestampMilliseconds,
        QByteArray arrOriginalDatagram,
        QByteArray arrSentDatagram,
        bool bSent,
        QString strMessage
    );

    std::uint64_t u64AttackId() const noexcept;
    tesla::protocol::AttackType typeAttack() const noexcept;
    std::uint32_t u32PacketIndex() const noexcept;
    std::uint64_t u64CaptureTimestampMilliseconds() const noexcept;
    std::uint64_t u64SendTimestampMilliseconds() const noexcept;
    const QByteArray& arrOriginalDatagram() const noexcept;
    const QByteArray& arrSentDatagram() const noexcept;
    bool bSent() const noexcept;
    const QString& strMessage() const noexcept;

private:
    std::uint64_t             m_u64AttackId;
    tesla::protocol::AttackType m_typeAttack;
    std::uint32_t             m_u32PacketIndex;
    std::uint64_t             m_u64CaptureTimestampMilliseconds;
    std::uint64_t             m_u64SendTimestampMilliseconds;
    QByteArray                m_arrOriginalDatagram;
    QByteArray                m_arrSentDatagram;
    bool                      m_bSent;
    QString                   m_strMessage;
};

/**
 * @brief 统一管理篡改、重放和DoS的计划、捕获、工作线程、停止和统计。
 *
 * 三种模式共享同一生命周期和内部组播发送边界；模式专用参数仍由std::variant隔离。
 */
class AttackExecutionController final : public QObject
{
    Q_OBJECT

public:
    explicit AttackExecutionController(
        QString strMulticastAddress,
        std::uint16_t u16MulticastPort,
        QObject* pParent = nullptr
    );
    ~AttackExecutionController() override;

    AttackExecutionController(const AttackExecutionController&) = delete;
    AttackExecutionController& operator=(const AttackExecutionController&) = delete;

    bool bConfigureContext(
        const tesla::protocol::AttackRoundContextControlDetails& detContext,
        QString& strError
    );
    bool bPreparePlan(
        const tesla::protocol::AttackPlanControlDetails& detPlan,
        bool bConfirmThresholdExceeded,
        QString& strError
    );
    bool bAcceptPlan(
        std::uint64_t u64AttackId,
        const std::string& strRoundId,
        QString& strError
    );
    /** @brief 管理端拒绝或发送失败时仅丢弃当前计划，保留公开上下文以便重新配置。 */
    void discardPlan() noexcept;
    bool bScheduleStart(
        std::uint64_t u64AttackId,
        const std::string& strRoundId,
        std::uint64_t u64StartTimestampMilliseconds,
        QString& strError
    );
    void stop(bool bEmergency) noexcept;

    void processCapturedDatagram(
        const QByteArray& arrDatagram,
        const QString& strSourceIp,
        std::uint64_t u64CaptureTimestampMilliseconds
    );

    tesla::protocol::AttackExecutionState stateExecution() const noexcept;
    bool bHasContext() const noexcept;
    bool bHasPlan() const noexcept;
    std::optional<tesla::protocol::AttackRoundContextControlDetails>
        optContextSnapshot() const;
    std::optional<tesla::protocol::AttackPlanControlDetails>
        optPlanSnapshot() const;
    tesla::protocol::AttackExecutionStatusControlDetails detStatusSnapshot() const;
    QVector<AttackExecutionRecord> vecRecordSnapshot() const;

signals:
    void stateChanged();
    void recordAdded();
    void logMessage(const QString& strMessage);

private:
    struct SendTask final
    {
        QByteArray    arrDatagram;
        QByteArray    arrOriginalDatagram;
        std::uint32_t u32PacketIndex = 0;
        std::uint64_t u64CaptureTimestampMilliseconds = 0;
        std::uint64_t u64DueTimestampMilliseconds = 0;
        QString       strMessage;
    };

    void workerLoop();
    void runDos();
    bool bSendDatagram(
        QUdpSocket& udpSocket,
        const QByteArray& arrDatagram,
        std::uint32_t u32PacketIndex,
        std::uint64_t u64CaptureTimestampMilliseconds,
        const QByteArray& arrOriginalDatagram,
        const QString& strMessage
    );
    void setState(tesla::protocol::AttackExecutionState stateExecution);
    void stopWorker(bool bPreserveTerminalState) noexcept;
    std::uint64_t u64NowMilliseconds() const noexcept;

    QString       m_strMulticastAddress;
    std::uint16_t m_u16MulticastPort;

    mutable std::mutex m_mtxState;
    std::condition_variable m_cndState;
    std::thread m_thrWorker;
    std::optional<tesla::protocol::AttackRoundContextControlDetails>
        m_optContext;
    std::optional<tesla::protocol::AttackPlanControlDetails> m_optPlan;
    std::deque<SendTask> m_deqTasks;
    std::set<std::uint32_t> m_setCapturedPacketIndexes;
    std::deque<AttackExecutionRecord> m_deqRecords;
    tesla::protocol::AttackExecutionState m_stateExecution;
    std::uint64_t m_u64StartTimestampMilliseconds;
    std::uint64_t m_u64ExecutionStartedMilliseconds;
    std::uint64_t m_u64CapturedPacketCount;
    std::uint64_t m_u64SentPacketCount;
    std::uint64_t m_u64SentByteCount;
    std::uint64_t m_u64SendErrorCount;
    std::uint64_t m_u64LastInjectionDelayMicroseconds;
    bool m_bStopRequested;
};

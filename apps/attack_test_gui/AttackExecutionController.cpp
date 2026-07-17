#include "AttackExecutionController.h"

#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <QHostAddress>
#include <QUdpSocket>

#include <algorithm>
#include <chrono>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>
#include <variant>

namespace
{
using SystemClock = std::chrono::system_clock;
constexpr std::size_t MAX_PENDING_SEND_TASKS = 4096;
constexpr std::size_t MAX_RECORD_ROWS = 20000;
constexpr qsizetype MESSAGE_OFFSET = static_cast<qsizetype>(
    tesla::protocol::UdpAuthenticationPacketCodec::FIXED_HEADER_SIZE
);

tesla::protocol::ByteBuffer vecBytes(const QByteArray& arrBytes)
{
    if (arrBytes.isEmpty())
    {
        return {};
    }

    return tesla::protocol::ByteBuffer(
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData()),
        reinterpret_cast<const std::uint8_t*>(arrBytes.constData())
            + arrBytes.size()
    );
}
}

AttackExecutionRecord::AttackExecutionRecord(
    std::uint64_t u64AttackId,
    tesla::protocol::AttackType typeAttack,
    std::uint32_t u32PacketIndex,
    std::uint64_t u64CaptureTimestampMilliseconds,
    std::uint64_t u64SendTimestampMilliseconds,
    QByteArray arrOriginalDatagram,
    QByteArray arrSentDatagram,
    bool bSent,
    QString strMessage
)
    : m_u64AttackId(u64AttackId),
      m_typeAttack(typeAttack),
      m_u32PacketIndex(u32PacketIndex),
      m_u64CaptureTimestampMilliseconds(u64CaptureTimestampMilliseconds),
      m_u64SendTimestampMilliseconds(u64SendTimestampMilliseconds),
      m_arrOriginalDatagram(std::move(arrOriginalDatagram)),
      m_arrSentDatagram(std::move(arrSentDatagram)),
      m_bSent(bSent),
      m_strMessage(std::move(strMessage))
{
}

std::uint64_t AttackExecutionRecord::u64AttackId() const noexcept
{
    return m_u64AttackId;
}

tesla::protocol::AttackType AttackExecutionRecord::typeAttack() const noexcept
{
    return m_typeAttack;
}

std::uint32_t AttackExecutionRecord::u32PacketIndex() const noexcept
{
    return m_u32PacketIndex;
}

std::uint64_t AttackExecutionRecord::u64CaptureTimestampMilliseconds() const noexcept
{
    return m_u64CaptureTimestampMilliseconds;
}

std::uint64_t AttackExecutionRecord::u64SendTimestampMilliseconds() const noexcept
{
    return m_u64SendTimestampMilliseconds;
}

const QByteArray& AttackExecutionRecord::arrOriginalDatagram() const noexcept
{
    return m_arrOriginalDatagram;
}

const QByteArray& AttackExecutionRecord::arrSentDatagram() const noexcept
{
    return m_arrSentDatagram;
}

bool AttackExecutionRecord::bSent() const noexcept
{
    return m_bSent;
}

const QString& AttackExecutionRecord::strMessage() const noexcept
{
    return m_strMessage;
}

AttackExecutionController::AttackExecutionController(
    QString strMulticastAddress,
    std::uint16_t u16MulticastPort,
    QObject* pParent
)
    : QObject(pParent),
      m_strMulticastAddress(std::move(strMulticastAddress)),
      m_u16MulticastPort(u16MulticastPort),
      m_stateExecution(tesla::protocol::AttackExecutionState::Idle),
      m_u64StartTimestampMilliseconds(0),
      m_u64ExecutionStartedMilliseconds(0),
      m_u64CapturedPacketCount(0),
      m_u64SentPacketCount(0),
      m_u64SentByteCount(0),
      m_u64SendErrorCount(0),
      m_u64LastInjectionDelayMicroseconds(0),
      m_bStopRequested(false)
{
    if (QHostAddress(m_strMulticastAddress).protocol()
            != QAbstractSocket::IPv4Protocol
        || m_u16MulticastPort == 0)
    {
        throw std::invalid_argument("Attack executor multicast target is invalid");
    }
}

AttackExecutionController::~AttackExecutionController()
{
    stopWorker(false);
}

bool AttackExecutionController::bConfigureContext(
    const tesla::protocol::AttackRoundContextControlDetails& detContext,
    QString& strError
)
{
    stopWorker(false);

    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_optContext = detContext;
        m_optPlan.reset();
        m_deqTasks.clear();
        m_setCapturedPacketIndexes.clear();
        m_deqRecords.clear();
        m_u64CapturedPacketCount = 0;
        m_u64SentPacketCount = 0;
        m_u64SentByteCount = 0;
        m_u64SendErrorCount = 0;
        m_u64LastInjectionDelayMicroseconds = 0;
        m_stateExecution = tesla::protocol::AttackExecutionState::ContextReady;
    }

    strError.clear();
    emit stateChanged();
    emit logMessage(QStringLiteral("已接收目标公开上下文：%1 / chain %2")
        .arg(QString::fromStdString(detContext.strTargetSenderId()))
        .arg(detContext.u64ChainId()));
    return true;
}

bool AttackExecutionController::bPreparePlan(
    const tesla::protocol::AttackPlanControlDetails& detPlan,
    bool bConfirmThresholdExceeded,
    QString& strError
)
{
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (!m_optContext.has_value()
            || m_stateExecution == tesla::protocol::AttackExecutionState::Running
            || m_stateExecution == tesla::protocol::AttackExecutionState::Scheduled)
        {
            strError = QStringLiteral("攻击端尚无可用上下文或已有攻击正在执行");
            return false;
        }

        const auto& detContext = m_optContext.value();
        if (detPlan.strRoundId() != detContext.strRoundId())
        {
            strError = QStringLiteral("攻击计划轮次与公开上下文不一致");
            return false;
        }

        if (detPlan.typeAttack() != tesla::protocol::AttackType::Dos
            && (detPlan.strTargetSenderId() != detContext.strTargetSenderId()
                || detPlan.u64ChainId() != detContext.u64ChainId()))
        {
            strError = QStringLiteral("攻击计划目标Sender或chain不一致");
            return false;
        }

        const auto fnIndexesValid = [&detContext](
            const std::vector<std::uint32_t>& vecIndexes
        )
        {
            return std::all_of(
                vecIndexes.begin(),
                vecIndexes.end(),
                [&detContext](std::uint32_t u32PacketIndex)
                {
                    return u32PacketIndex > 0
                        && u32PacketIndex <= detContext.u32DataPacketCount();
                }
            );
        };
        if (const auto* pTamper = std::get_if<
                tesla::protocol::TamperAttackPlanDetails
            >(&detPlan.varPlanDetails()))
        {
            if (!fnIndexesValid(pTamper->vecPacketIndexes()))
            {
                strError = QStringLiteral("篡改目标报文编号超出本轮范围");
                return false;
            }

            if (detContext.modeAuthentication()
                    == tesla::protocol::UdpAuthenticationMode::Improved
                && !bConfirmThresholdExceeded)
            {
                std::map<std::uint32_t, std::uint32_t> mapGroupCounts;
                for (std::uint32_t u32PacketIndex : pTamper->vecPacketIndexes())
                {
                    const std::uint32_t u32GroupIndex =
                        ((u32PacketIndex - 1U) / detContext.u32GroupSize()) + 1U;
                    ++mapGroupCounts[u32GroupIndex];
                }
                const bool bExceeded = std::any_of(
                    mapGroupCounts.begin(),
                    mapGroupCounts.end(),
                    [&detContext](const auto& prCount)
                    {
                        return prCount.second > detContext.u32DetectionThreshold();
                    }
                );
                if (bExceeded)
                {
                    strError = QStringLiteral(
                        "篡改位置超过检测阈值，不保证准确定位；需要明确确认"
                    );
                    return false;
                }
            }
        }
        else if (const auto* pReplay = std::get_if<
                     tesla::protocol::ReplayAttackPlanDetails
                 >(&detPlan.varPlanDetails()))
        {
            if (!fnIndexesValid(pReplay->vecPacketIndexes()))
            {
                strError = QStringLiteral("重放目标报文编号超出本轮范围");
                return false;
            }
        }

        m_optPlan = detPlan;
        m_deqTasks.clear();
        m_setCapturedPacketIndexes.clear();
        m_stateExecution = tesla::protocol::AttackExecutionState::PlanPending;
    }

    strError.clear();
    emit stateChanged();
    return true;
}

bool AttackExecutionController::bAcceptPlan(
    std::uint64_t u64AttackId,
    const std::string& strRoundId,
    QString& strError
)
{
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (!m_optPlan.has_value()
            || m_optPlan->u64AttackId() != u64AttackId
            || m_optPlan->strRoundId() != strRoundId
            || m_stateExecution
                != tesla::protocol::AttackExecutionState::PlanPending)
        {
            strError = QStringLiteral("计划接受消息与当前待确认计划不匹配");
            return false;
        }

        m_stateExecution = tesla::protocol::AttackExecutionState::Ready;
    }

    strError.clear();
    emit stateChanged();
    return true;
}

void AttackExecutionController::discardPlan() noexcept
{
    stopWorker(false);
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_optPlan.reset();
        m_deqTasks.clear();
        m_setCapturedPacketIndexes.clear();
        m_deqRecords.clear();
        m_u64StartTimestampMilliseconds = 0;
        m_u64ExecutionStartedMilliseconds = 0;
        m_u64CapturedPacketCount = 0;
        m_u64SentPacketCount = 0;
        m_u64SentByteCount = 0;
        m_u64SendErrorCount = 0;
        m_u64LastInjectionDelayMicroseconds = 0;
        m_stateExecution = m_optContext.has_value()
            ? tesla::protocol::AttackExecutionState::ContextReady
            : tesla::protocol::AttackExecutionState::Idle;
    }

    emit stateChanged();
}

bool AttackExecutionController::bScheduleStart(
    std::uint64_t u64AttackId,
    const std::string& strRoundId,
    std::uint64_t u64StartTimestampMilliseconds,
    QString& strError
)
{
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (!m_optPlan.has_value()
            || m_optPlan->u64AttackId() != u64AttackId
            || m_optPlan->strRoundId() != strRoundId
            || m_stateExecution != tesla::protocol::AttackExecutionState::Ready
            || u64StartTimestampMilliseconds <= u64NowMilliseconds() + 100U)
        {
            strError = QStringLiteral("攻击开始命令与计划不匹配或开始时间过近");
            return false;
        }

        m_u64StartTimestampMilliseconds = u64StartTimestampMilliseconds;
        m_bStopRequested = false;
        m_stateExecution = tesla::protocol::AttackExecutionState::Scheduled;
    }

    if (m_thrWorker.joinable())
    {
        m_thrWorker.join();
    }
    m_thrWorker = std::thread([this]()
    {
        workerLoop();
    });
    strError.clear();
    emit stateChanged();
    return true;
}

void AttackExecutionController::stop(bool bEmergency) noexcept
{
    stopWorker(true);
    emit logMessage(
        bEmergency
            ? QStringLiteral("攻击已紧急停止并清空待发送缓存")
            : QStringLiteral("攻击已停止并清空捕获缓存")
    );
}

void AttackExecutionController::processCapturedDatagram(
    const QByteArray& arrDatagram,
    const QString& strSourceIp,
    std::uint64_t u64CaptureTimestampMilliseconds
)
{
    bool    bShouldNotifyState = false;
    QString strLogMessage;

    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (!m_optContext.has_value()
            || !m_optPlan.has_value()
            || m_stateExecution != tesla::protocol::AttackExecutionState::Running
            || m_optPlan->typeAttack() == tesla::protocol::AttackType::Dos
            || QHostAddress(strSourceIp)
                != QHostAddress(QString::fromStdString(
                    m_optContext->strTargetSenderIp()
                )))
        {
            return;
        }

        const tesla::protocol::ByteBuffer vecDatagram = vecBytes(arrDatagram);
        const auto resHeader =
            tesla::protocol::UdpAuthenticationPacketCodec::resDecodeHeader(
                vecDatagram
            );
        if (!std::holds_alternative<
                tesla::protocol::UdpAuthenticationPacketHeader
            >(resHeader))
        {
            return;
        }

        const auto& hdrPacket = std::get<
            tesla::protocol::UdpAuthenticationPacketHeader
        >(resHeader);
        if (hdrPacket.u64ChainId() != m_optContext->u64ChainId()
            || hdrPacket.u32PacketIndex() == 0)
        {
            return;
        }

        const tesla::protocol::UdpAuthenticationPacketContext ctxPacket(
            m_optContext->modeAuthentication(),
            m_optContext->u32PacketsPerInterval(),
            m_optContext->u32DisclosureDelay(),
            m_optContext->u32DataPacketCount(),
            m_optContext->u32GroupSize(),
            m_optContext->nTauCount()
        );
        const auto resPacket =
            tesla::protocol::UdpAuthenticationPacketCodec::resDecode(
                vecDatagram,
                ctxPacket
            );
        if (!std::holds_alternative<tesla::protocol::UdpAuthenticationPacket>(
                resPacket
            ))
        {
            return;
        }

        const auto fnTargeted = [&hdrPacket](
            const std::vector<std::uint32_t>& vecIndexes
        )
        {
            return std::find(
                vecIndexes.begin(),
                vecIndexes.end(),
                hdrPacket.u32PacketIndex()
            ) != vecIndexes.end();
        };

        QByteArray arrAttack = arrDatagram;
        std::uint32_t u32RepeatCount = 0;
        std::uint32_t u32FirstDelayMilliseconds = 0;
        std::uint32_t u32RepeatGapMilliseconds = 0;
        QString strMessage;
        if (const auto* pTamper = std::get_if<
                tesla::protocol::TamperAttackPlanDetails
            >(&m_optPlan->varPlanDetails()))
        {
            if (!fnTargeted(pTamper->vecPacketIndexes())
                || arrAttack.size() < MESSAGE_OFFSET + 32)
            {
                return;
            }
            const qsizetype nWireOffset =
                MESSAGE_OFFSET + pTamper->u8MessageByteOffset();
            arrAttack[nWireOffset] = static_cast<char>(
                static_cast<std::uint8_t>(arrAttack.at(nWireOffset))
                    ^ pTamper->u8XorMask()
            );
            u32RepeatCount = pTamper->u32RepeatCount();
            strMessage = QStringLiteral("篡改冲突副本");
        }
        else
        {
            const auto& detReplay = std::get<
                tesla::protocol::ReplayAttackPlanDetails
            >(m_optPlan->varPlanDetails());
            if (!fnTargeted(detReplay.vecPacketIndexes()))
            {
                return;
            }
            u32RepeatCount = detReplay.u32RepeatCount();
            u32FirstDelayMilliseconds =
                detReplay.u32ReplayDelayMilliseconds();
            u32RepeatGapMilliseconds =
                detReplay.u32RepeatGapMilliseconds();
            strMessage = QStringLiteral("原始负载延迟重放");
        }

        if (!m_setCapturedPacketIndexes.insert(hdrPacket.u32PacketIndex()).second)
        {
            return;
        }
        if (m_deqTasks.size() + u32RepeatCount > MAX_PENDING_SEND_TASKS)
        {
            ++m_u64SendErrorCount;
            strLogMessage = QStringLiteral("攻击待发送缓存已达上限，拒绝新增任务");
        }
        else
        {
            ++m_u64CapturedPacketCount;
            for (std::uint32_t u32RepeatIndex = 0;
                 u32RepeatIndex < u32RepeatCount;
                 ++u32RepeatIndex)
            {
                m_deqTasks.push_back(SendTask{
                    arrAttack,
                    arrDatagram,
                    hdrPacket.u32PacketIndex(),
                    u64CaptureTimestampMilliseconds,
                    u64CaptureTimestampMilliseconds
                        + u32FirstDelayMilliseconds
                        + static_cast<std::uint64_t>(u32RepeatIndex)
                            * u32RepeatGapMilliseconds,
                    strMessage
                });
            }
            m_cndState.notify_all();
            bShouldNotifyState = true;
        }
    }

    if (!strLogMessage.isEmpty())
    {
        emit logMessage(strLogMessage);
    }
    if (bShouldNotifyState)
    {
        emit stateChanged();
    }
}

tesla::protocol::AttackExecutionState
AttackExecutionController::stateExecution() const noexcept
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    return m_stateExecution;
}

bool AttackExecutionController::bHasContext() const noexcept
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    return m_optContext.has_value();
}

bool AttackExecutionController::bHasPlan() const noexcept
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    return m_optPlan.has_value();
}

std::optional<tesla::protocol::AttackRoundContextControlDetails>
AttackExecutionController::optContextSnapshot() const
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    return m_optContext;
}

std::optional<tesla::protocol::AttackPlanControlDetails>
AttackExecutionController::optPlanSnapshot() const
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    return m_optPlan;
}

tesla::protocol::AttackExecutionStatusControlDetails
AttackExecutionController::detStatusSnapshot() const
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    if (!m_optPlan.has_value())
    {
        throw std::logic_error("Attack execution status requires a plan");
    }

    tesla::protocol::AttackExecutionStatusDetails varDetails =
        tesla::protocol::DosAttackStatusDetails(0, 0, 0.0);
    if (m_optPlan->typeAttack() == tesla::protocol::AttackType::Tamper)
    {
        varDetails = tesla::protocol::TamperAttackStatusDetails(
            m_u64CapturedPacketCount,
            m_u64SentPacketCount,
            m_u64LastInjectionDelayMicroseconds
        );
    }
    else if (m_optPlan->typeAttack() == tesla::protocol::AttackType::Replay)
    {
        varDetails = tesla::protocol::ReplayAttackStatusDetails(
            m_u64CapturedPacketCount,
            m_u64SentPacketCount
        );
    }
    else
    {
        const std::uint64_t u64ElapsedMilliseconds =
            m_u64ExecutionStartedMilliseconds == 0
            ? 0
            : std::max<std::uint64_t>(
                1,
                u64NowMilliseconds() - m_u64ExecutionStartedMilliseconds
            );
        varDetails = tesla::protocol::DosAttackStatusDetails(
            m_u64SentPacketCount,
            m_u64SentByteCount,
            static_cast<double>(m_u64SentPacketCount) * 1000.0
                / static_cast<double>(
                    std::max<std::uint64_t>(1, u64ElapsedMilliseconds)
                )
        );
    }

    return tesla::protocol::AttackExecutionStatusControlDetails(
        m_optPlan->u64AttackId(),
        m_optPlan->strRoundId(),
        m_stateExecution,
        std::move(varDetails),
        m_u64SendErrorCount,
        u64NowMilliseconds(),
        "Attack execution status snapshot"
    );
}

QVector<AttackExecutionRecord> AttackExecutionController::vecRecordSnapshot() const
{
    std::lock_guard<std::mutex> lckState(m_mtxState);
    QVector<AttackExecutionRecord> vecRecords;
    vecRecords.reserve(static_cast<qsizetype>(m_deqRecords.size()));
    for (const AttackExecutionRecord& recAttack : m_deqRecords)
    {
        vecRecords.push_back(recAttack);
    }
    return vecRecords;
}

void AttackExecutionController::workerLoop()
{
    {
        std::unique_lock<std::mutex> lckState(m_mtxState);
        const auto tpStart = SystemClock::time_point(
            std::chrono::milliseconds(m_u64StartTimestampMilliseconds)
        );
        m_cndState.wait_until(
            lckState,
            tpStart,
            [this]()
            {
                return m_bStopRequested;
            }
        );
        if (m_bStopRequested)
        {
            return;
        }
        m_stateExecution = tesla::protocol::AttackExecutionState::Running;
        m_u64ExecutionStartedMilliseconds = u64NowMilliseconds();
    }
    emit stateChanged();

    const auto optPlan = optPlanSnapshot();
    if (!optPlan.has_value())
    {
        setState(tesla::protocol::AttackExecutionState::Stopped);
        return;
    }
    if (optPlan->typeAttack() == tesla::protocol::AttackType::Dos)
    {
        runDos();
        return;
    }

    QUdpSocket udpSocket;
    while (true)
    {
        SendTask tskSend;
        {
            std::unique_lock<std::mutex> lckState(m_mtxState);
            m_cndState.wait(
                lckState,
                [this]()
                {
                    return m_bStopRequested || !m_deqTasks.empty();
                }
            );
            if (m_bStopRequested)
            {
                return;
            }

            auto itTask = std::min_element(
                m_deqTasks.begin(),
                m_deqTasks.end(),
                [](const SendTask& tskLeft, const SendTask& tskRight)
                {
                    return tskLeft.u64DueTimestampMilliseconds
                        < tskRight.u64DueTimestampMilliseconds;
                }
            );
            const auto tpDue = SystemClock::time_point(
                std::chrono::milliseconds(itTask->u64DueTimestampMilliseconds)
            );
            if (SystemClock::now() < tpDue)
            {
                m_cndState.wait_until(lckState, tpDue);
                continue;
            }

            tskSend = std::move(*itTask);
            m_deqTasks.erase(itTask);
        }

        bSendDatagram(
            udpSocket,
            tskSend.arrDatagram,
            tskSend.u32PacketIndex,
            tskSend.u64CaptureTimestampMilliseconds,
            tskSend.arrOriginalDatagram,
            tskSend.strMessage
        );
    }
}

void AttackExecutionController::runDos()
{
    const auto optPlan = optPlanSnapshot();
    if (!optPlan.has_value())
    {
        return;
    }
    const auto& detDos = std::get<tesla::protocol::DosAttackPlanDetails>(
        optPlan->varPlanDetails()
    );
    const QByteArray arrInvalid(
        static_cast<qsizetype>(detDos.u32PacketBytes()),
        static_cast<char>(0xA5)
    );
    const auto tpStart = std::chrono::steady_clock::now();
    const auto durPeriod = std::chrono::nanoseconds(
        1'000'000'000LL / detDos.u32RatePacketsPerSecond()
    );
    const auto tpEnd = tpStart
        + std::chrono::milliseconds(detDos.u32DurationMilliseconds());
    std::uint64_t u64Sequence = 0;
    QUdpSocket udpSocket;
    while (std::chrono::steady_clock::now() < tpEnd)
    {
        {
            std::unique_lock<std::mutex> lckState(m_mtxState);
            if (m_bStopRequested)
            {
                return;
            }
            const auto tpTarget = tpStart + durPeriod * u64Sequence;
            m_cndState.wait_until(
                lckState,
                tpTarget,
                [this]()
                {
                    return m_bStopRequested;
                }
            );
            if (m_bStopRequested)
            {
                return;
            }
        }

        bSendDatagram(
            udpSocket,
            arrInvalid,
            0,
            0,
            QByteArray(),
            QStringLiteral("DoS无效二进制数据报")
        );
        ++u64Sequence;
    }

    setState(tesla::protocol::AttackExecutionState::Completed);
}

bool AttackExecutionController::bSendDatagram(
    QUdpSocket& udpSocket,
    const QByteArray& arrDatagram,
    std::uint32_t u32PacketIndex,
    std::uint64_t u64CaptureTimestampMilliseconds,
    const QByteArray& arrOriginalDatagram,
    const QString& strMessage
)
{
    const qint64 nSent = udpSocket.writeDatagram(
        arrDatagram,
        QHostAddress(m_strMulticastAddress),
        m_u16MulticastPort
    );
    const bool bSent = nSent == arrDatagram.size();
    const std::uint64_t u64SendTimestampMilliseconds = u64NowMilliseconds();

    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (bSent)
        {
            ++m_u64SentPacketCount;
            m_u64SentByteCount += static_cast<std::uint64_t>(arrDatagram.size());
        }
        else
        {
            ++m_u64SendErrorCount;
        }
        if (u64CaptureTimestampMilliseconds > 0)
        {
            m_u64LastInjectionDelayMicroseconds =
                (u64SendTimestampMilliseconds
                    - u64CaptureTimestampMilliseconds) * 1000U;
        }

        // Keep detailed rows bounded; aggregate counters above still cover
        // the whole execution even when older rows are evicted.
        if (m_deqRecords.size() >= MAX_RECORD_ROWS)
        {
            m_deqRecords.pop_front();
        }
        m_deqRecords.push_back(AttackExecutionRecord(
            m_optPlan->u64AttackId(),
            m_optPlan->typeAttack(),
            u32PacketIndex,
            u64CaptureTimestampMilliseconds,
            u64SendTimestampMilliseconds,
            arrOriginalDatagram,
            arrDatagram,
            bSent,
            strMessage
        ));
    }
    emit recordAdded();
    emit stateChanged();
    return bSent;
}

void AttackExecutionController::setState(
    tesla::protocol::AttackExecutionState stateExecution
)
{
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_stateExecution = stateExecution;
    }
    emit stateChanged();
}

void AttackExecutionController::stopWorker(bool bPreserveTerminalState) noexcept
{
    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        m_bStopRequested = true;
        m_deqTasks.clear();
        m_setCapturedPacketIndexes.clear();
        m_cndState.notify_all();
    }
    if (m_thrWorker.joinable())
    {
        m_thrWorker.join();
    }

    {
        std::lock_guard<std::mutex> lckState(m_mtxState);
        if (bPreserveTerminalState
            && m_stateExecution != tesla::protocol::AttackExecutionState::Idle
            && m_stateExecution
                != tesla::protocol::AttackExecutionState::ContextReady)
        {
            m_stateExecution = tesla::protocol::AttackExecutionState::Stopped;
        }
        m_bStopRequested = false;
    }
    if (bPreserveTerminalState)
    {
        emit stateChanged();
    }
}

std::uint64_t AttackExecutionController::u64NowMilliseconds() const noexcept
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            SystemClock::now().time_since_epoch()
        ).count()
    );
}

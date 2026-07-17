#include "AttackTestMainWindow.h"

#include "tesla/protocol/UdpAuthenticationPacketCodec.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QStyle>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <exception>
#include <map>
#include <set>
#include <utility>
#include <variant>

namespace
{
using namespace tesla::protocol;

QLabel* pStateValue(QWidget* pParent)
{
    QLabel* pLabel = new QLabel(QStringLiteral("未知"), pParent);
    pLabel->setObjectName(QStringLiteral("stateValue"));
    pLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    return pLabel;
}

QString strExecutionState(AttackExecutionState stateExecution)
{
    switch (stateExecution)
    {
    case AttackExecutionState::Idle:
        return QStringLiteral("空闲");
    case AttackExecutionState::ContextReady:
        return QStringLiteral("公开上下文已就绪");
    case AttackExecutionState::PlanPending:
        return QStringLiteral("等待管理端确认");
    case AttackExecutionState::Ready:
        return QStringLiteral("三方启动准备中");
    case AttackExecutionState::Scheduled:
        return QStringLiteral("已按统一时间调度");
    case AttackExecutionState::Running:
        return QStringLiteral("异常流量模拟运行中");
    case AttackExecutionState::Completed:
        return QStringLiteral("已完成");
    case AttackExecutionState::Stopped:
        return QStringLiteral("已停止");
    case AttackExecutionState::Failed:
        return QStringLiteral("执行失败");
    }
    return QStringLiteral("未知");
}

QString strType(AttackType typeAttack)
{
    switch (typeAttack)
    {
    case AttackType::Tamper:
        return QStringLiteral("Message冲突副本");
    case AttackType::Replay:
        return QStringLiteral("延迟重复报文");
    case AttackType::Dos:
        return QStringLiteral("高频无效流量");
    }
    return QStringLiteral("未知");
}

QString strTypeCode(AttackType typeAttack)
{
    switch (typeAttack)
    {
    case AttackType::Tamper:
        return QStringLiteral("MESSAGE_CONFLICT_COPY");
    case AttackType::Replay:
        return QStringLiteral("DELAYED_DUPLICATE");
    case AttackType::Dos:
        return QStringLiteral("HIGH_RATE_INVALID_TRAFFIC");
    }
    return QStringLiteral("UNKNOWN");
}

QString strExecutionStateCode(AttackExecutionState stateExecution)
{
    switch (stateExecution)
    {
    case AttackExecutionState::Idle:
        return QStringLiteral("IDLE");
    case AttackExecutionState::ContextReady:
        return QStringLiteral("CONTEXT_READY");
    case AttackExecutionState::PlanPending:
        return QStringLiteral("PLAN_PENDING");
    case AttackExecutionState::Ready:
        return QStringLiteral("READY");
    case AttackExecutionState::Scheduled:
        return QStringLiteral("SCHEDULED");
    case AttackExecutionState::Running:
        return QStringLiteral("RUNNING");
    case AttackExecutionState::Completed:
        return QStringLiteral("COMPLETED");
    case AttackExecutionState::Stopped:
        return QStringLiteral("STOPPED");
    case AttackExecutionState::Failed:
        return QStringLiteral("FAILED");
    }
    return QStringLiteral("UNKNOWN");
}

QString strAuthenticationModeCode(UdpAuthenticationMode modeAuthentication)
{
    return modeAuthentication == UdpAuthenticationMode::Native
        ? QStringLiteral("NATIVE")
        : QStringLiteral("IMPROVED");
}

QString strCryptoAlgorithmCode(AuthenticationCryptoAlgorithm algCryptoAlgorithm)
{
    switch (algCryptoAlgorithm)
    {
    case AuthenticationCryptoAlgorithm::Sha256:
        return QStringLiteral("SHA-256");
    case AuthenticationCryptoAlgorithm::Sm3:
        return QStringLiteral("SM3");
    case AuthenticationCryptoAlgorithm::Sha3_256:
        return QStringLiteral("SHA3-256");
    }
    return QStringLiteral("UNKNOWN");
}

QString strPacketIndexes(const std::vector<std::uint32_t>& vecIndexes)
{
    QStringList listIndexes;
    listIndexes.reserve(static_cast<qsizetype>(vecIndexes.size()));
    for (const std::uint32_t u32Index : vecIndexes)
    {
        listIndexes.push_back(QString::number(u32Index));
    }
    return listIndexes.join(QLatin1Char(';'));
}

QJsonArray arrPacketIndexes(const std::vector<std::uint32_t>& vecIndexes)
{
    QJsonArray arrIndexes;
    for (const std::uint32_t u32Index : vecIndexes)
    {
        arrIndexes.append(static_cast<qint64>(u32Index));
    }
    return arrIndexes;
}

QString strUInt64(std::uint64_t u64Value)
{
    return QString::number(static_cast<qulonglong>(u64Value));
}

QString strHex(const QByteArray& arrBytes)
{
    return QString::fromLatin1(arrBytes.toHex());
}

QString strCsv(const QString& strValue)
{
    QString strEscaped = strValue;
    strEscaped.replace(QLatin1Char('"'), QStringLiteral("\"\""));
    return QLatin1Char('"') + strEscaped + QLatin1Char('"');
}

QTableWidgetItem* pReadOnlyItem(const QString& strText)
{
    QTableWidgetItem* pItem = new QTableWidgetItem(strText);
    pItem->setFlags(pItem->flags() & ~Qt::ItemIsEditable);
    return pItem;
}
}

AttackTestMainWindow::AttackTestMainWindow(
    std::uint16_t u16DiscoveryPort,
    std::uint16_t u16ControlPort,
    std::uint16_t u16MulticastPort,
    QWidget* pParent
)
    : QMainWindow(pParent),
      m_ctlNetwork(
          u16DiscoveryPort,
          u16ControlPort,
          QStringLiteral("239.10.10.10"),
          u16MulticastPort,
          std::chrono::milliseconds(1000),
          nullptr
      ),
      m_pServiceValue(nullptr),
      m_pControlValue(nullptr),
      m_pMulticastValue(nullptr),
      m_pExecutionValue(nullptr),
      m_pContextRoundValue(nullptr),
      m_pContextSenderValue(nullptr),
      m_pContextNetworkValue(nullptr),
      m_pContextParametersValue(nullptr),
      m_pTypeCombo(nullptr),
      m_pPacketIndexesEdit(nullptr),
      m_pRepeatSpin(nullptr),
      m_pOffsetSpin(nullptr),
      m_pMaskSpin(nullptr),
      m_pDelaySpin(nullptr),
      m_pGapSpin(nullptr),
      m_pRateSpin(nullptr),
      m_pDurationSpin(nullptr),
      m_pBytesSpin(nullptr),
      m_pThresholdConfirmCheck(nullptr),
      m_pValidationLabel(nullptr),
      m_pSubmitButton(nullptr),
      m_pLocalStopButton(nullptr),
      m_pLocalEmergencyButton(nullptr),
      m_pRecordTable(nullptr),
      m_pCapturedValue(nullptr),
      m_pSentValue(nullptr),
      m_pRateValue(nullptr),
      m_pByteValue(nullptr),
      m_pDelayValue(nullptr),
      m_pErrorValue(nullptr),
      m_pLogEdit(nullptr)
{
    setWindowTitle(QStringLiteral("TESLA 认证鲁棒性测试端"));
    resize(1320, 820);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("TESLA 认证鲁棒性测试端 · ")
            + m_ctlNetwork.strNodeName(),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateStatusPage(), QStringLiteral("管理连接"));
    pTabs->addTab(pCreateContextPage(), QStringLiteral("公开上下文"));
    pTabs->addTab(pCreatePlanPage(), QStringLiteral("测试计划"));
    pTabs->addTab(pCreateRecordPage(), QStringLiteral("执行记录"));
    pTabs->addTab(pCreateStatisticsPage(), QStringLiteral("统计"));
    pTabs->addTab(pCreateLogPage(), QStringLiteral("日志"));
    pLayout->addWidget(pTabs, 1);
    setCentralWidget(pCentralWidget);
    applyStyle();

    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::stateChanged,
        this,
        &AttackTestMainWindow::refreshStatus
    );
    connect(
        &m_ctlNetwork,
        &AttackTestNetworkController::logMessage,
        this,
        &AttackTestMainWindow::appendLog
    );

    if (!m_ctlNetwork.bStart())
    {
        appendLog(QStringLiteral("认证鲁棒性测试端网络服务启动失败"));
    }
    refreshStatus();
}

QWidget* AttackTestMainWindow::pCreateStatusPage()
{
    QWidget* pPage = new QWidget(this);
    QFormLayout* pLayout = new QFormLayout(pPage);
    m_pServiceValue = pStateValue(pPage);
    m_pControlValue = pStateValue(pPage);
    m_pMulticastValue = pStateValue(pPage);
    m_pExecutionValue = pStateValue(pPage);
    pLayout->addRow(QStringLiteral("测试端服务"), m_pServiceValue);
    pLayout->addRow(QStringLiteral("管理TCP客户端"), m_pControlValue);
    pLayout->addRow(QStringLiteral("TESLA组播监听"), m_pMulticastValue);
    pLayout->addRow(QStringLiteral("执行状态"), m_pExecutionValue);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "本程序只接收本轮公开认证上下文，异常流量目标固定为系统内部TESLA组播；"
            "不接收种子、未披露密钥、完整文件或任意外部目标。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addRow(pHintLabel);
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateContextPage()
{
    QWidget* pPage = new QWidget(this);
    QFormLayout* pLayout = new QFormLayout(pPage);
    m_pContextRoundValue = pStateValue(pPage);
    m_pContextSenderValue = pStateValue(pPage);
    m_pContextNetworkValue = pStateValue(pPage);
    m_pContextParametersValue = pStateValue(pPage);
    pLayout->addRow(QStringLiteral("轮次"), m_pContextRoundValue);
    pLayout->addRow(QStringLiteral("目标Sender"), m_pContextSenderValue);
    pLayout->addRow(QStringLiteral("公开网络标识"), m_pContextNetworkValue);
    pLayout->addRow(QStringLiteral("认证参数"), m_pContextParametersValue);
    pLayout->addRow(new QLabel(
        QStringLiteral("上下文由集中管理端选择并下发，本页面只读。"),
        pPage
    ));
    return pPage;
}

QWidget* AttackTestMainWindow::pCreatePlanPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pRootLayout = new QVBoxLayout(pPage);
    QFormLayout* pLayout = new QFormLayout();
    m_pTypeCombo = new QComboBox(pPage);
    m_pTypeCombo->addItems({
        QStringLiteral("Message冲突副本"),
        QStringLiteral("延迟重复报文"),
        QStringLiteral("高频无效流量")
    });
    m_pPacketIndexesEdit = new QLineEdit(QStringLiteral("1"), pPage);
    m_pPacketIndexesEdit->setPlaceholderText(QStringLiteral("例如：1,3-5"));
    m_pRepeatSpin = new QSpinBox(pPage);
    m_pRepeatSpin->setRange(1, 1000);
    m_pOffsetSpin = new QSpinBox(pPage);
    m_pOffsetSpin->setRange(0, 31);
    m_pMaskSpin = new QSpinBox(pPage);
    m_pMaskSpin->setRange(1, 255);
    m_pMaskSpin->setValue(1);
    m_pDelaySpin = new QSpinBox(pPage);
    m_pDelaySpin->setRange(1, 600000);
    m_pDelaySpin->setValue(500);
    m_pGapSpin = new QSpinBox(pPage);
    m_pGapSpin->setRange(0, 60000);
    m_pGapSpin->setValue(50);
    m_pRateSpin = new QSpinBox(pPage);
    m_pRateSpin->setRange(1, 20000);
    m_pRateSpin->setValue(1000);
    m_pDurationSpin = new QSpinBox(pPage);
    m_pDurationSpin->setRange(1, 60000);
    m_pDurationSpin->setValue(5000);
    m_pBytesSpin = new QSpinBox(pPage);
    m_pBytesSpin->setRange(1, 1472);
    m_pBytesSpin->setValue(96);
    m_pThresholdConfirmCheck = new QCheckBox(
        QStringLiteral("确认执行超过定位阈值的诊断轮次"),
        pPage
    );

    pLayout->addRow(QStringLiteral("测试类型"), m_pTypeCombo);
    pLayout->addRow(QStringLiteral("目标报文编号"), m_pPacketIndexesEdit);
    pLayout->addRow(QStringLiteral("相同副本次数"), m_pRepeatSpin);
    pLayout->addRow(QStringLiteral("Message字节位置"), m_pOffsetSpin);
    pLayout->addRow(QStringLiteral("XOR掩码"), m_pMaskSpin);
    pLayout->addRow(QStringLiteral("重复延迟ms"), m_pDelaySpin);
    pLayout->addRow(QStringLiteral("重复间隔ms"), m_pGapSpin);
    pLayout->addRow(QStringLiteral("无效流量PPS"), m_pRateSpin);
    pLayout->addRow(QStringLiteral("持续时间ms"), m_pDurationSpin);
    pLayout->addRow(QStringLiteral("单包字节数"), m_pBytesSpin);
    pLayout->addRow(m_pThresholdConfirmCheck);
    pRootLayout->addLayout(pLayout);

    m_pValidationLabel = new QLabel(pPage);
    m_pValidationLabel->setWordWrap(true);
    pRootLayout->addWidget(m_pValidationLabel);

    QHBoxLayout* pButtons = new QHBoxLayout();
    m_pSubmitButton = new QPushButton(QStringLiteral("提交计划"), pPage);
    m_pSubmitButton->setObjectName(QStringLiteral("primaryButton"));
    m_pLocalStopButton = new QPushButton(QStringLiteral("本地停止"), pPage);
    m_pLocalEmergencyButton = new QPushButton(QStringLiteral("本地紧急停止"), pPage);
    pButtons->addWidget(m_pSubmitButton);
    pButtons->addWidget(m_pLocalStopButton);
    pButtons->addWidget(m_pLocalEmergencyButton);
    pButtons->addStretch();
    pRootLayout->addLayout(pButtons);
    pRootLayout->addStretch();

    const auto fnChanged = [this]()
    {
        refreshPlanControls();
    };
    connect(m_pTypeCombo, &QComboBox::currentIndexChanged, this, fnChanged);
    connect(m_pPacketIndexesEdit, &QLineEdit::textChanged, this, fnChanged);
    connect(m_pRepeatSpin, &QSpinBox::valueChanged, this, fnChanged);
    connect(m_pGapSpin, &QSpinBox::valueChanged, this, fnChanged);
    connect(m_pThresholdConfirmCheck, &QCheckBox::toggled, this, fnChanged);
    connect(m_pSubmitButton, &QPushButton::clicked, this, &AttackTestMainWindow::submitPlan);
    connect(m_pLocalStopButton, &QPushButton::clicked, this, [this]()
    {
        stopLocally(false);
    });
    connect(m_pLocalEmergencyButton, &QPushButton::clicked, this, [this]()
    {
        stopLocally(true);
    });
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateRecordPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QHBoxLayout* pButtons = new QHBoxLayout();
    QPushButton* pCsvButton = new QPushButton(QStringLiteral("导出CSV"), pPage);
    QPushButton* pJsonButton = new QPushButton(QStringLiteral("导出JSON"), pPage);
    pButtons->addWidget(pCsvButton);
    pButtons->addWidget(pJsonButton);
    pButtons->addStretch();
    pLayout->addLayout(pButtons);

    m_pRecordTable = new QTableWidget(0, 10, pPage);
    m_pRecordTable->setHorizontalHeaderLabels({
        QStringLiteral("计划ID"),
        QStringLiteral("类型"),
        QStringLiteral("报文编号"),
        QStringLiteral("捕获时间"),
        QStringLiteral("发送时间"),
        QStringLiteral("延迟ms"),
        QStringLiteral("结果"),
        QStringLiteral("原Message"),
        QStringLiteral("发送Message"),
        QStringLiteral("说明")
    });
    m_pRecordTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_pRecordTable->horizontalHeader()->setStretchLastSection(true);
    m_pRecordTable->verticalHeader()->setVisible(false);
    m_pRecordTable->setAlternatingRowColors(true);
    m_pRecordTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    pLayout->addWidget(m_pRecordTable, 1);

    connect(pCsvButton, &QPushButton::clicked, this, [this]()
    {
        exportRecords(false);
    });
    connect(pJsonButton, &QPushButton::clicked, this, [this]()
    {
        exportRecords(true);
    });
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateStatisticsPage()
{
    QWidget* pPage = new QWidget(this);
    QFormLayout* pLayout = new QFormLayout(pPage);
    m_pCapturedValue = pStateValue(pPage);
    m_pSentValue = pStateValue(pPage);
    m_pRateValue = pStateValue(pPage);
    m_pByteValue = pStateValue(pPage);
    m_pDelayValue = pStateValue(pPage);
    m_pErrorValue = pStateValue(pPage);
    pLayout->addRow(QStringLiteral("匹配捕获数"), m_pCapturedValue);
    pLayout->addRow(QStringLiteral("实际发送数"), m_pSentValue);
    pLayout->addRow(QStringLiteral("实际PPS"), m_pRateValue);
    pLayout->addRow(QStringLiteral("发送字节数"), m_pByteValue);
    pLayout->addRow(QStringLiteral("最近注入延迟"), m_pDelayValue);
    pLayout->addRow(QStringLiteral("发送错误数"), m_pErrorValue);
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateLogPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    m_pLogEdit = new QTextEdit(pPage);
    m_pLogEdit->setReadOnly(true);
    m_pLogEdit->setPlaceholderText(QStringLiteral("真实控制和执行日志将在此显示"));
    pLayout->addWidget(m_pLogEdit);
    return pPage;
}

void AttackTestMainWindow::refreshStatus()
{
    m_pServiceValue->setText(
        m_ctlNetwork.bIsRunning() ? QStringLiteral("运行中") : QStringLiteral("停止")
    );
    m_pControlValue->setText(QStringLiteral("%1个管理客户端")
        .arg(m_ctlNetwork.nConnectedClientCount()));
    m_pMulticastValue->setText(
        m_ctlNetwork.bMulticastListening()
            ? QStringLiteral("监听中")
            : QStringLiteral("未监听")
    );
    m_pExecutionValue->setText(strExecutionState(
        m_ctlNetwork.stateAttackExecution()
    ));
    refreshContext();
    refreshPlanControls();
    refreshRecords();
    refreshStatistics();
}

void AttackTestMainWindow::refreshContext()
{
    const auto optContext = m_ctlNetwork.optRoundContextSnapshot();
    if (!optContext.has_value())
    {
        m_pContextRoundValue->setText(QStringLiteral("尚未下发"));
        m_pContextSenderValue->setText(QStringLiteral("—"));
        m_pContextNetworkValue->setText(QStringLiteral("—"));
        m_pContextParametersValue->setText(QStringLiteral("—"));
        return;
    }

    const auto& detContext = optContext.value();
    m_pContextRoundValue->setText(QString::fromStdString(detContext.strRoundId()));
    m_pContextSenderValue->setText(QStringLiteral("%1 / chain %2")
        .arg(QString::fromStdString(detContext.strTargetSenderId()))
        .arg(detContext.u64ChainId()));
    m_pContextNetworkValue->setText(QStringLiteral("%1 / 内部TESLA组播")
        .arg(QString::fromStdString(detContext.strTargetSenderIp())));
    m_pContextParametersValue->setText(QStringLiteral(
        "%1 / %2，数据报文=%3，每间隔=%4，间隔=%5ms，披露延迟=%6，分组=%7，阈值=%8"
    )
        .arg(detContext.modeAuthentication() == UdpAuthenticationMode::Native
            ? QStringLiteral("原生TESLA")
            : QStringLiteral("改进TESLA"))
        .arg(strCryptoAlgorithmCode(detContext.algCryptoAlgorithm()))
        .arg(detContext.u32DataPacketCount())
        .arg(detContext.u32PacketsPerInterval())
        .arg(detContext.u32IntervalMilliseconds())
        .arg(detContext.u32DisclosureDelay())
        .arg(detContext.u32GroupSize())
        .arg(detContext.u32DetectionThreshold()));
}

void AttackTestMainWindow::refreshPlanControls()
{
    const int nType = m_pTypeCombo->currentIndex();
    const bool bTamper = nType == 0;
    const bool bReplay = nType == 1;
    const bool bDos = nType == 2;
    m_pPacketIndexesEdit->setEnabled(!bDos);
    m_pRepeatSpin->setEnabled(!bDos);
    m_pOffsetSpin->setEnabled(bTamper);
    m_pMaskSpin->setEnabled(bTamper);
    m_pDelaySpin->setEnabled(bReplay);
    m_pGapSpin->setEnabled(bReplay && m_pRepeatSpin->value() > 1);
    m_pRateSpin->setEnabled(bDos);
    m_pDurationSpin->setEnabled(bDos);
    m_pBytesSpin->setEnabled(bDos);

    QString strError;
    bool bThresholdExceeded = false;
    const bool bInputsValid = bValidatePlanInputs(strError, bThresholdExceeded);
    const auto stateExecution = m_ctlNetwork.stateAttackExecution();
    const bool bCanSubmit = bInputsValid
        && m_ctlNetwork.nConnectedClientCount() == 1U
        && m_ctlNetwork.bMulticastListening()
        && stateExecution != AttackExecutionState::PlanPending
        && stateExecution != AttackExecutionState::Ready
        && stateExecution != AttackExecutionState::Scheduled
        && stateExecution != AttackExecutionState::Running;
    m_pSubmitButton->setEnabled(bCanSubmit);
    m_pLocalStopButton->setEnabled(
        stateExecution == AttackExecutionState::Scheduled
            || stateExecution == AttackExecutionState::Running
    );
    m_pLocalEmergencyButton->setEnabled(m_pLocalStopButton->isEnabled());

    m_pPacketIndexesEdit->setProperty("invalidInput", !bInputsValid && !bDos);
    m_pPacketIndexesEdit->style()->unpolish(m_pPacketIndexesEdit);
    m_pPacketIndexesEdit->style()->polish(m_pPacketIndexesEdit);
    m_pThresholdConfirmCheck->setVisible(bTamper && bThresholdExceeded);
    if (bInputsValid)
    {
        m_pValidationLabel->setText(QStringLiteral("参数有效，可以提交给集中管理端。"));
        m_pValidationLabel->setObjectName(QStringLiteral("validLabel"));
    }
    else
    {
        m_pValidationLabel->setText(strError);
        m_pValidationLabel->setObjectName(QStringLiteral("errorLabel"));
    }
    m_pValidationLabel->style()->unpolish(m_pValidationLabel);
    m_pValidationLabel->style()->polish(m_pValidationLabel);
}

void AttackTestMainWindow::refreshRecords()
{
    const QVector<AttackExecutionRecord> vecRecords =
        m_ctlNetwork.vecAttackRecordSnapshot();
    m_pRecordTable->setRowCount(vecRecords.size());
    for (qsizetype nRow = 0; nRow < vecRecords.size(); ++nRow)
    {
        const AttackExecutionRecord& recRecord = vecRecords.at(nRow);
        const std::uint64_t u64DelayMilliseconds =
            recRecord.u64CaptureTimestampMilliseconds() == 0
            || recRecord.u64SendTimestampMilliseconds()
                < recRecord.u64CaptureTimestampMilliseconds()
            ? 0
            : recRecord.u64SendTimestampMilliseconds()
                - recRecord.u64CaptureTimestampMilliseconds();
        m_pRecordTable->setItem(nRow, 0, pReadOnlyItem(QString::number(recRecord.u64AttackId())));
        m_pRecordTable->setItem(nRow, 1, pReadOnlyItem(strType(recRecord.typeAttack())));
        m_pRecordTable->setItem(nRow, 2, pReadOnlyItem(QString::number(recRecord.u32PacketIndex())));
        m_pRecordTable->setItem(nRow, 3, pReadOnlyItem(
            recRecord.u64CaptureTimestampMilliseconds() == 0
                ? QStringLiteral("—")
                : QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(
                    recRecord.u64CaptureTimestampMilliseconds()
                )).toString(QStringLiteral("HH:mm:ss.zzz"))
        ));
        m_pRecordTable->setItem(nRow, 4, pReadOnlyItem(QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(recRecord.u64SendTimestampMilliseconds())
        ).toString(QStringLiteral("HH:mm:ss.zzz"))));
        m_pRecordTable->setItem(nRow, 5, pReadOnlyItem(QString::number(u64DelayMilliseconds)));
        m_pRecordTable->setItem(nRow, 6, pReadOnlyItem(
            recRecord.bSent() ? QStringLiteral("已发送") : QStringLiteral("失败")
        ));
        m_pRecordTable->setItem(nRow, 7, pReadOnlyItem(
            strDatagramMessage(recRecord.arrOriginalDatagram())
        ));
        m_pRecordTable->setItem(nRow, 8, pReadOnlyItem(
            strDatagramMessage(recRecord.arrSentDatagram())
        ));
        m_pRecordTable->setItem(nRow, 9, pReadOnlyItem(recRecord.strMessage()));
    }
}

void AttackTestMainWindow::refreshStatistics()
{
    m_pCapturedValue->setText(QStringLiteral("0"));
    m_pSentValue->setText(QStringLiteral("0"));
    m_pRateValue->setText(QStringLiteral("0.00"));
    m_pByteValue->setText(QStringLiteral("0"));
    m_pDelayValue->setText(QStringLiteral("0 μs"));
    m_pErrorValue->setText(QStringLiteral("0"));

    const auto optStatus = m_ctlNetwork.optExecutionStatusSnapshot();
    if (!optStatus.has_value())
    {
        return;
    }

    const auto& detStatus = optStatus.value();
    m_pErrorValue->setText(QString::number(detStatus.u64SendErrorCount()));
    if (const auto* pTamper = std::get_if<TamperAttackStatusDetails>(
            &detStatus.varStatusDetails()
        ))
    {
        m_pCapturedValue->setText(QString::number(pTamper->u64CapturedPacketCount()));
        m_pSentValue->setText(QString::number(pTamper->u64InjectedPacketCount()));
        m_pDelayValue->setText(QStringLiteral("%1 μs")
            .arg(pTamper->u64LastInjectionDelayMicroseconds()));
    }
    else if (const auto* pReplay = std::get_if<ReplayAttackStatusDetails>(
                 &detStatus.varStatusDetails()
             ))
    {
        m_pCapturedValue->setText(QString::number(pReplay->u64CapturedPacketCount()));
        m_pSentValue->setText(QString::number(pReplay->u64ReplayedPacketCount()));
    }
    else
    {
        const auto& detDos = std::get<DosAttackStatusDetails>(
            detStatus.varStatusDetails()
        );
        m_pSentValue->setText(QString::number(detDos.u64SentPacketCount()));
        m_pRateValue->setText(QString::number(detDos.dActualPacketsPerSecond(), 'f', 2));
        m_pByteValue->setText(QString::number(detDos.u64SentByteCount()));
    }
}

void AttackTestMainWindow::submitPlan()
{
    QString strError;
    bool bThresholdExceeded = false;
    if (!bValidatePlanInputs(strError, bThresholdExceeded))
    {
        m_pValidationLabel->setText(strError);
        return;
    }

    try
    {
        AttackPlanDetails varPlan = DosAttackPlanDetails(1, 1, 1);
        if (m_pTypeCombo->currentIndex() == 0)
        {
            varPlan = TamperAttackPlanDetails(
                vecPacketIndexes(strError),
                static_cast<std::uint8_t>(m_pOffsetSpin->value()),
                static_cast<std::uint8_t>(m_pMaskSpin->value()),
                static_cast<std::uint32_t>(m_pRepeatSpin->value())
            );
        }
        else if (m_pTypeCombo->currentIndex() == 1)
        {
            varPlan = ReplayAttackPlanDetails(
                vecPacketIndexes(strError),
                static_cast<std::uint32_t>(m_pDelaySpin->value()),
                static_cast<std::uint32_t>(m_pRepeatSpin->value()),
                static_cast<std::uint32_t>(m_pGapSpin->value())
            );
        }
        else
        {
            varPlan = DosAttackPlanDetails(
                static_cast<std::uint32_t>(m_pRateSpin->value()),
                static_cast<std::uint32_t>(m_pDurationSpin->value()),
                static_cast<std::uint32_t>(m_pBytesSpin->value())
            );
        }

        if (!m_ctlNetwork.bSubmitPlan(
                std::move(varPlan),
                bThresholdExceeded && m_pThresholdConfirmCheck->isChecked(),
                strError
            ))
        {
            m_pValidationLabel->setText(strError);
            return;
        }
        appendLog(QStringLiteral("计划已提交，等待管理端配置Receiver并确认"));
    }
    catch (const std::exception& exError)
    {
        m_pValidationLabel->setText(QString::fromUtf8(exError.what()));
    }
    refreshStatus();
}

void AttackTestMainWindow::stopLocally(bool bEmergency)
{
    m_ctlNetwork.stopLocalExecution(bEmergency);
    appendLog(
        bEmergency
            ? QStringLiteral("已执行本地紧急停止")
            : QStringLiteral("已执行本地停止")
    );
}

void AttackTestMainWindow::exportRecords(bool bJson)
{
    const QVector<AttackExecutionRecord> vecRecords =
        m_ctlNetwork.vecAttackRecordSnapshot();
    if (vecRecords.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("导出"), QStringLiteral("当前没有执行记录。"));
        return;
    }


    const auto optContext = m_ctlNetwork.optRoundContextSnapshot();
    const auto optPlan = m_ctlNetwork.optPlanSnapshot();
    const auto optStatus = m_ctlNetwork.optExecutionStatusSnapshot();
    if (!optContext.has_value() || !optPlan.has_value() || !optStatus.has_value())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("导出失败"),
            QStringLiteral("当前执行记录缺少轮次、计划或统计上下文。")
        );
        return;
    }

    const AttackRoundContextControlDetails& detContext = *optContext;
    const AttackPlanControlDetails& detPlan = *optPlan;
    const AttackExecutionStatusControlDetails& detStatus = *optStatus;

    // 实验标识只由公开配置生成，同一配置的多次run可被归为同一实验组。
    const QString strExperimentId = QStringLiteral(
        "tesla-robustness-%1-%2-%3-p%4-ppi%5-i%6-d%7-g%8-t%9"
    )
        .arg(strAuthenticationModeCode(detContext.modeAuthentication()))
        .arg(strCryptoAlgorithmCode(detContext.algCryptoAlgorithm()))
        .arg(QString::fromStdString(detContext.strTargetSenderId()))
        .arg(detContext.u32DataPacketCount())
        .arg(detContext.u32PacketsPerInterval())
        .arg(detContext.u32IntervalMilliseconds())
        .arg(detContext.u32DisclosureDelay())
        .arg(detContext.u32GroupSize())
        .arg(detContext.u32DetectionThreshold());
    const QString strRunId = QString::fromStdString(detPlan.strRoundId());
    const QString strGitCommit = QString::fromUtf8(TESLA_GIT_COMMIT);
    const QString strLocalIpv4Address = m_ctlNetwork.strLocalIpv4Address();
    const QString strSourceIp = strLocalIpv4Address.isEmpty()
        ? QStringLiteral("UNAVAILABLE")
        : strLocalIpv4Address;
    std::uint64_t u64RoundTimestampMilliseconds = 0;
    for (const AttackExecutionRecord& recRecord : vecRecords)
    {
        const std::uint64_t u64Candidate =
            recRecord.u64CaptureTimestampMilliseconds() == 0
            ? recRecord.u64SendTimestampMilliseconds()
            : recRecord.u64CaptureTimestampMilliseconds();
        if (u64Candidate > 0
            && (u64RoundTimestampMilliseconds == 0
                || u64Candidate < u64RoundTimestampMilliseconds))
        {
            u64RoundTimestampMilliseconds = u64Candidate;
        }
    }

    QString     strConfiguredTargetPackets;
    QString     strMessageByteOffset;
    QString     strXorMask;
    QString     strRepeatCount;
    QString     strReplayDelayMilliseconds;
    QString     strRepeatGapMilliseconds;
    QString     strConfiguredRate;
    QString     strConfiguredDuration;
    QString     strConfiguredPacketBytes;
    QJsonObject objPlanDetails;
    if (const auto* pTamper = std::get_if<TamperAttackPlanDetails>(
            &detPlan.varPlanDetails()
        ))
    {
        strConfiguredTargetPackets = strPacketIndexes(pTamper->vecPacketIndexes());
        strMessageByteOffset = QString::number(pTamper->u8MessageByteOffset());
        strXorMask = QStringLiteral("0x%1").arg(
            pTamper->u8XorMask(), 2, 16, QLatin1Char('0')
        );
        strRepeatCount = QString::number(pTamper->u32RepeatCount());
        objPlanDetails.insert(
            QStringLiteral("packetIndexes"),
            arrPacketIndexes(pTamper->vecPacketIndexes())
        );
        objPlanDetails.insert(
            QStringLiteral("messageByteOffset"),
            static_cast<qint64>(pTamper->u8MessageByteOffset())
        );
        objPlanDetails.insert(QStringLiteral("xorMask"), strXorMask);
        objPlanDetails.insert(
            QStringLiteral("repeatCount"),
            static_cast<qint64>(pTamper->u32RepeatCount())
        );
    }
    else if (const auto* pReplay = std::get_if<ReplayAttackPlanDetails>(
                 &detPlan.varPlanDetails()
             ))
    {
        strConfiguredTargetPackets = strPacketIndexes(pReplay->vecPacketIndexes());
        strRepeatCount = QString::number(pReplay->u32RepeatCount());
        strReplayDelayMilliseconds =
            QString::number(pReplay->u32ReplayDelayMilliseconds());
        strRepeatGapMilliseconds =
            QString::number(pReplay->u32RepeatGapMilliseconds());
        objPlanDetails.insert(
            QStringLiteral("packetIndexes"),
            arrPacketIndexes(pReplay->vecPacketIndexes())
        );
        objPlanDetails.insert(
            QStringLiteral("replayDelayMs"),
            static_cast<qint64>(pReplay->u32ReplayDelayMilliseconds())
        );
        objPlanDetails.insert(
            QStringLiteral("repeatCount"),
            static_cast<qint64>(pReplay->u32RepeatCount())
        );
        objPlanDetails.insert(
            QStringLiteral("repeatGapMs"),
            static_cast<qint64>(pReplay->u32RepeatGapMilliseconds())
        );
    }
    else
    {
        const auto& detTraffic = std::get<DosAttackPlanDetails>(
            detPlan.varPlanDetails()
        );
        strConfiguredTargetPackets = QStringLiteral("CONTINUOUS_INVALID_DATAGRAMS");
        strConfiguredRate =
            QString::number(detTraffic.u32RatePacketsPerSecond());
        strConfiguredDuration =
            QString::number(detTraffic.u32DurationMilliseconds());
        strConfiguredPacketBytes =
            QString::number(detTraffic.u32PacketBytes());
        objPlanDetails.insert(
            QStringLiteral("ratePacketsPerSecond"),
            static_cast<qint64>(detTraffic.u32RatePacketsPerSecond())
        );
        objPlanDetails.insert(
            QStringLiteral("durationMs"),
            static_cast<qint64>(detTraffic.u32DurationMilliseconds())
        );
        objPlanDetails.insert(
            QStringLiteral("packetBytes"),
            static_cast<qint64>(detTraffic.u32PacketBytes())
        );
    }

    std::uint64_t u64CapturedPacketCount = 0;
    std::uint64_t u64SentPacketCount = 0;
    std::uint64_t u64SentByteCount = 0;
    std::uint64_t u64LastDelayMicroseconds = 0;
    double        dActualPacketsPerSecond = 0.0;
    QJsonObject   objStatistics;
    if (const auto* pTamper = std::get_if<TamperAttackStatusDetails>(
            &detStatus.varStatusDetails()
        ))
    {
        u64CapturedPacketCount = pTamper->u64CapturedPacketCount();
        u64SentPacketCount = pTamper->u64InjectedPacketCount();
        u64LastDelayMicroseconds = pTamper->u64LastInjectionDelayMicroseconds();
    }
    else if (const auto* pReplay = std::get_if<ReplayAttackStatusDetails>(
                 &detStatus.varStatusDetails()
             ))
    {
        u64CapturedPacketCount = pReplay->u64CapturedPacketCount();
        u64SentPacketCount = pReplay->u64ReplayedPacketCount();
    }
    else
    {
        const auto& detTraffic = std::get<DosAttackStatusDetails>(
            detStatus.varStatusDetails()
        );
        u64SentPacketCount = detTraffic.u64SentPacketCount();
        u64SentByteCount = detTraffic.u64SentByteCount();
        dActualPacketsPerSecond = detTraffic.dActualPacketsPerSecond();
    }
    objStatistics.insert(
        QStringLiteral("capturedPacketCount"),
        strUInt64(u64CapturedPacketCount)
    );
    objStatistics.insert(
        QStringLiteral("sentPacketCount"),
        strUInt64(u64SentPacketCount)
    );
    objStatistics.insert(
        QStringLiteral("sentByteCount"),
        strUInt64(u64SentByteCount)
    );
    objStatistics.insert(
        QStringLiteral("lastDelayUs"),
        strUInt64(u64LastDelayMicroseconds)
    );
    objStatistics.insert(
        QStringLiteral("actualPacketsPerSecond"),
        dActualPacketsPerSecond
    );
    objStatistics.insert(
        QStringLiteral("sendErrorCount"),
        strUInt64(detStatus.u64SendErrorCount())
    );
    const bool bTerminalState =
        detStatus.stateExecution() == AttackExecutionState::Completed
        || detStatus.stateExecution() == AttackExecutionState::Stopped;
    const bool bValidSample = bTerminalState
        && detStatus.u64SendErrorCount() == 0;
    QString strInvalidReason;
    if (detStatus.u64SendErrorCount() > 0)
    {
        strInvalidReason = QStringLiteral("SEND_ERRORS");
    }
    else if (!bTerminalState)
    {
        strInvalidReason = QStringLiteral("EXECUTION_NOT_TERMINAL");
    }

    const QString strSuffix = bJson ? QStringLiteral("json") : QStringLiteral("csv");
    const QString strPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出本地执行记录"),
        QStringLiteral("tesla-robustness-%1.%2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")), strSuffix),
        bJson ? QStringLiteral("JSON (*.json)") : QStringLiteral("CSV (*.csv)")
    );
    if (strPath.isEmpty())
    {
        return;
    }

    QByteArray arrOutput;
    if (bJson)
    {
        QJsonArray arrRecords;
        for (const AttackExecutionRecord& recRecord : vecRecords)
        {
            QJsonObject objRecord;
            objRecord.insert(QStringLiteral("planId"), strUInt64(recRecord.u64AttackId()));
            objRecord.insert(QStringLiteral("type"), strTypeCode(recRecord.typeAttack()));
            objRecord.insert(QStringLiteral("packetIndex"), static_cast<qint64>(recRecord.u32PacketIndex()));
            objRecord.insert(QStringLiteral("captureTimestampMs"), strUInt64(recRecord.u64CaptureTimestampMilliseconds()));
            objRecord.insert(QStringLiteral("sendTimestampMs"), strUInt64(recRecord.u64SendTimestampMilliseconds()));
            objRecord.insert(QStringLiteral("sent"), recRecord.bSent());
            objRecord.insert(QStringLiteral("originalMessage"), strDatagramMessage(recRecord.arrOriginalDatagram()));
            objRecord.insert(QStringLiteral("sentMessage"), strDatagramMessage(recRecord.arrSentDatagram()));
            objRecord.insert(QStringLiteral("originalDatagramHex"), strHex(recRecord.arrOriginalDatagram()));
            objRecord.insert(QStringLiteral("sentDatagramHex"), strHex(recRecord.arrSentDatagram()));
            objRecord.insert(QStringLiteral("description"), recRecord.strMessage());
            arrRecords.append(objRecord);
        }
        QJsonObject objRoundSummary;
        objRoundSummary.insert(QStringLiteral("experimentId"), strExperimentId);
        objRoundSummary.insert(QStringLiteral("runId"), strRunId);
        objRoundSummary.insert(
            QStringLiteral("timestampMs"),
            strUInt64(u64RoundTimestampMilliseconds)
        );
        objRoundSummary.insert(QStringLiteral("gitCommit"), strGitCommit);
        objRoundSummary.insert(QStringLiteral("nodeId"), m_ctlNetwork.strNodeName());
        objRoundSummary.insert(QStringLiteral("sourceIp"), strSourceIp);
        objRoundSummary.insert(
            QStringLiteral("sourceIpSemantics"),
            QStringLiteral("PREFERRED_LOCAL_MULTICAST_INTERFACE")
        );
        objRoundSummary.insert(QStringLiteral("planId"), strUInt64(detPlan.u64AttackId()));
        objRoundSummary.insert(QStringLiteral("type"), strTypeCode(detPlan.typeAttack()));
        objRoundSummary.insert(
            QStringLiteral("authenticationMode"),
            strAuthenticationModeCode(detContext.modeAuthentication())
        );
        objRoundSummary.insert(
            QStringLiteral("cryptoAlgorithm"),
            strCryptoAlgorithmCode(detContext.algCryptoAlgorithm())
        );
        // 测试端不接收业务载荷；字段保留并明确其安全边界，不伪造Hash。
        objRoundSummary.insert(
            QStringLiteral("payloadHash"),
            QStringLiteral("NOT_DISTRIBUTED")
        );
        objRoundSummary.insert(
            QStringLiteral("packetCount"),
            static_cast<qint64>(detContext.u32DataPacketCount())
        );
        objRoundSummary.insert(
            QStringLiteral("packetsPerInterval"),
            static_cast<qint64>(detContext.u32PacketsPerInterval())
        );
        objRoundSummary.insert(
            QStringLiteral("intervalMs"),
            static_cast<qint64>(detContext.u32IntervalMilliseconds())
        );
        objRoundSummary.insert(
            QStringLiteral("disclosureDelay"),
            static_cast<qint64>(detContext.u32DisclosureDelay())
        );
        objRoundSummary.insert(
            QStringLiteral("groupSize"),
            static_cast<qint64>(detContext.u32GroupSize())
        );
        objRoundSummary.insert(
            QStringLiteral("detectionThreshold"),
            static_cast<qint64>(detContext.u32DetectionThreshold())
        );
        objRoundSummary.insert(
            QStringLiteral("targetSenderId"),
            QString::fromStdString(detPlan.strTargetSenderId())
        );
        objRoundSummary.insert(
            QStringLiteral("targetSenderIp"),
            QString::fromStdString(detContext.strTargetSenderIp())
        );
        objRoundSummary.insert(QStringLiteral("chainId"), strUInt64(detPlan.u64ChainId()));
        objRoundSummary.insert(
            QStringLiteral("roundStatus"),
            strExecutionStateCode(detStatus.stateExecution())
        );
        objRoundSummary.insert(QStringLiteral("validSample"), bValidSample);
        objRoundSummary.insert(QStringLiteral("invalidReason"), strInvalidReason);
        objRoundSummary.insert(
            QStringLiteral("configuredStartTimestampMs"),
            strUInt64(detContext.u64StartTimestampMilliseconds())
        );
        objRoundSummary.insert(
            QStringLiteral("configuredFault"),
            strTypeCode(detPlan.typeAttack())
        );
        objRoundSummary.insert(
            QStringLiteral("configuredFaultValue"),
            objPlanDetails
        );
        objRoundSummary.insert(QStringLiteral("planDetails"), objPlanDetails);
        objRoundSummary.insert(QStringLiteral("statistics"), objStatistics);

        QJsonObject objRoot;
        objRoot.insert(QStringLiteral("schemaVersion"), 1);
        objRoot.insert(
            QStringLiteral("exportedAtMs"),
            QString::number(QDateTime::currentMSecsSinceEpoch())
        );
        objRoot.insert(QStringLiteral("roundSummary"), objRoundSummary);
        objRoot.insert(QStringLiteral("records"), arrRecords);
        arrOutput = QJsonDocument(objRoot).toJson(QJsonDocument::Indented);
    }
    else
    {
        arrOutput.append(
            "experimentId,runId,timestampMs,gitCommit,nodeId,sourceIp,sourceIpSemantics,"
            "planId,type,authenticationMode,cryptoAlgorithm,payloadHash,packetCount,"
            "packetsPerInterval,intervalMs,disclosureDelay,groupSize,detectionThreshold,"
            "targetSenderId,targetSenderIp,chainId,"
            "configuredStartTimestampMs,roundStatus,validSample,invalidReason,"
            "sendErrorCount,capturedPacketCount,sentPacketCount,"
            "sentByteCount,actualPacketsPerSecond,lastDelayUs,targetPacketIndexes,"
            "messageByteOffset,xorMask,repeatCount,replayDelayMs,repeatGapMs,"
            "configuredRatePps,configuredDurationMs,configuredPacketBytes,"
            "packetIndex,captureTimestampMs,sendTimestampMs,sent,originalMessage,"
            "sentMessage,originalDatagramHex,sentDatagramHex,description\r\n"
        );
        for (const AttackExecutionRecord& recRecord : vecRecords)
        {
            const QStringList listValues{
                strExperimentId,
                strRunId,
                strUInt64(u64RoundTimestampMilliseconds),
                strGitCommit,
                m_ctlNetwork.strNodeName(),
                strSourceIp,
                QStringLiteral("PREFERRED_LOCAL_MULTICAST_INTERFACE"),
                strUInt64(recRecord.u64AttackId()),
                strTypeCode(recRecord.typeAttack()),
                strAuthenticationModeCode(detContext.modeAuthentication()),
                strCryptoAlgorithmCode(detContext.algCryptoAlgorithm()),
                QStringLiteral("NOT_DISTRIBUTED"),
                QString::number(detContext.u32DataPacketCount()),
                QString::number(detContext.u32PacketsPerInterval()),
                QString::number(detContext.u32IntervalMilliseconds()),
                QString::number(detContext.u32DisclosureDelay()),
                QString::number(detContext.u32GroupSize()),
                QString::number(detContext.u32DetectionThreshold()),
                QString::fromStdString(detPlan.strTargetSenderId()),
                QString::fromStdString(detContext.strTargetSenderIp()),
                strUInt64(detPlan.u64ChainId()),
                strUInt64(detContext.u64StartTimestampMilliseconds()),
                strExecutionStateCode(detStatus.stateExecution()),
                bValidSample ? QStringLiteral("true") : QStringLiteral("false"),
                strInvalidReason,
                strUInt64(detStatus.u64SendErrorCount()),
                strUInt64(u64CapturedPacketCount),
                strUInt64(u64SentPacketCount),
                strUInt64(u64SentByteCount),
                QString::number(dActualPacketsPerSecond, 'f', 3),
                strUInt64(u64LastDelayMicroseconds),
                strConfiguredTargetPackets,
                strMessageByteOffset,
                strXorMask,
                strRepeatCount,
                strReplayDelayMilliseconds,
                strRepeatGapMilliseconds,
                strConfiguredRate,
                strConfiguredDuration,
                strConfiguredPacketBytes,
                QString::number(recRecord.u32PacketIndex()),
                strUInt64(recRecord.u64CaptureTimestampMilliseconds()),
                strUInt64(recRecord.u64SendTimestampMilliseconds()),
                recRecord.bSent() ? QStringLiteral("true") : QStringLiteral("false"),
                strDatagramMessage(recRecord.arrOriginalDatagram()),
                strDatagramMessage(recRecord.arrSentDatagram()),
                strHex(recRecord.arrOriginalDatagram()),
                strHex(recRecord.arrSentDatagram()),
                recRecord.strMessage()
            };
            QStringList listEscapedValues;
            listEscapedValues.reserve(listValues.size());
            for (const QString& strValue : listValues)
            {
                listEscapedValues.push_back(strCsv(strValue));
            }
            arrOutput.append(
                (listEscapedValues.join(QLatin1Char(',')) + QStringLiteral("\r\n"))
                    .toUtf8()
            );
        }
    }

    QFile filOutput(strPath);
    if (!filOutput.open(QIODevice::WriteOnly | QIODevice::Truncate)
        || filOutput.write(arrOutput) != arrOutput.size())
    {
        QMessageBox::warning(this, QStringLiteral("导出失败"), filOutput.errorString());
        return;
    }
    appendLog(QStringLiteral("本地执行记录已导出：") + strPath);
}

bool AttackTestMainWindow::bValidatePlanInputs(
    QString& strError,
    bool& bThresholdExceeded
) const
{
    bThresholdExceeded = false;
    const auto optContext = m_ctlNetwork.optRoundContextSnapshot();
    if (!optContext.has_value())
    {
        strError = QStringLiteral("等待集中管理端下发本轮公开上下文。");
        return false;
    }
    if (m_pTypeCombo->currentIndex() == 2)
    {
        strError.clear();
        return true;
    }

    const std::vector<std::uint32_t> vecIndexes = vecPacketIndexes(strError);
    if (vecIndexes.empty())
    {
        return false;
    }
    for (const std::uint32_t u32PacketIndex : vecIndexes)
    {
        if (u32PacketIndex > optContext->u32DataPacketCount())
        {
            strError = QStringLiteral("目标报文编号必须位于1…%1。")
                .arg(optContext->u32DataPacketCount());
            return false;
        }
    }
    if (m_pTypeCombo->currentIndex() == 1
        && m_pRepeatSpin->value() > 1
        && m_pGapSpin->value() == 0)
    {
        strError = QStringLiteral("重复次数大于1时，重复间隔必须大于0。");
        return false;
    }

    if (m_pTypeCombo->currentIndex() == 0
        && optContext->modeAuthentication() == UdpAuthenticationMode::Improved)
    {
        std::map<std::uint32_t, std::uint32_t> mapGroupCounts;
        for (const std::uint32_t u32PacketIndex : vecIndexes)
        {
            const std::uint32_t u32GroupIndex =
                ((u32PacketIndex - 1U) / optContext->u32GroupSize()) + 1U;
            ++mapGroupCounts[u32GroupIndex];
        }
        bThresholdExceeded = std::any_of(
            mapGroupCounts.cbegin(),
            mapGroupCounts.cend(),
            [&optContext](const auto& prCount)
            {
                return prCount.second > optContext->u32DetectionThreshold();
            }
        );
        if (bThresholdExceeded && !m_pThresholdConfirmCheck->isChecked())
        {
            strError = QStringLiteral(
                "同一分组内的目标数量超过检测阈值；不保证准确定位，请明确确认。"
            );
            return false;
        }
    }

    strError.clear();
    return true;
}

std::vector<std::uint32_t> AttackTestMainWindow::vecPacketIndexes(
    QString& strError
) const
{
    std::set<std::uint32_t> setIndexes;
    const QStringList listParts = m_pPacketIndexesEdit->text().split(
        QLatin1Char(','),
        Qt::SkipEmptyParts
    );
    for (const QString& strPartValue : listParts)
    {
        const QString strPart = strPartValue.trimmed();
        const QStringList listRange = strPart.split(QLatin1Char('-'));
        bool bStartOk = false;
        bool bEndOk = false;
        const uint u32Start = listRange.value(0).toUInt(&bStartOk);
        const uint u32End = listRange.size() == 1
            ? u32Start
            : listRange.value(1).toUInt(&bEndOk);
        if (listRange.size() == 1)
        {
            bEndOk = bStartOk;
        }
        if (listRange.size() > 2 || !bStartOk || !bEndOk
            || u32Start == 0 || u32End < u32Start || u32End - u32Start > 999U)
        {
            strError = QStringLiteral("报文编号格式无效，请使用1,3-5形式且单个范围不超过1000项。");
            return {};
        }
        for (uint u32Index = u32Start; u32Index <= u32End; ++u32Index)
        {
            setIndexes.insert(static_cast<std::uint32_t>(u32Index));
            if (setIndexes.size() > 1000U)
            {
                strError = QStringLiteral("单个计划最多包含1000个不同报文编号。");
                return {};
            }
        }
    }
    if (setIndexes.empty())
    {
        strError = QStringLiteral("至少填写一个目标报文编号。");
        return {};
    }
    return std::vector<std::uint32_t>(setIndexes.cbegin(), setIndexes.cend());
}

QString AttackTestMainWindow::strDatagramMessage(
    const QByteArray& arrDatagram
) const
{
    const auto optContext = m_ctlNetwork.optRoundContextSnapshot();
    if (!optContext.has_value() || arrDatagram.isEmpty())
    {
        return QStringLiteral("—");
    }

    try
    {
        const auto& detContext = optContext.value();
        const UdpAuthenticationPacketContext ctxPacket(
            detContext.modeAuthentication(),
            detContext.u32PacketsPerInterval(),
            detContext.u32DisclosureDelay(),
            detContext.u32DataPacketCount(),
            detContext.u32GroupSize(),
            detContext.nTauCount()
        );
        const ByteBuffer vecDatagram(
            reinterpret_cast<const std::uint8_t*>(arrDatagram.constData()),
            reinterpret_cast<const std::uint8_t*>(arrDatagram.constData())
                + arrDatagram.size()
        );
        const auto resPacket = UdpAuthenticationPacketCodec::resDecode(
            vecDatagram,
            ctxPacket
        );
        if (!std::holds_alternative<UdpAuthenticationPacket>(resPacket))
        {
            return QStringLiteral("非认证数据报");
        }
        const auto& udpPacket = std::get<UdpAuthenticationPacket>(resPacket);
        if (!udpPacket.bIsDataPacket())
        {
            return QStringLiteral("DISCLOSE");
        }
        const auto& datPacket = std::get<UdpDataPacket>(udpPacket.varDetails());
        return QString::fromLatin1(QByteArray(
            reinterpret_cast<const char*>(datPacket.arrMessage().data()),
            static_cast<qsizetype>(datPacket.arrMessage().size())
        ).toHex());
    }
    catch (const std::exception&)
    {
        return QStringLiteral("解析失败");
    }
}

void AttackTestMainWindow::appendLog(const QString& strMessage)
{
    if (m_pLogEdit != nullptr)
    {
        m_pLogEdit->append(
            QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz "))
                + strMessage
        );
    }
}

void AttackTestMainWindow::applyStyle()
{
    setStyleSheet(QStringLiteral(R"(
        QMainWindow, QWidget {
            background: #f6f8fb;
            color: #1f2937;
            font-family: "Microsoft YaHei";
            font-size: 13px;
        }
        QLabel#titleLabel {
            font-size: 22px;
            font-weight: 700;
            color: #7f1d1d;
            padding: 8px 4px;
        }
        QLabel#stateValue {
            background: white;
            border: 1px solid #dbe3ec;
            border-radius: 5px;
            padding: 9px;
            color: #7f1d1d;
            font-weight: 600;
        }
        QLabel#hintLabel {
            color: #64748b;
            padding: 6px;
        }
        QLabel#validLabel {
            color: #166534;
        }
        QLabel#errorLabel {
            color: #b91c1c;
        }
        QLineEdit[invalidInput="true"] {
            border: 2px solid #dc2626;
            background: #fef2f2;
        }
        QPushButton {
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            padding: 7px 16px;
        }
        QPushButton#primaryButton {
            background: #7f1d1d;
            color: white;
        }
        QPushButton:disabled {
            color: #94a3b8;
            background: #eef2f7;
        }
        QTabWidget::pane, QTextEdit, QTableWidget {
            background: white;
            border: 1px solid #dbe3ec;
        }
    )"));
}

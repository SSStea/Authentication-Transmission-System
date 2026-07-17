#include "ManagerMainWindow.h"

#include "tesla/core/AuthenticationRoundParameters.h"
#include "tesla/metrics/CommunicationCost.h"
#include "tesla/workload/FileWorkload.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDoubleSpinBox>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRandomGenerator>
#include <QSpinBox>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>

#include <exception>

namespace
{
using tesla::protocol::NodeRole;

QString strConnectionState(ManagerConnectionState stateConnection)
{
    switch (stateConnection)
    {
    case ManagerConnectionState::Disconnected:
        return QStringLiteral("未连接");
    case ManagerConnectionState::Connecting:
        return QStringLiteral("连接中");
    case ManagerConnectionState::Connected:
        return QStringLiteral("已连接");
    }

    return QStringLiteral("未知");
}

QString strRunningState(
    ManagerConnectionState stateConnection,
    bool bRunning,
    const QString& strRunning,
    const QString& strIdle
)
{
    if (stateConnection != ManagerConnectionState::Connected)
    {
        return QStringLiteral("未知");
    }

    return bRunning ? strRunning : strIdle;
}

QTableWidgetItem* pReadOnlyItem(const QString& strText)
{
    QTableWidgetItem* pItem = new QTableWidgetItem(strText);
    pItem->setFlags(pItem->flags() & ~Qt::ItemIsEditable);
    return pItem;
}

}

ManagerMainWindow::ManagerMainWindow(
    std::uint16_t u16DiscoveryPort,
    QWidget* pParent
)
    : QMainWindow(pParent),
      // 控制器是按值成员，由C++成员生命周期管理，不能再交给Qt父对象重复销毁。
      m_ctlNetwork(u16DiscoveryPort, std::chrono::milliseconds(3000), nullptr),
      m_ctlAuthentication(m_ctlNetwork, nullptr),
      m_ctlAttackExperiment(m_ctlNetwork, m_ctlAuthentication, nullptr),
      m_pNodeTable(nullptr),
      m_pAttackTable(nullptr),
      m_pStatusLabel(new QLabel(QStringLiteral("就绪"), this)),
      m_pModeCombo(nullptr),
      m_pAlgorithmCombo(nullptr),
      m_pPayloadCombo(nullptr),
      m_pIntervalSpin(nullptr),
      m_pPacketsSpin(nullptr),
      m_pRepeatSpin(nullptr),
      m_pDisclosureSpin(nullptr),
      m_pGroupSpin(nullptr),
      m_pThresholdSpin(nullptr),
      m_pTextEdit(nullptr),
      m_pSelectFileButton(nullptr),
      m_pFileInfoLabel(nullptr),
      m_pFileComparisonTable(nullptr),
      m_pValidationLabel(nullptr),
      m_pCommunicationValue(nullptr),
      m_pPrepareButton(nullptr),
      m_pStartButton(nullptr),
      m_pPauseButton(nullptr),
      m_pResumeButton(nullptr),
      m_pStopButton(nullptr),
      m_pFaultSenderCombo(nullptr),
      m_pFaultTypeCombo(nullptr),
      m_pFaultLossRateSpin(nullptr),
      m_pFaultProtectedGroupSpin(nullptr),
      m_pFaultStartPacketSpin(nullptr),
      m_pFaultDurationSpin(nullptr),
      m_pFaultDelaySpin(nullptr),
      m_pFaultStateLabel(nullptr),
      m_pFaultPrepareButton(nullptr),
      m_pAttackEndpointCombo(nullptr),
      m_pAttackSenderCombo(nullptr),
      m_pAttackStateLabel(nullptr),
      m_pAttackPlanLabel(nullptr),
      m_pAttackPrepareButton(nullptr),
      m_pAttackStopButton(nullptr),
      m_pAttackEmergencyButton(nullptr),
      m_bAuthenticationInputsValid(false),
      m_bPreparedConfigurationCurrent(false)
{
    setWindowTitle(QStringLiteral("TESLA 集中管理"));
    resize(1280, 780);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pRootLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("TESLA 无人机集群广播认证系统 · 集中管理"),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pRootLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateNodePage(), QStringLiteral("节点连接"));
    pTabs->addTab(pCreateConfigurationPage(), QStringLiteral("参数与载荷"));
    pTabs->addTab(pCreateExperimentPage(), QStringLiteral("实验控制"));
    pTabs->addTab(pCreateAttackPage(), QStringLiteral("认证鲁棒性测试端"));
    pTabs->addTab(pCreateFileComparisonPage(), QStringLiteral("文件Hash比较"));
    pRootLayout->addWidget(pTabs, 1);

    setCentralWidget(pCentralWidget);
    statusBar()->addWidget(m_pStatusLabel, 1);
    applyStyle();

    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::nodesChanged,
        this,
        &ManagerMainWindow::refreshNodeTables
    );
    connect(
        &m_ctlNetwork,
        &ManagerNetworkController::logMessage,
        this,
        [this](const QString& strMessage)
        {
            m_pStatusLabel->setText(strMessage);
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::configurationStateChanged,
        this,
        [this](bool, const QString& strMessage)
        {
            m_pStatusLabel->setText(strMessage);
            refreshAuthenticationActions();
            refreshFaultControls();
            refreshAttackControls();
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::roundStateChanged,
        this,
        [this](bool, bool)
        {
            refreshAuthenticationActions();
            refreshFaultControls();
            refreshNodeTables();
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::faultPlanStateChanged,
        this,
        [this](bool, const QString& strMessage)
        {
            m_pStatusLabel->setText(strMessage);
            refreshAuthenticationActions();
            refreshFaultControls();
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::resultMessage,
        this,
        [this](const QString& strMessage)
        {
            m_pStatusLabel->setText(strMessage);
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::fileComparisonResult,
        this,
        [this](
            const QString& strSenderId,
            quint64 u64ChainId,
            quint64 u64OriginalByteCount,
            quint64 u64RecoveredByteCount,
            const QString& strOriginalSha256,
            const QString& strRecoveredSha256,
            bool bMatches
        )
        {
            const int nRow = m_pFileComparisonTable->rowCount();
            m_pFileComparisonTable->insertRow(nRow);
            m_pFileComparisonTable->setItem(
                nRow,
                0,
                pReadOnlyItem(strSenderId)
            );
            m_pFileComparisonTable->setItem(
                nRow,
                1,
                pReadOnlyItem(QString::number(u64ChainId))
            );
            m_pFileComparisonTable->setItem(
                nRow,
                2,
                pReadOnlyItem(QString::number(u64OriginalByteCount))
            );
            m_pFileComparisonTable->setItem(
                nRow,
                3,
                pReadOnlyItem(QString::number(u64RecoveredByteCount))
            );
            m_pFileComparisonTable->setItem(
                nRow,
                4,
                pReadOnlyItem(strOriginalSha256)
            );
            m_pFileComparisonTable->setItem(
                nRow,
                5,
                pReadOnlyItem(strRecoveredSha256)
            );
            m_pFileComparisonTable->setItem(
                nRow,
                6,
                pReadOnlyItem(
                    bMatches ? QStringLiteral("一致") : QStringLiteral("失败")
                )
            );
        }
    );
    connect(
        &m_ctlAttackExperiment,
        &ManagerAttackExperimentController::stateChanged,
        this,
        &ManagerMainWindow::refreshAttackControls
    );
    connect(
        &m_ctlAttackExperiment,
        &ManagerAttackExperimentController::message,
        this,
        [this](const QString& strMessage)
        {
            m_pStatusLabel->setText(strMessage);
            refreshAttackControls();
        }
    );

    m_ctlNetwork.start();
    validateAuthenticationInputs();
}

QWidget* ManagerMainWindow::pCreateNodePage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);

    QHBoxLayout* pButtonLayout = new QHBoxLayout();
    QPushButton* pScanButton = new QPushButton(QStringLiteral("扫描节点"), pPage);
    QPushButton* pConnectButton = new QPushButton(QStringLiteral("连接全部"), pPage);
    QPushButton* pDisconnectButton = new QPushButton(QStringLiteral("断开全部"), pPage);
    QPushButton* pRefreshButton = new QPushButton(QStringLiteral("刷新状态"), pPage);
    pScanButton->setObjectName(QStringLiteral("primaryButton"));
    pButtonLayout->addWidget(pScanButton);
    pButtonLayout->addWidget(pConnectButton);
    pButtonLayout->addWidget(pDisconnectButton);
    pButtonLayout->addWidget(pRefreshButton);
    pButtonLayout->addStretch();
    pLayout->addLayout(pButtonLayout);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral("扫描只发现节点；连接全部才建立持久MANAGER TCP连接。"),
        pPage
    );
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel);

    m_pNodeTable = new QTableWidget(0, 7, pPage);
    m_pNodeTable->setHorizontalHeaderLabels({
        QStringLiteral("发送"),
        QStringLiteral("节点名称"),
        QStringLiteral("IP地址"),
        QStringLiteral("TCP状态"),
        QStringLiteral("Sender"),
        QStringLiteral("Receiver"),
        QStringLiteral("最后心跳")
    });
    m_pNodeTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_pNodeTable->verticalHeader()->setVisible(false);
    m_pNodeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_pNodeTable->setAlternatingRowColors(true);
    pLayout->addWidget(m_pNodeTable, 1);

    connect(
        pScanButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &ManagerNetworkController::scanNodes
    );
    connect(
        pConnectButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &ManagerNetworkController::connectAll
    );
    connect(
        pDisconnectButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &ManagerNetworkController::disconnectAll
    );
    connect(
        pRefreshButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &ManagerNetworkController::refreshStatus
    );
    connect(
        m_pNodeTable,
        &QTableWidget::itemChanged,
        this,
        [this](QTableWidgetItem* pItem)
        {
            if (pItem == nullptr || pItem->column() != 0)
            {
                return;
            }

            const QString strEndpointKey = pItem->data(Qt::UserRole).toString();
            if (pItem->checkState() == Qt::Checked)
            {
                m_setSelectedSenderEndpoints.insert(strEndpointKey);
            }
            else
            {
                m_setSelectedSenderEndpoints.remove(strEndpointKey);
            }

            m_bPreparedConfigurationCurrent = false;
            refreshAuthenticationActions();
        }
    );

    return pPage;
}

QWidget* ManagerMainWindow::pCreateConfigurationPage()
{
    QWidget* pPage = new QWidget(this);
    QHBoxLayout* pLayout = new QHBoxLayout(pPage);

    QGroupBox* pParameterGroup = new QGroupBox(QStringLiteral("认证参数"), pPage);
    QFormLayout* pParameterLayout = new QFormLayout(pParameterGroup);
    m_pModeCombo = new QComboBox(pParameterGroup);
    m_pModeCombo->addItems({
        QStringLiteral("原生TESLA"),
        QStringLiteral("改进TESLA")
    });
    m_pAlgorithmCombo = new QComboBox(pParameterGroup);
    m_pAlgorithmCombo->addItems({
        QStringLiteral("SHA-256"),
        QStringLiteral("SM3"),
        QStringLiteral("SHA3-256")
    });
    m_pPayloadCombo = new QComboBox(pParameterGroup);
    m_pPayloadCombo->addItems({
        QStringLiteral("文本模式"),
        QStringLiteral("文件模式")
    });
    m_pIntervalSpin = new QSpinBox(pParameterGroup);
    m_pIntervalSpin->setRange(1, 60000);
    m_pIntervalSpin->setValue(100);
    m_pPacketsSpin = new QSpinBox(pParameterGroup);
    m_pPacketsSpin->setRange(1, 10000);
    m_pPacketsSpin->setValue(100);
    m_pRepeatSpin = new QSpinBox(pParameterGroup);
    m_pRepeatSpin->setRange(1, 200000);
    m_pRepeatSpin->setValue(1000);
    m_pDisclosureSpin = new QSpinBox(pParameterGroup);
    m_pDisclosureSpin->setRange(1, 1000);
    m_pDisclosureSpin->setValue(3);
    m_pGroupSpin = new QSpinBox(pParameterGroup);
    m_pGroupSpin->setRange(2, 10000);
    m_pGroupSpin->setValue(100);
    m_pThresholdSpin = new QSpinBox(pParameterGroup);
    m_pThresholdSpin->setRange(1, 1000);
    m_pThresholdSpin->setValue(1);
    pParameterLayout->addRow(QStringLiteral("认证模式"), m_pModeCombo);
    pParameterLayout->addRow(QStringLiteral("密码算法"), m_pAlgorithmCombo);
    pParameterLayout->addRow(QStringLiteral("载荷模式"), m_pPayloadCombo);
    pParameterLayout->addRow(QStringLiteral("时间间隔(ms)"), m_pIntervalSpin);
    pParameterLayout->addRow(QStringLiteral("每间隔发包数"), m_pPacketsSpin);
    pParameterLayout->addRow(QStringLiteral("文本发送次数"), m_pRepeatSpin);
    pParameterLayout->addRow(QStringLiteral("披露延迟"), m_pDisclosureSpin);
    pParameterLayout->addRow(QStringLiteral("分组大小"), m_pGroupSpin);
    pParameterLayout->addRow(QStringLiteral("检测阈值"), m_pThresholdSpin);

    QGroupBox* pPayloadGroup = new QGroupBox(QStringLiteral("载荷与CA"), pPage);
    QVBoxLayout* pPayloadLayout = new QVBoxLayout(pPayloadGroup);
    m_pTextEdit = new QTextEdit(pPayloadGroup);
    m_pTextEdit->setPlaceholderText(
        QStringLiteral("输入1至32字节UTF-8文本，例如 helloworld")
    );
    m_pTextEdit->setPlainText(QStringLiteral("helloworld"));
    m_pTextEdit->setMaximumHeight(100);
    pPayloadLayout->addWidget(m_pTextEdit);
    m_pSelectFileButton = new QPushButton(QStringLiteral("选择文件"), pPayloadGroup);
    pPayloadLayout->addWidget(m_pSelectFileButton);
    m_pFileInfoLabel = new QLabel(
        QStringLiteral("尚未选择文件；最大支持6,400,000B"),
        pPayloadGroup
    );
    m_pFileInfoLabel->setWordWrap(true);
    m_pFileInfoLabel->setObjectName(QStringLiteral("hintLabel"));
    pPayloadLayout->addWidget(m_pFileInfoLabel);
    m_pPrepareButton = new QPushButton(
        QStringLiteral("生成并下发本轮CA材料"),
        pPayloadGroup
    );
    m_pPrepareButton->setObjectName(QStringLiteral("primaryButton"));
    pPayloadLayout->addWidget(m_pPrepareButton);
    m_pValidationLabel = new QLabel(pPayloadGroup);
    m_pValidationLabel->setWordWrap(true);
    pPayloadLayout->addWidget(m_pValidationLabel);
    m_pCommunicationValue = new QLabel(pPayloadGroup);
    m_pCommunicationValue->setObjectName(QStringLiteral("stateValue"));
    m_pCommunicationValue->setWordWrap(true);
    pPayloadLayout->addWidget(m_pCommunicationValue);
    QLabel* pBoundaryLabel = new QLabel(
        QStringLiteral(
            "Message固定32B；文件通过TCP原始二进制分块上传，Sender完整接收后"
            "重新切成32B Message，TCP分块不会与UDP序列化类型混用。"
        ),
        pPayloadGroup
    );
    pBoundaryLabel->setWordWrap(true);
    pBoundaryLabel->setObjectName(QStringLiteral("hintLabel"));
    pPayloadLayout->addWidget(pBoundaryLabel);
    pPayloadLayout->addStretch();

    pLayout->addWidget(pParameterGroup);
    pLayout->addWidget(pPayloadGroup);

    const auto fnInputChanged = [this]()
    {
        m_bPreparedConfigurationCurrent = false;
        validateAuthenticationInputs();
    };
    connect(
        m_pModeCombo,
        &QComboBox::currentIndexChanged,
        this,
        [fnInputChanged](int)
        {
            fnInputChanged();
        }
    );
    connect(
        m_pAlgorithmCombo,
        &QComboBox::currentIndexChanged,
        this,
        [fnInputChanged](int)
        {
            fnInputChanged();
        }
    );
    connect(
        m_pPayloadCombo,
        &QComboBox::currentIndexChanged,
        this,
        [fnInputChanged](int)
        {
            fnInputChanged();
        }
    );
    for (QSpinBox* pSpin : {
             m_pIntervalSpin,
             m_pPacketsSpin,
             m_pRepeatSpin,
             m_pDisclosureSpin,
             m_pGroupSpin,
             m_pThresholdSpin
         })
    {
        connect(
            pSpin,
            &QSpinBox::valueChanged,
            this,
            [fnInputChanged](int)
            {
                fnInputChanged();
            }
        );
    }
    connect(
        m_pTextEdit,
        &QTextEdit::textChanged,
        this,
        fnInputChanged
    );
    connect(
        m_pPrepareButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::prepareRound
    );
    connect(
        m_pSelectFileButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::selectFile
    );

    return pPage;
}

QWidget* ManagerMainWindow::pCreateExperimentPage()
{
    QWidget* pPage = pCreateStagePlaceholder(
        QStringLiteral("实验控制"),
        QStringLiteral(
            "控制命令按统一未来时间下发。暂停在指定逻辑间隔结束后生效，"
            "继续从新的未来时间和下一个逻辑间隔恢复。"
        )
    );
    QVBoxLayout* pLayout = qobject_cast<QVBoxLayout*>(pPage->layout());
    QHBoxLayout* pButtons = new QHBoxLayout();
    m_pStartButton = new QPushButton(QStringLiteral("开始"), pPage);
    m_pPauseButton = new QPushButton(QStringLiteral("暂停"), pPage);
    m_pResumeButton = new QPushButton(QStringLiteral("继续"), pPage);
    m_pStopButton = new QPushButton(QStringLiteral("停止"), pPage);
    m_pStartButton->setObjectName(QStringLiteral("primaryButton"));
    pButtons->addWidget(m_pStartButton);
    pButtons->addWidget(m_pPauseButton);
    pButtons->addWidget(m_pResumeButton);
    pButtons->addWidget(m_pStopButton);
    pButtons->addStretch();
    pLayout->insertLayout(1, pButtons);

    QGroupBox* pFaultGroup = new QGroupBox(
        QStringLiteral("发送侧故障注入"),
        pPage
    );
    QFormLayout* pFaultForm = new QFormLayout(pFaultGroup);
    m_pFaultSenderCombo = new QComboBox(pFaultGroup);
    m_pFaultTypeCombo = new QComboBox(pFaultGroup);
    m_pFaultTypeCombo->addItems({
        QStringLiteral("丢包"),
        QStringLiteral("逻辑断链"),
        QStringLiteral("固定延迟")
    });
    m_pFaultLossRateSpin = new QDoubleSpinBox(pFaultGroup);
    m_pFaultLossRateSpin->setRange(0.01, 99.99);
    m_pFaultLossRateSpin->setDecimals(2);
    m_pFaultLossRateSpin->setValue(10.0);
    m_pFaultLossRateSpin->setSuffix(QStringLiteral(" %"));
    m_pFaultProtectedGroupSpin = new QSpinBox(pFaultGroup);
    m_pFaultProtectedGroupSpin->setRange(1, 10000000);
    m_pFaultProtectedGroupSpin->setValue(100);
    m_pFaultProtectedGroupSpin->setToolTip(QStringLiteral(
        "标签承载的组末位置不会被丢弃。原生/改进对比时应使用相同保护分组大小。"
    ));
    m_pFaultStartPacketSpin = new QSpinBox(pFaultGroup);
    m_pFaultStartPacketSpin->setRange(1, 10000000);
    m_pFaultDurationSpin = new QSpinBox(pFaultGroup);
    m_pFaultDurationSpin->setRange(1, 60000);
    m_pFaultDurationSpin->setValue(1000);
    m_pFaultDelaySpin = new QSpinBox(pFaultGroup);
    m_pFaultDelaySpin->setRange(1, 10000);
    m_pFaultDelaySpin->setValue(100);
    m_pFaultStateLabel = new QLabel(QStringLiteral("未配置"), pFaultGroup);
    m_pFaultPrepareButton = new QPushButton(
        QStringLiteral("下发故障注入计划"),
        pFaultGroup
    );
    pFaultForm->addRow(QStringLiteral("目标Sender"), m_pFaultSenderCombo);
    pFaultForm->addRow(QStringLiteral("类型"), m_pFaultTypeCombo);
    pFaultForm->addRow(QStringLiteral("丢包率"), m_pFaultLossRateSpin);
    pFaultForm->addRow(
        QStringLiteral("标签保护分组"),
        m_pFaultProtectedGroupSpin
    );
    pFaultForm->addRow(QStringLiteral("断链起始报文"), m_pFaultStartPacketSpin);
    pFaultForm->addRow(QStringLiteral("断链持续ms"), m_pFaultDurationSpin);
    pFaultForm->addRow(QStringLiteral("固定延迟ms"), m_pFaultDelaySpin);
    pFaultForm->addRow(QStringLiteral("状态"), m_pFaultStateLabel);
    pFaultForm->addRow(m_pFaultPrepareButton);
    pLayout->insertWidget(2, pFaultGroup);

    connect(
        m_pStartButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::startRound
    );
    connect(
        m_pPauseButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::pauseRound
    );
    connect(
        m_pResumeButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::resumeRound
    );
    connect(
        m_pStopButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::stopRound
    );
    connect(
        m_pFaultPrepareButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::prepareFaultPlan
    );
    connect(
        m_pFaultTypeCombo,
        &QComboBox::currentIndexChanged,
        this,
        [this](int)
        {
            refreshFaultControls();
        }
    );
    connect(
        m_pFaultProtectedGroupSpin,
        &QSpinBox::valueChanged,
        this,
        [this](int)
        {
            refreshFaultControls();
        }
    );

    refreshFaultControls();
    return pPage;
}

QWidget* ManagerMainWindow::pCreateAttackPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "管理端只选择独立测试端和目标Sender并下发公开上下文；"
            "具体计划在测试端配置，返回后由管理端安装临时Receiver来源映射。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel);

    m_pAttackTable = new QTableWidget(0, 6, pPage);
    m_pAttackTable->setHorizontalHeaderLabels({
        QStringLiteral("名称"),
        QStringLiteral("IP地址"),
        QStringLiteral("TCP状态"),
        QStringLiteral("组播监听"),
        QStringLiteral("测试状态"),
        QStringLiteral("最后心跳")
    });
    m_pAttackTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_pAttackTable->verticalHeader()->setVisible(false);
    m_pAttackTable->setAlternatingRowColors(true);
    pLayout->addWidget(m_pAttackTable, 1);

    QGroupBox* pPlanGroup = new QGroupBox(
        QStringLiteral("认证鲁棒性测试编排"),
        pPage
    );
    QFormLayout* pForm = new QFormLayout(pPlanGroup);
    m_pAttackEndpointCombo = new QComboBox(pPlanGroup);
    m_pAttackSenderCombo = new QComboBox(pPlanGroup);
    m_pAttackStateLabel = new QLabel(QStringLiteral("未准备"), pPlanGroup);
    m_pAttackPlanLabel = new QLabel(QStringLiteral("尚未收到计划"), pPlanGroup);
    m_pAttackPlanLabel->setWordWrap(true);

    pForm->addRow(QStringLiteral("独立测试端"), m_pAttackEndpointCombo);
    pForm->addRow(QStringLiteral("目标Sender"), m_pAttackSenderCombo);
    pForm->addRow(QStringLiteral("测试端返回计划"), m_pAttackPlanLabel);
    pForm->addRow(QStringLiteral("状态"), m_pAttackStateLabel);
    pLayout->addWidget(pPlanGroup);

    QHBoxLayout* pButtons = new QHBoxLayout();
    m_pAttackPrepareButton = new QPushButton(QStringLiteral("下发公开上下文"), pPage);
    m_pAttackStopButton = new QPushButton(QStringLiteral("停止异常流量模拟"), pPage);
    m_pAttackEmergencyButton = new QPushButton(QStringLiteral("紧急停止"), pPage);
    m_pAttackPrepareButton->setObjectName(QStringLiteral("primaryButton"));
    pButtons->addWidget(m_pAttackPrepareButton);
    pButtons->addWidget(m_pAttackStopButton);
    pButtons->addWidget(m_pAttackEmergencyButton);
    pButtons->addStretch();
    pLayout->addLayout(pButtons);

    connect(
        m_pAttackPrepareButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::prepareAttackContext
    );
    connect(
        m_pAttackStopButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::stopAttackPlan
    );
    connect(
        m_pAttackEmergencyButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::emergencyStopAttackPlan
    );
    refreshAttackControls();
    return pPage;
}

QWidget* ManagerMainWindow::pCreateFileComparisonPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "这里只比较原文件与各Receiver恢复文件的大小和SHA-256，"
            "不建立全部认证结果汇总页面。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel);

    m_pFileComparisonTable = new QTableWidget(0, 7, pPage);
    m_pFileComparisonTable->setHorizontalHeaderLabels({
        QStringLiteral("Sender"),
        QStringLiteral("chainId"),
        QStringLiteral("原大小"),
        QStringLiteral("恢复大小"),
        QStringLiteral("原SHA-256"),
        QStringLiteral("恢复SHA-256"),
        QStringLiteral("结果")
    });
    m_pFileComparisonTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents
    );
    m_pFileComparisonTable->horizontalHeader()->setStretchLastSection(true);
    m_pFileComparisonTable->verticalHeader()->setVisible(false);
    m_pFileComparisonTable->setAlternatingRowColors(true);
    pLayout->addWidget(m_pFileComparisonTable, 1);
    return pPage;
}

QWidget* ManagerMainWindow::pCreateStagePlaceholder(
    const QString& strTitle,
    const QString& strDescription
)
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pTitleLabel = new QLabel(strTitle, pPage);
    pTitleLabel->setObjectName(QStringLiteral("sectionTitleLabel"));
    QLabel* pDescriptionLabel = new QLabel(strDescription, pPage);
    pDescriptionLabel->setWordWrap(true);
    pDescriptionLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pTitleLabel);
    pLayout->addWidget(pDescriptionLabel);
    pLayout->addStretch();
    return pPage;
}

void ManagerMainWindow::refreshNodeTables()
{
    const QVector<ManagerNodeSnapshot> vecSnapshots = m_ctlNetwork.vecNodeSnapshots();
    const QString strCurrentAttackEndpoint =
        m_pAttackEndpointCombo != nullptr
            ? m_pAttackEndpointCombo->currentData().toString()
            : QString();

    m_pNodeTable->blockSignals(true);
    m_pNodeTable->setRowCount(0);
    m_pAttackTable->setRowCount(0);
    if (m_pAttackEndpointCombo != nullptr)
    {
        m_pAttackEndpointCombo->blockSignals(true);
        m_pAttackEndpointCombo->clear();
    }

    for (const ManagerNodeSnapshot& snpNode : vecSnapshots)
    {
        const QString strHeartbeat = snpNode.nHeartbeatAgeMilliseconds() >= 0
            ? QStringLiteral("%1ms").arg(snpNode.nHeartbeatAgeMilliseconds())
            : QStringLiteral("未收到");

        if (snpNode.roleNode() == NodeRole::Attacker)
        {
            const int nRow = m_pAttackTable->rowCount();
            m_pAttackTable->insertRow(nRow);
            m_pAttackTable->setItem(nRow, 0, pReadOnlyItem(snpNode.strNodeName()));
            m_pAttackTable->setItem(nRow, 1, pReadOnlyItem(snpNode.strIpAddress()));
            m_pAttackTable->setItem(
                nRow,
                2,
                pReadOnlyItem(strConnectionState(snpNode.stateConnection()))
            );
            m_pAttackTable->setItem(
                nRow,
                3,
                pReadOnlyItem(strRunningState(
                    snpNode.stateConnection(),
                    snpNode.bMulticastListening(),
                    QStringLiteral("监听中"),
                    QStringLiteral("未监听")
                ))
            );
            m_pAttackTable->setItem(
                nRow,
                4,
                pReadOnlyItem(strRunningState(
                    snpNode.stateConnection(),
                    snpNode.bAttackRunning(),
                    QStringLiteral("运行中"),
                    QStringLiteral("空闲")
                ))
            );
            m_pAttackTable->setItem(nRow, 5, pReadOnlyItem(strHeartbeat));
            if (m_pAttackEndpointCombo != nullptr
                && snpNode.stateConnection() == ManagerConnectionState::Connected)
            {
                m_pAttackEndpointCombo->addItem(
                    snpNode.strNodeName() + QStringLiteral(" / ")
                        + snpNode.strIpAddress(),
                    snpNode.strEndpointKey()
                );
            }
            continue;
        }

        const int nRow = m_pNodeTable->rowCount();
        m_pNodeTable->insertRow(nRow);
        QTableWidgetItem* pSenderItem = new QTableWidgetItem();
        pSenderItem->setData(Qt::UserRole, snpNode.strEndpointKey());
        pSenderItem->setCheckState(
            m_setSelectedSenderEndpoints.contains(snpNode.strEndpointKey())
                ? Qt::Checked
                : Qt::Unchecked
        );
        if (snpNode.stateConnection() != ManagerConnectionState::Connected)
        {
            pSenderItem->setCheckState(Qt::Unchecked);
            pSenderItem->setFlags(pSenderItem->flags() & ~Qt::ItemIsEnabled);
            m_setSelectedSenderEndpoints.remove(snpNode.strEndpointKey());
        }

        m_pNodeTable->setItem(nRow, 0, pSenderItem);
        m_pNodeTable->setItem(nRow, 1, pReadOnlyItem(snpNode.strNodeName()));
        m_pNodeTable->setItem(nRow, 2, pReadOnlyItem(snpNode.strIpAddress()));
        m_pNodeTable->setItem(
            nRow,
            3,
            pReadOnlyItem(strConnectionState(snpNode.stateConnection()))
        );
        m_pNodeTable->setItem(
            nRow,
            4,
            pReadOnlyItem(strRunningState(
                snpNode.stateConnection(),
                snpNode.bSenderRunning(),
                QStringLiteral("运行中"),
                QStringLiteral("空闲")
            ))
        );
        m_pNodeTable->setItem(
            nRow,
            5,
            pReadOnlyItem(strRunningState(
                snpNode.stateConnection(),
                snpNode.bReceiverRunning(),
                QStringLiteral("监听中"),
                QStringLiteral("停止")
            ))
        );
        m_pNodeTable->setItem(nRow, 6, pReadOnlyItem(strHeartbeat));
    }

    m_pNodeTable->blockSignals(false);
    if (m_pAttackEndpointCombo != nullptr)
    {
        const int nIndex = m_pAttackEndpointCombo->findData(
            strCurrentAttackEndpoint
        );
        if (nIndex >= 0)
        {
            m_pAttackEndpointCombo->setCurrentIndex(nIndex);
        }
        m_pAttackEndpointCombo->blockSignals(false);
    }
    refreshFaultControls();
    refreshAttackControls();
}

void ManagerMainWindow::validateAuthenticationInputs()
{
    if (m_pModeCombo == nullptr)
    {
        return;
    }

    const bool bImproved = m_pModeCombo->currentIndex() == 1;
    const bool bFileMode = m_pPayloadCombo->currentIndex() == 1;
    const int nPacketsPerInterval = m_pPacketsSpin->value();
    const int nGroupSize = m_pGroupSpin->value();
    const int nDetectionThreshold = m_pThresholdSpin->value();
    const QByteArray arrText = m_pTextEdit->toPlainText().toUtf8();

    m_pGroupSpin->setEnabled(bImproved);
    m_pThresholdSpin->setEnabled(bImproved);
    m_pTextEdit->setEnabled(!bFileMode);
    m_pRepeatSpin->setEnabled(!bFileMode);
    m_pSelectFileButton->setEnabled(bFileMode);
    refreshSelectedFileInformation();

    QStringList listErrors;
    bool bPacketGroupingValid = true;
    bool bThresholdValid = true;
    if (bImproved && nPacketsPerInterval % nGroupSize != 0)
    {
        bPacketGroupingValid = false;
        listErrors.append(
            QStringLiteral("每间隔发包数必须是分组大小的整数倍；%1不能被%2整除")
                .arg(nPacketsPerInterval)
                .arg(nGroupSize)
        );
    }
    if (bImproved
        && (nDetectionThreshold < 1
            || nDetectionThreshold >= nGroupSize))
    {
        bThresholdValid = false;
        listErrors.append(
            QStringLiteral("检测阈值必须满足 1 <= 阈值 < 分组大小")
        );
    }
    if (bImproved && bPacketGroupingValid && bThresholdValid)
    {
        try
        {
            // 复用核心参数构造，提前拦截矩阵规模或Tau数量安全上限。
            static_cast<void>(tesla::core::ImprovedTeslaParameters(
                static_cast<std::uint32_t>(nGroupSize),
                static_cast<std::uint32_t>(nDetectionThreshold)
            ));
        }
        catch (const std::exception& exError)
        {
            bThresholdValid = false;
            listErrors.append(QStringLiteral("改进参数不可构造：%1")
                .arg(QString::fromUtf8(exError.what())));
        }
    }

    const bool bTextValid = bFileMode || (
        !arrText.isEmpty()
        && arrText.size() <= static_cast<qsizetype>(
            tesla::protocol::BINARY_BLOCK_SIZE
        )
        && !arrText.contains('\0')
    );
    const bool bFileValid = !bFileMode || (
        m_ptrSelectedFileBytes
        && !m_ptrSelectedFileBytes->isEmpty()
        && m_ptrSelectedFileBytes->size() <= static_cast<qsizetype>(
            tesla::workload::FileWorkload::MAXIMUM_FILE_SIZE
        )
        && m_arrSelectedFileSha256.size() == 32
    );
    if (!bTextValid)
    {
        listErrors.append(QStringLiteral(
            "文本必须是1至32字节UTF-8内容且不能包含零字节"
        ));
    }
    if (!bFileValid)
    {
        listErrors.append(QStringLiteral(
            "请选择1至6,400,000字节的完整文件"
        ));
    }

    const auto fnSetInvalid = [](QWidget* pWidget, bool bInvalid)
    {
        pWidget->setStyleSheet(
            bInvalid
                ? QStringLiteral(
                    "border: 2px solid #dc2626; background: #fff7f7;"
                )
                : QString()
        );
    };
    fnSetInvalid(m_pPacketsSpin, !bPacketGroupingValid);
    fnSetInvalid(m_pGroupSpin, !bPacketGroupingValid);
    fnSetInvalid(m_pThresholdSpin, !bThresholdValid);
    fnSetInvalid(m_pTextEdit, !bTextValid);
    fnSetInvalid(m_pSelectFileButton, !bFileValid);

    m_bAuthenticationInputsValid = listErrors.isEmpty();
    m_pValidationLabel->setText(
        m_bAuthenticationInputsValid
            ? QStringLiteral("参数有效，可生成并下发本轮CA材料")
            : listErrors.join(QStringLiteral("；"))
    );
    m_pValidationLabel->setStyleSheet(
        m_bAuthenticationInputsValid
            ? QStringLiteral("color: #166534;")
            : QStringLiteral("color: #b91c1c;")
    );

    if (!m_bAuthenticationInputsValid)
    {
        m_pCommunicationValue->setText(QStringLiteral("通信开销：参数无效"));
    }
    else
    {
        const std::uint64_t u64PacketCount = bFileMode
            ? static_cast<std::uint64_t>(
                (m_ptrSelectedFileBytes->size()
                    + static_cast<qsizetype>(
                        tesla::workload::FileWorkload::MESSAGE_SIZE
                    ) - 1)
                / static_cast<qsizetype>(
                    tesla::workload::FileWorkload::MESSAGE_SIZE
                )
            )
            : static_cast<std::uint64_t>(m_pRepeatSpin->value());
        const std::uint64_t u64DataIntervalCount =
            (u64PacketCount
                + static_cast<std::uint64_t>(nPacketsPerInterval) - 1U)
            / static_cast<std::uint64_t>(nPacketsPerInterval);
        tesla::metrics::CommunicationCostMetricSummary sumCommunication =
            tesla::metrics::CommunicationCostCalculator::sumNative(
                1,
                "CONFIGURATION",
                "MANAGER",
                0,
                u64PacketCount,
                u64DataIntervalCount
            );
        if (bImproved)
        {
            const tesla::core::ImprovedTeslaParameters prmImproved(
                static_cast<std::uint32_t>(nGroupSize),
                static_cast<std::uint32_t>(nDetectionThreshold)
            );
            const std::uint64_t u64GroupCount =
                (u64PacketCount + static_cast<std::uint64_t>(nGroupSize) - 1U)
                / static_cast<std::uint64_t>(nGroupSize);
            sumCommunication =
                tesla::metrics::CommunicationCostCalculator::sumImproved(
                    1,
                    "CONFIGURATION",
                    "MANAGER",
                    0,
                    u64PacketCount,
                    u64DataIntervalCount,
                    u64GroupCount * prmImproved.nTauCount(),
                    u64GroupCount
                );
        }

        m_pCommunicationValue->setText(
            QStringLiteral("认证模式：%1\n通信开销总字节数：%2B")
                .arg(
                    bImproved
                        ? QStringLiteral("改进TESLA")
                        : QStringLiteral("原生TESLA")
                )
                .arg(sumCommunication.u64TotalBytes())
        );
    }

    refreshAuthenticationActions();
}

void ManagerMainWindow::refreshAuthenticationActions()
{
    if (m_pPrepareButton == nullptr || m_pStartButton == nullptr)
    {
        return;
    }

    const bool bRunning = m_ctlAuthentication.bRoundRunning();
    const bool bPaused = m_ctlAuthentication.bRoundPaused();
    m_pPrepareButton->setEnabled(
        m_bAuthenticationInputsValid && !bRunning
    );
    m_pStartButton->setEnabled(
        m_bAuthenticationInputsValid
        && m_bPreparedConfigurationCurrent
        && m_ctlAuthentication.bConfigurationReady()
        && m_ctlAuthentication.bFaultPlanReady()
        && (!m_ctlAttackExperiment.bContextSent()
            || m_ctlAttackExperiment.bReady())
        && !bRunning
    );
    m_pPauseButton->setEnabled(bRunning && !bPaused);
    m_pResumeButton->setEnabled(bRunning && bPaused);
    m_pStopButton->setEnabled(bRunning);
}

void ManagerMainWindow::selectFile()
{
    const QString strFilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择认证文件")
    );
    if (strFilePath.isEmpty())
    {
        return;
    }

    const QFileInfo infFile(strFilePath);
    if (!infFile.isFile() || infFile.size() <= 0
        || infFile.size() > static_cast<qint64>(
            tesla::workload::FileWorkload::MAXIMUM_FILE_SIZE
        ))
    {
        m_pStatusLabel->setText(QStringLiteral(
            "文件必须存在且大小为1至6,400,000字节"
        ));
        return;
    }

    QFile fileSource(strFilePath);
    if (!fileSource.open(QIODevice::ReadOnly))
    {
        m_pStatusLabel->setText(QStringLiteral("无法读取所选文件"));
        return;
    }

    const QByteArray arrFileBytes = fileSource.readAll();
    if (arrFileBytes.size() != infFile.size())
    {
        m_pStatusLabel->setText(QStringLiteral("文件读取长度发生变化，请重新选择"));
        return;
    }

    m_strSelectedFilePath = strFilePath;
    m_ptrSelectedFileBytes = std::make_shared<const QByteArray>(arrFileBytes);
    m_arrSelectedFileSha256 = QCryptographicHash::hash(
        arrFileBytes,
        QCryptographicHash::Sha256
    );
    m_bPreparedConfigurationCurrent = false;
    validateAuthenticationInputs();
}

void ManagerMainWindow::refreshSelectedFileInformation()
{
    if (!m_ptrSelectedFileBytes)
    {
        m_pFileInfoLabel->setText(QStringLiteral(
            "尚未选择文件；最大支持6,400,000B"
        ));
        return;
    }

    const QFileInfo infFile(m_strSelectedFilePath);
    const std::uint64_t u64PacketCount = static_cast<std::uint64_t>(
        (m_ptrSelectedFileBytes->size()
            + static_cast<qsizetype>(
                tesla::workload::FileWorkload::MESSAGE_SIZE
            ) - 1)
        / static_cast<qsizetype>(
            tesla::workload::FileWorkload::MESSAGE_SIZE
        )
    );
    const std::uint64_t u64IntervalCount =
        (u64PacketCount + m_pPacketsSpin->value() - 1U)
        / static_cast<std::uint64_t>(m_pPacketsSpin->value());
    const std::uint64_t u64EstimatedDataDuration =
        u64IntervalCount * m_pIntervalSpin->value();
    const std::uint64_t u64EstimatedCompleteDuration =
        (u64IntervalCount + m_pDisclosureSpin->value())
        * m_pIntervalSpin->value();

    // 参数变化后同步刷新全部自动值，避免界面仍显示选择文件时的旧估算。
    m_pFileInfoLabel->setText(
        QStringLiteral(
            "文件：%1\n类型：%2，大小：%3B，Message：固定32B，分片：%4，"
            "数据间隔：%5，链长度：%6，预计数据发送：%7ms，"
            "预计认证完成：%8ms\n原始SHA-256：%9"
        )
            .arg(infFile.fileName(), infFile.suffix().toLower())
            .arg(m_ptrSelectedFileBytes->size())
            .arg(u64PacketCount)
            .arg(u64IntervalCount)
            .arg(u64IntervalCount + 1U)
            .arg(u64EstimatedDataDuration)
            .arg(u64EstimatedCompleteDuration)
            .arg(QString::fromLatin1(m_arrSelectedFileSha256.toHex()))
    );
}

void ManagerMainWindow::prepareRound()
{
    try
    {
        std::optional<tesla::protocol::ImprovedTeslaControlParameters>
            optImprovedParameters;
        const bool bImproved = m_pModeCombo->currentIndex() == 1;
        if (bImproved)
        {
            optImprovedParameters.emplace(
                static_cast<std::uint32_t>(m_pGroupSpin->value()),
                static_cast<std::uint32_t>(m_pThresholdSpin->value())
            );
        }

        tesla::protocol::AuthenticationCryptoAlgorithm algCrypto =
            tesla::protocol::AuthenticationCryptoAlgorithm::Sha256;
        if (m_pAlgorithmCombo->currentIndex() == 1)
        {
            algCrypto =
                tesla::protocol::AuthenticationCryptoAlgorithm::Sm3;
        }
        else if (m_pAlgorithmCombo->currentIndex() == 2)
        {
            algCrypto =
                tesla::protocol::AuthenticationCryptoAlgorithm::Sha3_256;
        }

        QString strError;
        if (m_pPayloadCombo->currentIndex() == 0)
        {
            const ManagerTextRoundConfiguration cfgRound(
                bImproved
                    ? tesla::protocol::UdpAuthenticationMode::Improved
                    : tesla::protocol::UdpAuthenticationMode::Native,
                algCrypto,
                static_cast<std::uint32_t>(m_pRepeatSpin->value()),
                static_cast<std::uint32_t>(m_pPacketsSpin->value()),
                static_cast<std::uint32_t>(m_pDisclosureSpin->value()),
                static_cast<std::uint32_t>(m_pIntervalSpin->value()),
                std::move(optImprovedParameters),
                m_pTextEdit->toPlainText()
            );
            m_bPreparedConfigurationCurrent =
                m_ctlAuthentication.bPrepareTextRound(
                    cfgRound,
                    m_setSelectedSenderEndpoints,
                    m_ctlNetwork.vecNodeSnapshots(),
                    strError
                );
        }
        else
        {
            const ManagerFileRoundConfiguration cfgRound(
                bImproved
                    ? tesla::protocol::UdpAuthenticationMode::Improved
                    : tesla::protocol::UdpAuthenticationMode::Native,
                algCrypto,
                static_cast<std::uint32_t>(m_pPacketsSpin->value()),
                static_cast<std::uint32_t>(m_pDisclosureSpin->value()),
                static_cast<std::uint32_t>(m_pIntervalSpin->value()),
                std::move(optImprovedParameters),
                m_ptrSelectedFileBytes,
                m_arrSelectedFileSha256
            );
            m_pFileComparisonTable->setRowCount(0);
            m_bPreparedConfigurationCurrent =
                m_ctlAuthentication.bPrepareFileRound(
                cfgRound,
                m_setSelectedSenderEndpoints,
                m_ctlNetwork.vecNodeSnapshots(),
                strError
            );
        }
        if (!m_bPreparedConfigurationCurrent)
        {
            m_pStatusLabel->setText(strError);
        }
        refreshAuthenticationActions();
    }
    catch (const std::exception& exError)
    {
        m_bPreparedConfigurationCurrent = false;
        m_pStatusLabel->setText(QString::fromUtf8(exError.what()));
        refreshAuthenticationActions();
    }
}

void ManagerMainWindow::startRound()
{
    QString strError;
    const std::uint64_t u64StartTimestampMilliseconds =
        static_cast<std::uint64_t>(QDateTime::currentMSecsSinceEpoch()) + 2000U;

    const bool bHasRobustnessPlan = m_ctlAttackExperiment.bReady();
    if (bHasRobustnessPlan
        && !m_ctlAttackExperiment.bStartPrepared(
            u64StartTimestampMilliseconds,
            strError
        ))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    if (!m_ctlAuthentication.bStartRoundAt(
            u64StartTimestampMilliseconds,
            strError
        ))
    {
        if (bHasRobustnessPlan)
        {
            QString strRollbackError;
            static_cast<void>(m_ctlAttackExperiment.bStopPrepared(
                false,
                strRollbackError
            ));
        }
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral(
        "开始命令已使用同一未来时间下发给所有已准备参与方"
    ));
}

void ManagerMainWindow::pauseRound()
{
    QString strError;
    if (!m_ctlAuthentication.bPauseRound(strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral(
        "暂停命令已下发，将在统一逻辑间隔边界生效"
    ));
}

void ManagerMainWindow::resumeRound()
{
    QString strError;
    if (!m_ctlAuthentication.bResumeRound(strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral(
        "继续命令已下发，将从新的统一未来时间恢复"
    ));
}

void ManagerMainWindow::stopRound()
{
    QString strError;
    if (m_ctlAttackExperiment.bRunning()
        || m_ctlAttackExperiment.bReady())
    {
        QString strTestStopError;
        static_cast<void>(m_ctlAttackExperiment.bStopPrepared(
            false,
            strTestStopError
        ));
    }
    if (!m_ctlAuthentication.bStopRound(strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral("停止命令已下发"));
}

void ManagerMainWindow::prepareFaultPlan()
{
    try
    {
        QString strError;
        const int nSenderContextIndex =
            m_pFaultSenderCombo->currentData().toInt();
        const QVector<tesla::protocol::AttackRoundContextControlDetails>
            vecContexts = m_ctlAuthentication.vecAttackRoundContexts();
        if (nSenderContextIndex < 0
            || nSenderContextIndex >= vecContexts.size())
        {
            m_pStatusLabel->setText(QStringLiteral("故障注入目标Sender无效"));
            return;
        }

        const auto& detContext = vecContexts.at(nSenderContextIndex);
        const std::uint32_t u32ProtectedGroupSize = static_cast<std::uint32_t>(
            m_pFaultProtectedGroupSpin->value()
        );
        if (m_pFaultTypeCombo->currentIndex() != 2
            && detContext.u32PacketsPerInterval() % u32ProtectedGroupSize != 0)
        {
            m_pStatusLabel->setText(QStringLiteral(
                "标签保护分组必须整除每间隔发包数"
            ));
            return;
        }

        tesla::protocol::AuthenticationFaultDetails varFault =
            tesla::protocol::FixedDelayFaultDetails(1);
        if (m_pFaultTypeCombo->currentIndex() == 0)
        {
            std::uint64_t u64RandomSeed =
                QRandomGenerator::global()->generate64();
            if (u64RandomSeed == 0)
            {
                // 协议用零表示无效种子，极小概率取零时改用固定非零值。
                u64RandomSeed = 1;
            }
            varFault = tesla::protocol::PacketLossFaultDetails(
                m_pFaultLossRateSpin->value(),
                u64RandomSeed,
                u32ProtectedGroupSize
            );
        }
        else if (m_pFaultTypeCombo->currentIndex() == 1)
        {
            varFault = tesla::protocol::LogicalDisconnectFaultDetails(
                static_cast<std::uint32_t>(m_pFaultStartPacketSpin->value()),
                static_cast<std::uint32_t>(m_pFaultDurationSpin->value()),
                u32ProtectedGroupSize
            );
        }
        else
        {
            varFault = tesla::protocol::FixedDelayFaultDetails(
                static_cast<std::uint32_t>(m_pFaultDelaySpin->value())
            );
        }

        if (!m_ctlAuthentication.bConfigureFaultPlan(
                nSenderContextIndex,
                std::move(varFault),
                strError
            ))
        {
            m_pStatusLabel->setText(strError);
        }
        refreshFaultControls();
    }
    catch (const std::exception& exError)
    {
        m_pStatusLabel->setText(QString::fromUtf8(exError.what()));
        refreshFaultControls();
    }
}

void ManagerMainWindow::prepareAttackContext()
{
    QString strError;
    if (!m_ctlAttackExperiment.bPrepareContext(
            m_pAttackEndpointCombo->currentData().toString(),
            m_pAttackSenderCombo->currentData().toInt(),
            strError
        ))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral(
        "公开上下文已下发，请在独立测试端配置计划"
    ));
    refreshAttackControls();
}

void ManagerMainWindow::stopAttackPlan()
{
    QString strError;
    if (!m_ctlAttackExperiment.bStopPrepared(false, strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral("异常流量模拟停止命令已下发"));
    refreshAttackControls();
}

void ManagerMainWindow::emergencyStopAttackPlan()
{
    QString strError;
    if (!m_ctlAttackExperiment.bStopPrepared(true, strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral("异常流量模拟紧急停止命令已下发"));
    refreshAttackControls();
}

void ManagerMainWindow::refreshFaultControls()
{
    if (m_pFaultSenderCombo == nullptr || m_pFaultTypeCombo == nullptr)
    {
        return;
    }

    const int nCurrentSenderIndex = m_pFaultSenderCombo->currentData().toInt();
    const QVector<tesla::protocol::AttackRoundContextControlDetails>
        vecContexts = m_ctlAuthentication.vecAttackRoundContexts();
    m_pFaultSenderCombo->blockSignals(true);
    m_pFaultSenderCombo->clear();
    for (int nIndex = 0; nIndex < vecContexts.size(); ++nIndex)
    {
        const auto& detContext = vecContexts.at(nIndex);
        m_pFaultSenderCombo->addItem(
            QString::fromStdString(detContext.strTargetSenderId())
                + QStringLiteral(" / chain ")
                + QString::number(detContext.u64ChainId()),
            nIndex
        );
    }
    const int nRestoredIndex = m_pFaultSenderCombo->findData(
        nCurrentSenderIndex
    );
    if (nRestoredIndex >= 0)
    {
        m_pFaultSenderCombo->setCurrentIndex(nRestoredIndex);
    }
    m_pFaultSenderCombo->blockSignals(false);

    const int nType = m_pFaultTypeCombo->currentIndex();
    const int nSelectedContextIndex =
        m_pFaultSenderCombo->currentData().toInt();
    const bool bHasSelectedContext = nSelectedContextIndex >= 0
        && nSelectedContextIndex < vecContexts.size();
    bool bProtectedGroupValid = true;
    if (bHasSelectedContext)
    {
        const auto& detContext = vecContexts.at(nSelectedContextIndex);
        m_pFaultProtectedGroupSpin->blockSignals(true);
        m_pFaultProtectedGroupSpin->setMaximum(
            static_cast<int>(detContext.u32PacketsPerInterval())
        );
        if (detContext.modeAuthentication()
            == tesla::protocol::UdpAuthenticationMode::Improved)
        {
            m_pFaultProtectedGroupSpin->setValue(
                static_cast<int>(detContext.u32GroupSize())
            );
        }
        m_pFaultProtectedGroupSpin->blockSignals(false);
        m_pFaultStartPacketSpin->setMaximum(
            static_cast<int>(detContext.u32DataPacketCount())
        );
        bProtectedGroupValid = detContext.u32PacketsPerInterval()
            % static_cast<std::uint32_t>(
                m_pFaultProtectedGroupSpin->value()
            ) == 0;
    }

    const bool bRunning = m_ctlAuthentication.bRoundRunning();
    const bool bCanConfigureBase = m_ctlAuthentication.bConfigurationReady()
        && !bRunning
        && !m_ctlAuthentication.bFaultPlanPending()
        && (!m_ctlAuthentication.bFaultConfigured()
            || !m_ctlAuthentication.bFaultPlanReady())
        && !m_ctlAttackExperiment.bContextSent()
        && m_pFaultSenderCombo->count() > 0;
    const bool bRequiresProtectedGroup = nType == 0 || nType == 1;
    const bool bCanConfigure = bCanConfigureBase
        && (!bRequiresProtectedGroup || bProtectedGroupValid);
    m_pFaultLossRateSpin->setEnabled(nType == 0 && bCanConfigure);
    m_pFaultProtectedGroupSpin->setEnabled(
        bRequiresProtectedGroup
            && bCanConfigureBase
            && bHasSelectedContext
            && vecContexts.at(nSelectedContextIndex).modeAuthentication()
                == tesla::protocol::UdpAuthenticationMode::Native
    );
    m_pFaultStartPacketSpin->setEnabled(nType == 1 && bCanConfigure);
    m_pFaultDurationSpin->setEnabled(nType == 1 && bCanConfigure);
    m_pFaultDelaySpin->setEnabled(nType == 2 && bCanConfigure);
    m_pFaultTypeCombo->setEnabled(bCanConfigure);
    m_pFaultSenderCombo->setEnabled(bCanConfigure);
    m_pFaultPrepareButton->setEnabled(bCanConfigure);
    m_pFaultProtectedGroupSpin->setStyleSheet(
        bRequiresProtectedGroup && !bProtectedGroupValid
            ? QStringLiteral("border: 2px solid #dc2626; background: #fff7f7;")
            : QString()
    );

    if (m_ctlAuthentication.bFaultPlanPending())
    {
        m_pFaultStateLabel->setText(QStringLiteral("等待目标Sender确认"));
    }
    else if (m_ctlAuthentication.bFaultConfigured()
        && m_ctlAuthentication.bFaultPlanReady())
    {
        m_pFaultStateLabel->setText(QStringLiteral("已确认；本轮停止后自动清除"));
    }
    else
    {
        m_pFaultStateLabel->setText(QStringLiteral("未配置"));
    }
}

void ManagerMainWindow::refreshAttackControls()
{
    if (m_pAttackEndpointCombo == nullptr
        || m_pAttackSenderCombo == nullptr)
    {
        return;
    }

    const int nCurrentSenderIndex =
        m_pAttackSenderCombo->currentData().toInt();
    const QVector<tesla::protocol::AttackRoundContextControlDetails>
        vecContexts = m_ctlAuthentication.vecAttackRoundContexts();
    m_pAttackSenderCombo->blockSignals(true);
    m_pAttackSenderCombo->clear();
    for (int nIndex = 0; nIndex < vecContexts.size(); ++nIndex)
    {
        const tesla::protocol::AttackRoundContextControlDetails& detContext =
            vecContexts.at(nIndex);
        m_pAttackSenderCombo->addItem(
            QString::fromStdString(detContext.strTargetSenderId())
                + QStringLiteral(" / chain ")
                + QString::number(detContext.u64ChainId()),
            nIndex
        );
    }
    const int nRestoredIndex = m_pAttackSenderCombo->findData(
        nCurrentSenderIndex
    );
    if (nRestoredIndex >= 0)
    {
        m_pAttackSenderCombo->setCurrentIndex(nRestoredIndex);
    }
    m_pAttackSenderCombo->blockSignals(false);

    const bool bHasEndpoint = m_pAttackEndpointCombo->count() > 0;
    const bool bHasContext = m_pAttackSenderCombo->count() > 0;
    const bool bReady = m_ctlAttackExperiment.bReady();
    const bool bRunning = m_ctlAttackExperiment.bRunning();
    m_pAttackStateLabel->setText(m_ctlAttackExperiment.strStateText());
    m_pAttackPlanLabel->setText(m_ctlAttackExperiment.strPlanSummary());

    m_pAttackPrepareButton->setEnabled(
        bHasEndpoint
            && bHasContext
            && !bRunning
            && !m_ctlAttackExperiment.bContextSent()
            && !m_ctlAuthentication.bFaultConfigured()
    );
    m_pAttackEndpointCombo->setEnabled(!m_ctlAttackExperiment.bContextSent());
    m_pAttackSenderCombo->setEnabled(!m_ctlAttackExperiment.bContextSent());
    m_pAttackStopButton->setEnabled(
        m_ctlAttackExperiment.bContextSent() || bReady || bRunning
    );
    m_pAttackEmergencyButton->setEnabled(bReady || bRunning);

    refreshAuthenticationActions();
}

void ManagerMainWindow::applyStyle()
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
            color: #17365d;
            padding: 8px 4px;
        }
        QLabel#sectionTitleLabel {
            font-size: 18px;
            font-weight: 600;
            color: #17365d;
        }
        QLabel#hintLabel {
            color: #64748b;
            padding: 4px;
        }
        QPushButton {
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            padding: 7px 16px;
        }
        QPushButton#primaryButton {
            color: white;
            background: #2563eb;
            border-color: #2563eb;
        }
        QPushButton:disabled {
            color: #94a3b8;
            background: #eef2f7;
        }
        QTableWidget, QGroupBox, QTabWidget::pane {
            background: white;
            border: 1px solid #dbe3ec;
        }
        QHeaderView::section {
            background: #eaf0f7;
            border: 0;
            border-right: 1px solid #d7dee8;
            padding: 7px;
            font-weight: 600;
        }
    )"));
}

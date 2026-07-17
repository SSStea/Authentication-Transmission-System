#include "ManagerMainWindow.h"

#include "tesla/core/AuthenticationRoundParameters.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
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

QPushButton* pDisabledStageButton(const QString& strText, const QString& strTip)
{
    QPushButton* pButton = new QPushButton(strText);
    pButton->setEnabled(false);
    pButton->setToolTip(strTip);
    return pButton;
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
      m_pNodeTable(nullptr),
      m_pAttackTable(nullptr),
      m_pStatusLabel(new QLabel(QStringLiteral("就绪"), this)),
      m_pModeCombo(nullptr),
      m_pAlgorithmCombo(nullptr),
      m_pIntervalSpin(nullptr),
      m_pPacketsSpin(nullptr),
      m_pRepeatSpin(nullptr),
      m_pDisclosureSpin(nullptr),
      m_pGroupSpin(nullptr),
      m_pThresholdSpin(nullptr),
      m_pTextEdit(nullptr),
      m_pValidationLabel(nullptr),
      m_pCommunicationValue(nullptr),
      m_pPrepareButton(nullptr),
      m_pStartButton(nullptr),
      m_pPauseButton(nullptr),
      m_pResumeButton(nullptr),
      m_pStopButton(nullptr),
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
    pTabs->addTab(pCreateAttackPage(), QStringLiteral("攻击测试端"));
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
        }
    );
    connect(
        &m_ctlAuthentication,
        &ManagerAuthenticationController::roundStateChanged,
        this,
        [this](bool, bool)
        {
            refreshAuthenticationActions();
            refreshNodeTables();
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
    pPayloadLayout->addWidget(pDisabledStageButton(
        QStringLiteral("选择文件"),
        QStringLiteral("阶段7实现文件上传、分片、恢复与Hash比较")
    ));
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
            "Message固定32B；文本内容使用独立控制消息下发，"
            "不会与算法配置或UDP序列化混用。"
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
        &ManagerMainWindow::prepareTextRound
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

    connect(
        m_pStartButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::startTextRound
    );
    connect(
        m_pPauseButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::pauseTextRound
    );
    connect(
        m_pResumeButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::resumeTextRound
    );
    connect(
        m_pStopButton,
        &QPushButton::clicked,
        this,
        &ManagerMainWindow::stopTextRound
    );

    return pPage;
}

QWidget* ManagerMainWindow::pCreateAttackPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "攻击测试端独立发现和连接，不进入正常Sender选择表。"
            "攻击计划与执行在阶段10启用。"
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
        QStringLiteral("攻击状态"),
        QStringLiteral("最后心跳")
    });
    m_pAttackTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_pAttackTable->verticalHeader()->setVisible(false);
    m_pAttackTable->setAlternatingRowColors(true);
    pLayout->addWidget(m_pAttackTable, 1);

    QHBoxLayout* pButtons = new QHBoxLayout();
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("配置攻击计划"),
        QStringLiteral("阶段10实现")
    ));
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("同步开始"),
        QStringLiteral("阶段10实现")
    ));
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("停止攻击"),
        QStringLiteral("阶段10实现")
    ));
    pButtons->addStretch();
    pLayout->addLayout(pButtons);
    return pPage;
}

QWidget* ManagerMainWindow::pCreateFileComparisonPage()
{
    return pCreateStagePlaceholder(
        QStringLiteral("文件Hash比较"),
        QStringLiteral(
            "阶段7接入原始文件大小、SHA-256和各Receiver恢复结果。"
            "集中管理GUI不会在此汇总全部认证结果。"
        )
    );
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

    m_pNodeTable->blockSignals(true);
    m_pNodeTable->setRowCount(0);
    m_pAttackTable->setRowCount(0);

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
}

void ManagerMainWindow::validateAuthenticationInputs()
{
    if (m_pModeCombo == nullptr)
    {
        return;
    }

    const bool bImproved = m_pModeCombo->currentIndex() == 1;
    const int nPacketsPerInterval = m_pPacketsSpin->value();
    const int nGroupSize = m_pGroupSpin->value();
    const int nDetectionThreshold = m_pThresholdSpin->value();
    const QByteArray arrText = m_pTextEdit->toPlainText().toUtf8();

    m_pGroupSpin->setEnabled(bImproved);
    m_pThresholdSpin->setEnabled(bImproved);

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

    const bool bTextValid = !arrText.isEmpty()
        && arrText.size()
            <= static_cast<qsizetype>(
                tesla::protocol::BINARY_BLOCK_SIZE
            )
        && !arrText.contains('\0');
    if (!bTextValid)
    {
        listErrors.append(QStringLiteral(
            "文本必须是1至32字节UTF-8内容且不能包含零字节"
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
        const std::uint64_t u64PacketCount =
            static_cast<std::uint64_t>(m_pRepeatSpin->value());
        const std::uint64_t u64DataIntervalCount =
            (u64PacketCount
                + static_cast<std::uint64_t>(nPacketsPerInterval) - 1U)
            / static_cast<std::uint64_t>(nPacketsPerInterval);
        const std::uint64_t u64MessageBytes =
            u64PacketCount * tesla::protocol::BINARY_BLOCK_SIZE;
        const std::uint64_t u64KeyBytes =
            u64DataIntervalCount * tesla::protocol::BINARY_BLOCK_SIZE;

        if (!bImproved)
        {
            const std::uint64_t u64MacBytes =
                u64PacketCount * tesla::protocol::BINARY_BLOCK_SIZE;
            m_pCommunicationValue->setText(
                QStringLiteral(
                    "算法字段通信开销：Message %1B + Key %2B + MAC %3B = %4B"
                )
                    .arg(u64MessageBytes)
                    .arg(u64KeyBytes)
                    .arg(u64MacBytes)
                    .arg(u64MessageBytes + u64KeyBytes + u64MacBytes)
            );
        }
        else
        {
            const tesla::core::ImprovedTeslaParameters prmImproved(
                static_cast<std::uint32_t>(nGroupSize),
                static_cast<std::uint32_t>(nDetectionThreshold)
            );
            const std::uint64_t u64GroupCount =
                (u64PacketCount + static_cast<std::uint64_t>(nGroupSize) - 1U)
                / static_cast<std::uint64_t>(nGroupSize);
            const std::uint64_t u64TauBytes =
                u64GroupCount * prmImproved.nTauCount()
                * tesla::protocol::BINARY_BLOCK_SIZE;
            const std::uint64_t u64FastTagBytes =
                u64GroupCount * tesla::protocol::BINARY_BLOCK_SIZE;
            m_pCommunicationValue->setText(
                QStringLiteral(
                    "算法字段通信开销：Message %1B + Key %2B + τ %3B + "
                    "FastGroupTag %4B = %5B"
                )
                    .arg(u64MessageBytes)
                    .arg(u64KeyBytes)
                    .arg(u64TauBytes)
                    .arg(u64FastTagBytes)
                    .arg(
                        u64MessageBytes + u64KeyBytes
                        + u64TauBytes + u64FastTagBytes
                    )
            );
        }
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
        && !bRunning
    );
    m_pPauseButton->setEnabled(bRunning && !bPaused);
    m_pResumeButton->setEnabled(bRunning && bPaused);
    m_pStopButton->setEnabled(bRunning);
}

void ManagerMainWindow::prepareTextRound()
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

        QString strError;
        m_bPreparedConfigurationCurrent =
            m_ctlAuthentication.bPrepareTextRound(
                cfgRound,
                m_setSelectedSenderEndpoints,
                m_ctlNetwork.vecNodeSnapshots(),
                strError
            );
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

void ManagerMainWindow::startTextRound()
{
    QString strError;
    if (!m_ctlAuthentication.bStartRound(strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral(
        "开始命令已下发，节点将在统一未来时间启动"
    ));
}

void ManagerMainWindow::pauseTextRound()
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

void ManagerMainWindow::resumeTextRound()
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

void ManagerMainWindow::stopTextRound()
{
    QString strError;
    if (!m_ctlAuthentication.bStopRound(strError))
    {
        m_pStatusLabel->setText(strError);
        return;
    }

    m_pStatusLabel->setText(QStringLiteral("停止命令已下发"));
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

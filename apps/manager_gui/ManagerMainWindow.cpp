#include "ManagerMainWindow.h"

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
      m_ctlNetwork(u16DiscoveryPort, std::chrono::milliseconds(3000), this),
      m_pNodeTable(nullptr),
      m_pAttackTable(nullptr),
      m_pStatusLabel(new QLabel(QStringLiteral("就绪"), this))
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

    m_ctlNetwork.start();
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
    QComboBox* pModeCombo = new QComboBox(pParameterGroup);
    pModeCombo->addItems({
        QStringLiteral("原生TESLA"),
        QStringLiteral("改进TESLA")
    });
    QComboBox* pAlgorithmCombo = new QComboBox(pParameterGroup);
    pAlgorithmCombo->addItems({
        QStringLiteral("SHA-256"),
        QStringLiteral("SM3"),
        QStringLiteral("SHA3-256")
    });
    QSpinBox* pIntervalSpin = new QSpinBox(pParameterGroup);
    pIntervalSpin->setRange(1, 60000);
    pIntervalSpin->setValue(100);
    QSpinBox* pPacketsSpin = new QSpinBox(pParameterGroup);
    pPacketsSpin->setRange(1, 10000);
    pPacketsSpin->setValue(100);
    QSpinBox* pDisclosureSpin = new QSpinBox(pParameterGroup);
    pDisclosureSpin->setRange(1, 1000);
    pDisclosureSpin->setValue(3);
    QSpinBox* pGroupSpin = new QSpinBox(pParameterGroup);
    pGroupSpin->setRange(2, 10000);
    pGroupSpin->setValue(100);
    QSpinBox* pThresholdSpin = new QSpinBox(pParameterGroup);
    pThresholdSpin->setRange(1, 1000);
    pThresholdSpin->setValue(1);
    pParameterLayout->addRow(QStringLiteral("认证模式"), pModeCombo);
    pParameterLayout->addRow(QStringLiteral("密码算法"), pAlgorithmCombo);
    pParameterLayout->addRow(QStringLiteral("时间间隔(ms)"), pIntervalSpin);
    pParameterLayout->addRow(QStringLiteral("每间隔发包数"), pPacketsSpin);
    pParameterLayout->addRow(QStringLiteral("披露延迟"), pDisclosureSpin);
    pParameterLayout->addRow(QStringLiteral("分组大小"), pGroupSpin);
    pParameterLayout->addRow(QStringLiteral("检测阈值"), pThresholdSpin);

    QGroupBox* pPayloadGroup = new QGroupBox(QStringLiteral("载荷与CA"), pPage);
    QVBoxLayout* pPayloadLayout = new QVBoxLayout(pPayloadGroup);
    QTextEdit* pTextEdit = new QTextEdit(pPayloadGroup);
    pTextEdit->setPlaceholderText(QStringLiteral("阶段6实现文本认证传输"));
    pTextEdit->setEnabled(false);
    pPayloadLayout->addWidget(pTextEdit);
    pPayloadLayout->addWidget(pDisabledStageButton(
        QStringLiteral("选择文件"),
        QStringLiteral("阶段7实现文件上传、分片、恢复与Hash比较")
    ));
    pPayloadLayout->addWidget(pDisabledStageButton(
        QStringLiteral("生成并下发本轮CA材料"),
        QStringLiteral("阶段5只建立GUI与连接框架；业务编排在后续阶段接入")
    ));
    QLabel* pBoundaryLabel = new QLabel(
        QStringLiteral("Message固定32B。当前页面不生成演示密钥、不发送模拟载荷。"),
        pPayloadGroup
    );
    pBoundaryLabel->setWordWrap(true);
    pBoundaryLabel->setObjectName(QStringLiteral("hintLabel"));
    pPayloadLayout->addWidget(pBoundaryLabel);
    pPayloadLayout->addStretch();

    pLayout->addWidget(pParameterGroup);
    pLayout->addWidget(pPayloadGroup);
    return pPage;
}

QWidget* ManagerMainWindow::pCreateExperimentPage()
{
    QWidget* pPage = pCreateStagePlaceholder(
        QStringLiteral("实验控制"),
        QStringLiteral(
            "阶段5仅冻结开始、暂停、继续和停止的界面职责。"
            "阶段6接入文本认证后再启用，不使用模拟运行状态。"
        )
    );
    QVBoxLayout* pLayout = qobject_cast<QVBoxLayout*>(pPage->layout());
    QHBoxLayout* pButtons = new QHBoxLayout();
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("开始"),
        QStringLiteral("阶段6启用")
    ));
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("暂停"),
        QStringLiteral("阶段6启用")
    ));
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("继续"),
        QStringLiteral("阶段6启用")
    ));
    pButtons->addWidget(pDisabledStageButton(
        QStringLiteral("停止"),
        QStringLiteral("阶段6启用")
    ));
    pButtons->addStretch();
    pLayout->insertLayout(1, pButtons);
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

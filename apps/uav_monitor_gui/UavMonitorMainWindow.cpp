#include "UavMonitorMainWindow.h"

#include "AuthenticationMetricsView.h"
#include "AuthenticationMonitorWidget.h"

#include <QDateTime>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

namespace
{
QString strConnectionState(UavMonitorConnectionState stateConnection)
{
    switch (stateConnection)
    {
    case UavMonitorConnectionState::Disconnected:
        return QStringLiteral("未连接");
    case UavMonitorConnectionState::Connecting:
        return QStringLiteral("连接中");
    case UavMonitorConnectionState::Connected:
        return QStringLiteral("已连接");
    }

    return QStringLiteral("未知");
}

QLabel* pStateValue(QWidget* pParent)
{
    QLabel* pLabel = new QLabel(QStringLiteral("未知"), pParent);
    pLabel->setObjectName(QStringLiteral("stateValue"));
    return pLabel;
}
}

UavMonitorMainWindow::UavMonitorMainWindow(
    std::uint16_t u16DefaultManagementPort,
    QWidget* pParent
)
    : QMainWindow(pParent),
      m_ctlNetwork(std::chrono::milliseconds(3000), nullptr),
      m_pHostEdit(nullptr),
      m_pPortSpin(nullptr),
      m_pConnectionValue(nullptr),
      m_pNodeValue(nullptr),
      m_pSenderValue(nullptr),
      m_pReceiverValue(nullptr),
      m_pResponseValue(nullptr),
      m_pFileStatusEdit(nullptr),
      m_pLogEdit(nullptr),
      m_pAuthenticationMonitor(nullptr)
{
    setWindowTitle(QStringLiteral("TESLA 无人机广播节点监控"));
    resize(1220, 760);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("TESLA 无人机广播节点监控"),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateConnectionPage(), QStringLiteral("节点连接"));
    m_pAuthenticationMonitor = new tesla::gui::AuthenticationMonitorWidget(
        pTabs
    );
    pTabs->addTab(m_pAuthenticationMonitor, QStringLiteral("报文与异常"));
    m_ptrMetricsView = std::make_unique<AuthenticationMetricsView>(pTabs);
    pTabs->addTab(m_ptrMetricsView->pComputationPage(), QStringLiteral("计算"));
    pTabs->addTab(m_ptrMetricsView->pEnergyPage(), QStringLiteral("估算能耗"));
    pTabs->addTab(pCreateFileStatusPage(), QStringLiteral("文件"));
    pTabs->addTab(pCreateLogPage(), QStringLiteral("日志"));
    pLayout->addWidget(pTabs, 1);
    setCentralWidget(pCentralWidget);
    applyStyle();

    m_pPortSpin->setValue(u16DefaultManagementPort);

    connect(
        &m_ctlNetwork,
        &UavMonitorNetworkController::stateChanged,
        this,
        &UavMonitorMainWindow::refreshStatus
    );
    connect(
        &m_ctlNetwork,
        &UavMonitorNetworkController::logMessage,
        this,
        &UavMonitorMainWindow::appendLog
    );
    connect(
        &m_ctlNetwork,
        &UavMonitorNetworkController::fileStatusMessage,
        this,
        &UavMonitorMainWindow::appendFileStatus
    );
    connect(
        &m_ctlNetwork,
        &UavMonitorNetworkController::authenticationObservationsChanged,
        this,
        &UavMonitorMainWindow::refreshAuthenticationViews
    );
    connect(
        &m_ctlNetwork,
        &UavMonitorNetworkController::authenticationMetricsChanged,
        this,
        &UavMonitorMainWindow::refreshAuthenticationMetrics
    );
    refreshStatus();
    refreshAuthenticationViews();
    refreshAuthenticationMetrics();
}

UavMonitorMainWindow::~UavMonitorMainWindow() = default;

QWidget* UavMonitorMainWindow::pCreateConnectionPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);

    QHBoxLayout* pConnectionLayout = new QHBoxLayout();
    m_pHostEdit = new QLineEdit(QStringLiteral("127.0.0.1"), pPage);
    m_pPortSpin = new QSpinBox(pPage);
    m_pPortSpin->setRange(1, 65535);
    QPushButton* pConnectButton = new QPushButton(QStringLiteral("连接"), pPage);
    QPushButton* pDisconnectButton = new QPushButton(QStringLiteral("断开"), pPage);
    QPushButton* pRefreshButton = new QPushButton(QStringLiteral("刷新状态"), pPage);
    pConnectButton->setObjectName(QStringLiteral("primaryButton"));
    pConnectionLayout->addWidget(new QLabel(QStringLiteral("NodeAgent IP"), pPage));
    pConnectionLayout->addWidget(m_pHostEdit, 1);
    pConnectionLayout->addWidget(new QLabel(QStringLiteral("端口"), pPage));
    pConnectionLayout->addWidget(m_pPortSpin);
    pConnectionLayout->addWidget(pConnectButton);
    pConnectionLayout->addWidget(pDisconnectButton);
    pConnectionLayout->addWidget(pRefreshButton);
    pLayout->addLayout(pConnectionLayout);

    QGridLayout* pStateLayout = new QGridLayout();
    m_pConnectionValue = pStateValue(pPage);
    m_pNodeValue = pStateValue(pPage);
    m_pSenderValue = pStateValue(pPage);
    m_pReceiverValue = pStateValue(pPage);
    m_pResponseValue = pStateValue(pPage);
    pStateLayout->addWidget(new QLabel(QStringLiteral("TCP"), pPage), 0, 0);
    pStateLayout->addWidget(m_pConnectionValue, 0, 1);
    pStateLayout->addWidget(new QLabel(QStringLiteral("节点名称"), pPage), 1, 0);
    pStateLayout->addWidget(m_pNodeValue, 1, 1);
    pStateLayout->addWidget(new QLabel(QStringLiteral("Sender"), pPage), 2, 0);
    pStateLayout->addWidget(m_pSenderValue, 2, 1);
    pStateLayout->addWidget(new QLabel(QStringLiteral("Receiver"), pPage), 3, 0);
    pStateLayout->addWidget(m_pReceiverValue, 3, 1);
    pStateLayout->addWidget(new QLabel(QStringLiteral("最后响应"), pPage), 4, 0);
    pStateLayout->addWidget(m_pResponseValue, 4, 1);
    pStateLayout->setColumnStretch(1, 1);
    pLayout->addLayout(pStateLayout);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "该程序固定使用MONITOR身份，只查询状态并订阅后续报文、指标和日志事件，"
            "不能配置Sender、上传文件或控制实验。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addWidget(pHintLabel);
    pLayout->addStretch();

    connect(
        pConnectButton,
        &QPushButton::clicked,
        this,
        [this]()
        {
            m_ctlNetwork.connectToNode(
                m_pHostEdit->text(),
                static_cast<std::uint16_t>(m_pPortSpin->value())
            );
        }
    );
    connect(
        pDisconnectButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &UavMonitorNetworkController::disconnectFromNode
    );
    connect(
        pRefreshButton,
        &QPushButton::clicked,
        &m_ctlNetwork,
        &UavMonitorNetworkController::refreshStatus
    );
    return pPage;
}

QWidget* UavMonitorMainWindow::pCreateLogPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    m_pLogEdit = new QTextEdit(pPage);
    m_pLogEdit->setReadOnly(true);
    m_pLogEdit->setPlaceholderText(QStringLiteral("真实MONITOR连接日志将在此显示"));
    pLayout->addWidget(m_pLogEdit);
    return pPage;
}

QWidget* UavMonitorMainWindow::pCreateFileStatusPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "MONITOR只读取节点上报的文件发送或恢复结果，"
            "不会接收原始文件、原始Hash或修改认证状态。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    m_pFileStatusEdit = new QTextEdit(pPage);
    m_pFileStatusEdit->setReadOnly(true);
    m_pFileStatusEdit->setPlaceholderText(QStringLiteral("尚无文件认证结果"));
    pLayout->addWidget(pHintLabel);
    pLayout->addWidget(m_pFileStatusEdit, 1);
    return pPage;
}

void UavMonitorMainWindow::appendFileStatus(const QString& strMessage)
{
    m_pFileStatusEdit->append(
        QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz "))
        + strMessage
    );
}

void UavMonitorMainWindow::refreshAuthenticationViews()
{
    m_pAuthenticationMonitor->setSnapshots(
        m_ctlNetwork.vecPacketObservationSnapshot(),
        m_ctlNetwork.vecFailureObservationSnapshot(),
        m_ctlNetwork.vecDosSummarySnapshot()
    );
}

void UavMonitorMainWindow::refreshAuthenticationMetrics()
{
    const std::vector<tesla::metrics::AuthenticationMetricRecord> vecMetrics =
        m_ctlNetwork.vecMetricSnapshot();
    m_ptrMetricsView->setRecords(vecMetrics);
    m_pAuthenticationMonitor->setMetricSnapshots(vecMetrics);
}

void UavMonitorMainWindow::refreshStatus()
{
    m_pConnectionValue->setText(strConnectionState(m_ctlNetwork.stateConnection()));
    m_pNodeValue->setText(
        m_ctlNetwork.strNodeName().isEmpty()
            ? QStringLiteral("未知")
            : m_ctlNetwork.strNodeName()
    );
    m_pSenderValue->setText(
        m_ctlNetwork.stateConnection() == UavMonitorConnectionState::Connected
            ? (m_ctlNetwork.bSenderRunning()
                ? QStringLiteral("运行中")
                : QStringLiteral("空闲"))
            : QStringLiteral("未知")
    );
    m_pReceiverValue->setText(
        m_ctlNetwork.stateConnection() == UavMonitorConnectionState::Connected
            ? (m_ctlNetwork.bReceiverRunning()
                ? QStringLiteral("监听中")
                : QStringLiteral("停止"))
            : QStringLiteral("未知")
    );
    m_pResponseValue->setText(
        m_ctlNetwork.nLastResponseAgeMilliseconds() >= 0
            ? QStringLiteral("%1ms").arg(
                m_ctlNetwork.nLastResponseAgeMilliseconds()
            )
            : QStringLiteral("未收到")
    );
}

void UavMonitorMainWindow::appendLog(const QString& strMessage)
{
    if (m_pLogEdit != nullptr)
    {
        m_pLogEdit->append(
            QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss.zzz "))
                + strMessage
        );
    }
}

void UavMonitorMainWindow::applyStyle()
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
        QLabel#stateValue {
            background: white;
            border: 1px solid #dbe3ec;
            border-radius: 5px;
            padding: 9px;
            color: #14532d;
            font-weight: 600;
        }
        QLabel#hintLabel {
            color: #64748b;
            padding: 6px;
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
        QTabWidget::pane, QTextEdit {
            background: white;
            border: 1px solid #dbe3ec;
        }
    )"));
}

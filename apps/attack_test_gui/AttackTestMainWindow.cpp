#include "AttackTestMainWindow.h"

#include <QComboBox>
#include <QDateTime>
#include <QFormLayout>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QTabWidget>
#include <QTextEdit>
#include <QVBoxLayout>

namespace
{
QLabel* pStateValue(QWidget* pParent)
{
    QLabel* pLabel = new QLabel(QStringLiteral("未知"), pParent);
    pLabel->setObjectName(QStringLiteral("stateValue"));
    return pLabel;
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
      m_pAttackValue(nullptr),
      m_pLogEdit(nullptr)
{
    setWindowTitle(QStringLiteral("TESLA 独立攻击测试端"));
    resize(1220, 760);

    QWidget* pCentralWidget = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pCentralWidget);
    QLabel* pTitleLabel = new QLabel(
        QStringLiteral("TESLA 独立攻击测试端 · ")
            + m_ctlNetwork.strNodeName(),
        pCentralWidget
    );
    pTitleLabel->setObjectName(QStringLiteral("titleLabel"));
    pLayout->addWidget(pTitleLabel);

    QTabWidget* pTabs = new QTabWidget(pCentralWidget);
    pTabs->addTab(pCreateStatusPage(), QStringLiteral("管理连接"));
    pTabs->addTab(
        pCreatePlaceholderPage(
            QStringLiteral("目标公开上下文"),
            QStringLiteral(
                "阶段10只接收目标Sender公开上下文，"
                "不得接收种子、未披露密钥或完整原始载荷。"
            )
        ),
        QStringLiteral("目标上下文")
    );
    pTabs->addTab(pCreateAttackPlanPage(), QStringLiteral("攻击配置"));
    pTabs->addTab(
        pCreatePlaceholderPage(
            QStringLiteral("攻击报文"),
            QStringLiteral("阶段10显示真实捕获、修改和发送记录，不生成演示记录。")
        ),
        QStringLiteral("攻击报文")
    );
    pTabs->addTab(
        pCreatePlaceholderPage(
            QStringLiteral("执行统计"),
            QStringLiteral(
                "阶段10统计捕获数、实际注入数、重放数、DoS PPS、"
                "总发送字节和错误数。"
            )
        ),
        QStringLiteral("统计")
    );
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
        appendLog(QStringLiteral("攻击测试端网络服务启动失败"));
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
    m_pAttackValue = pStateValue(pPage);
    pLayout->addRow(QStringLiteral("攻击端服务"), m_pServiceValue);
    pLayout->addRow(QStringLiteral("管理TCP客户端"), m_pControlValue);
    pLayout->addRow(QStringLiteral("TESLA组播监听"), m_pMulticastValue);
    pLayout->addRow(QStringLiteral("攻击执行"), m_pAttackValue);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral(
            "攻击端使用独立控制端口和协议。阶段5只监听并立即丢弃组播数据，"
            "不会捕获保存、修改、重放或发送DoS流量。"
        ),
        pPage
    );
    pHintLabel->setWordWrap(true);
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addRow(pHintLabel);
    return pPage;
}

QWidget* AttackTestMainWindow::pCreateAttackPlanPage()
{
    QWidget* pPage = new QWidget(this);
    QFormLayout* pLayout = new QFormLayout(pPage);
    QComboBox* pAttackTypeCombo = new QComboBox(pPage);
    pAttackTypeCombo->addItems({
        QStringLiteral("篡改冲突副本"),
        QStringLiteral("延迟重放"),
        QStringLiteral("UDP拒绝服务")
    });
    QSpinBox* pPacketSpin = new QSpinBox(pPage);
    pPacketSpin->setRange(1, 10000000);
    QSpinBox* pRateSpin = new QSpinBox(pPage);
    pRateSpin->setRange(1, 20000);
    QPushButton* pPrepareButton = new QPushButton(QStringLiteral("准备"), pPage);
    QPushButton* pStartButton = new QPushButton(QStringLiteral("开始"), pPage);
    QPushButton* pStopButton = new QPushButton(QStringLiteral("停止"), pPage);
    QPushButton* pEmergencyButton = new QPushButton(
        QStringLiteral("紧急停止"),
        pPage
    );

    pAttackTypeCombo->setEnabled(false);
    pPacketSpin->setEnabled(false);
    pRateSpin->setEnabled(false);
    pPrepareButton->setEnabled(false);
    pStartButton->setEnabled(false);
    pStopButton->setEnabled(false);
    pEmergencyButton->setEnabled(false);
    pLayout->addRow(QStringLiteral("攻击类型"), pAttackTypeCombo);
    pLayout->addRow(QStringLiteral("目标报文编号"), pPacketSpin);
    pLayout->addRow(QStringLiteral("DoS PPS"), pRateSpin);
    pLayout->addRow(pPrepareButton);
    pLayout->addRow(pStartButton);
    pLayout->addRow(pStopButton);
    pLayout->addRow(pEmergencyButton);

    QLabel* pHintLabel = new QLabel(
        QStringLiteral("阶段10完成参数校验、同步执行和安全上限后启用。"),
        pPage
    );
    pHintLabel->setObjectName(QStringLiteral("hintLabel"));
    pLayout->addRow(pHintLabel);
    return pPage;
}

QWidget* AttackTestMainWindow::pCreatePlaceholderPage(
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

QWidget* AttackTestMainWindow::pCreateLogPage()
{
    QWidget* pPage = new QWidget(this);
    QVBoxLayout* pLayout = new QVBoxLayout(pPage);
    m_pLogEdit = new QTextEdit(pPage);
    m_pLogEdit->setReadOnly(true);
    m_pLogEdit->setPlaceholderText(QStringLiteral("真实攻击端连接日志将在此显示"));
    pLayout->addWidget(m_pLogEdit);
    return pPage;
}

void AttackTestMainWindow::refreshStatus()
{
    m_pServiceValue->setText(
        m_ctlNetwork.bIsRunning()
            ? QStringLiteral("运行中")
            : QStringLiteral("停止")
    );
    m_pControlValue->setText(QStringLiteral("%1个管理客户端")
        .arg(m_ctlNetwork.nConnectedClientCount()));
    m_pMulticastValue->setText(
        m_ctlNetwork.bMulticastListening()
            ? QStringLiteral("监听中")
            : QStringLiteral("未监听")
    );
    m_pAttackValue->setText(
        m_ctlNetwork.bAttackRunning()
            ? QStringLiteral("运行中")
            : QStringLiteral("空闲")
    );
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
        QLabel#sectionTitleLabel {
            font-size: 18px;
            font-weight: 600;
            color: #7f1d1d;
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
        QPushButton {
            background: white;
            border: 1px solid #cbd5e1;
            border-radius: 5px;
            padding: 7px 16px;
        }
        QPushButton:disabled {
            color: #94a3b8;
            background: #eef2f7;
        }
        QTabWidget::pane, QTextEdit {
            background: white;
            border: 1px solid #dbe3ec;
        }
    )"));
}

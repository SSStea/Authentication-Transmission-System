#pragma once

#include "AttackTestNetworkController.h"

#include <QMainWindow>

#include <cstdint>
#include <vector>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTextEdit;

/** @brief 独立认证鲁棒性测试端主窗口，配置计划并展示真实捕获与执行结果。 */
class AttackTestMainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit AttackTestMainWindow(
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16ControlPort = 38030,
        std::uint16_t u16MulticastPort = 39020,
        QWidget* pParent = nullptr
    );

private:
    QWidget* pCreateStatusPage();
    QWidget* pCreateContextPage();
    QWidget* pCreatePlanPage();
    QWidget* pCreateRecordPage();
    QWidget* pCreateStatisticsPage();
    QWidget* pCreateLogPage();
    void refreshStatus();
    void refreshContext();
    void refreshPlanControls();
    void refreshRecords();
    void refreshStatistics();
    void submitPlan();
    void stopLocally(bool bEmergency);
    void exportRecords(bool bJson);
    bool bValidatePlanInputs(QString& strError, bool& bThresholdExceeded) const;
    std::vector<std::uint32_t> vecPacketIndexes(QString& strError) const;
    QString strDatagramMessage(const QByteArray& arrDatagram) const;
    void appendLog(const QString& strMessage);
    void applyStyle();

    AttackTestNetworkController m_ctlNetwork;
    QLabel*                     m_pServiceValue;
    QLabel*                     m_pControlValue;
    QLabel*                     m_pMulticastValue;
    QLabel*                     m_pExecutionValue;
    QLabel*                     m_pContextRoundValue;
    QLabel*                     m_pContextSenderValue;
    QLabel*                     m_pContextNetworkValue;
    QLabel*                     m_pContextParametersValue;
    QComboBox*                  m_pTypeCombo;
    QLineEdit*                  m_pPacketIndexesEdit;
    QSpinBox*                   m_pRepeatSpin;
    QSpinBox*                   m_pOffsetSpin;
    QSpinBox*                   m_pMaskSpin;
    QSpinBox*                   m_pDelaySpin;
    QSpinBox*                   m_pGapSpin;
    QSpinBox*                   m_pRateSpin;
    QSpinBox*                   m_pDurationSpin;
    QSpinBox*                   m_pBytesSpin;
    QCheckBox*                  m_pThresholdConfirmCheck;
    QLabel*                     m_pValidationLabel;
    QPushButton*                m_pSubmitButton;
    QPushButton*                m_pLocalStopButton;
    QPushButton*                m_pLocalEmergencyButton;
    QTableWidget*               m_pRecordTable;
    QLabel*                     m_pCapturedValue;
    QLabel*                     m_pSentValue;
    QLabel*                     m_pRateValue;
    QLabel*                     m_pByteValue;
    QLabel*                     m_pDelayValue;
    QLabel*                     m_pErrorValue;
    QTextEdit*                  m_pLogEdit;
};

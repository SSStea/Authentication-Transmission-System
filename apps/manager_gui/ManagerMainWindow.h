#pragma once

#include "ManagerAuthenticationController.h"
#include "ManagerNetworkController.h"

#include <QMainWindow>
#include <QSet>

#include <cstdint>

class QLabel;
class QComboBox;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTextEdit;

/** @brief 集中管理GUI主窗口，负责阶段6文本轮次输入、校验和运行控制。 */
class ManagerMainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit ManagerMainWindow(
        std::uint16_t u16DiscoveryPort = 37020,
        QWidget* pParent = nullptr
    );

private:
    QWidget* pCreateNodePage();
    QWidget* pCreateConfigurationPage();
    QWidget* pCreateExperimentPage();
    QWidget* pCreateAttackPage();
    QWidget* pCreateFileComparisonPage();
    QWidget* pCreateStagePlaceholder(
        const QString& strTitle,
        const QString& strDescription
    );
    void refreshNodeTables();
    void validateAuthenticationInputs();
    void refreshAuthenticationActions();
    void prepareTextRound();
    void startTextRound();
    void pauseTextRound();
    void resumeTextRound();
    void stopTextRound();
    void applyStyle();

    ManagerNetworkController m_ctlNetwork;
    ManagerAuthenticationController m_ctlAuthentication;
    QTableWidget*             m_pNodeTable;
    QTableWidget*             m_pAttackTable;
    QLabel*                   m_pStatusLabel;
    QComboBox*                m_pModeCombo;
    QComboBox*                m_pAlgorithmCombo;
    QSpinBox*                 m_pIntervalSpin;
    QSpinBox*                 m_pPacketsSpin;
    QSpinBox*                 m_pRepeatSpin;
    QSpinBox*                 m_pDisclosureSpin;
    QSpinBox*                 m_pGroupSpin;
    QSpinBox*                 m_pThresholdSpin;
    QTextEdit*                m_pTextEdit;
    QLabel*                   m_pValidationLabel;
    QLabel*                   m_pCommunicationValue;
    QPushButton*              m_pPrepareButton;
    QPushButton*              m_pStartButton;
    QPushButton*              m_pPauseButton;
    QPushButton*              m_pResumeButton;
    QPushButton*              m_pStopButton;
    bool                      m_bAuthenticationInputsValid;
    bool                      m_bPreparedConfigurationCurrent;
    QSet<QString>             m_setSelectedSenderEndpoints;
};

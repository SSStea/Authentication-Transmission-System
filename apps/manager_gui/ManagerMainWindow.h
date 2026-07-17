#pragma once

#include "ManagerAuthenticationController.h"
#include "ManagerNetworkController.h"

#include <QMainWindow>
#include <QByteArray>
#include <QSet>

#include <cstdint>
#include <memory>

class QLabel;
class QComboBox;
class QPushButton;
class QSpinBox;
class QTableWidget;
class QTextEdit;

/** @brief 集中管理GUI主窗口，负责文本/文件轮次输入、校验和运行控制。 */
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
    void refreshSelectedFileInformation();
    void selectFile();
    void prepareRound();
    void startRound();
    void pauseRound();
    void resumeRound();
    void stopRound();
    void applyStyle();

    ManagerNetworkController m_ctlNetwork;
    ManagerAuthenticationController m_ctlAuthentication;
    QTableWidget*             m_pNodeTable;
    QTableWidget*             m_pAttackTable;
    QLabel*                   m_pStatusLabel;
    QComboBox*                m_pModeCombo;
    QComboBox*                m_pAlgorithmCombo;
    QComboBox*                m_pPayloadCombo;
    QSpinBox*                 m_pIntervalSpin;
    QSpinBox*                 m_pPacketsSpin;
    QSpinBox*                 m_pRepeatSpin;
    QSpinBox*                 m_pDisclosureSpin;
    QSpinBox*                 m_pGroupSpin;
    QSpinBox*                 m_pThresholdSpin;
    QTextEdit*                m_pTextEdit;
    QPushButton*              m_pSelectFileButton;
    QLabel*                   m_pFileInfoLabel;
    QTableWidget*             m_pFileComparisonTable;
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
    QString                   m_strSelectedFilePath;
    std::shared_ptr<const QByteArray> m_ptrSelectedFileBytes;
    QByteArray                m_arrSelectedFileSha256;
};

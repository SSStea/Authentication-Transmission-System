#pragma once

#include "ManagerNetworkController.h"

#include <QMainWindow>
#include <QSet>

#include <cstdint>

class QLabel;
class QTableWidget;

/** @brief 集中管理GUI阶段5主窗口，固定四类职责页面但不提前实现认证业务。 */
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
    void applyStyle();

    ManagerNetworkController m_ctlNetwork;
    QTableWidget*             m_pNodeTable;
    QTableWidget*             m_pAttackTable;
    QLabel*                   m_pStatusLabel;
    QSet<QString>             m_setSelectedSenderEndpoints;
};

#pragma once

#include "AttackTestNetworkController.h"

#include <QMainWindow>

#include <cstdint>

class QLabel;
class QTextEdit;

/** @brief 独立攻击测试端阶段5主窗口，只展示连接职责和禁用的后续攻击入口。 */
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
    QWidget* pCreateAttackPlanPage();
    QWidget* pCreatePlaceholderPage(
        const QString& strTitle,
        const QString& strDescription
    );
    QWidget* pCreateLogPage();
    void refreshStatus();
    void appendLog(const QString& strMessage);
    void applyStyle();

    AttackTestNetworkController m_ctlNetwork;
    QLabel*                     m_pServiceValue;
    QLabel*                     m_pControlValue;
    QLabel*                     m_pMulticastValue;
    QLabel*                     m_pAttackValue;
    QTextEdit*                  m_pLogEdit;
};

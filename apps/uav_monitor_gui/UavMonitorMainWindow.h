#pragma once

#include "UavMonitorNetworkController.h"

#include <QMainWindow>

#include <cstdint>

class QLabel;
class QLineEdit;
class QSpinBox;
class QTextEdit;
namespace tesla::gui
{
class AuthenticationMonitorWidget;
}

/** @brief 无人机广播节点监控GUI阶段5主窗口。 */
class UavMonitorMainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit UavMonitorMainWindow(
        std::uint16_t u16DefaultManagementPort = 38020,
        QWidget* pParent = nullptr
    );

private:
    QWidget* pCreateConnectionPage();
    QWidget* pCreatePlaceholderPage(
        const QString& strTitle,
        const QString& strDescription
    );
    QWidget* pCreateFileStatusPage();
    QWidget* pCreateLogPage();
    void refreshStatus();
    void appendLog(const QString& strMessage);
    void appendFileStatus(const QString& strMessage);
    void refreshAuthenticationViews();
    void applyStyle();

    UavMonitorNetworkController m_ctlNetwork;
    QLineEdit*                  m_pHostEdit;
    QSpinBox*                   m_pPortSpin;
    QLabel*                     m_pConnectionValue;
    QLabel*                     m_pNodeValue;
    QLabel*                     m_pSenderValue;
    QLabel*                     m_pReceiverValue;
    QLabel*                     m_pResponseValue;
    QTextEdit*                  m_pFileStatusEdit;
    QTextEdit*                  m_pLogEdit;
    tesla::gui::AuthenticationMonitorWidget* m_pAuthenticationMonitor;
};

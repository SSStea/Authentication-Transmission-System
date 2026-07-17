#pragma once

#include "UavMonitorNetworkController.h"

#include <QMainWindow>

#include <cstdint>
#include <memory>

class QLabel;
class QLineEdit;
class QSpinBox;
class QTextEdit;
class AuthenticationMetricsView;
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
    ~UavMonitorMainWindow() override;

private:
    QWidget* pCreateConnectionPage();
    QWidget* pCreateFileStatusPage();
    QWidget* pCreateLogPage();
    void refreshStatus();
    void appendLog(const QString& strMessage);
    void appendFileStatus(const QString& strMessage);
    void refreshAuthenticationViews();
    void refreshAuthenticationMetrics();
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
    std::unique_ptr<AuthenticationMetricsView> m_ptrMetricsView;
};

#pragma once

#include "PcNodeNetworkController.h"

#include <QMainWindow>

#include <cstdint>

class QLabel;
class QTextEdit;
class PcLocalKeyChainWidget;
class PcMatrixLocationWidget;
namespace tesla::gui
{
class AuthenticationMonitorWidget;
}

/** @brief PC广播节点阶段5主窗口，保留本地算法和矩阵展示边界。 */
class PcNodeMainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit PcNodeMainWindow(
        std::uint16_t u16DiscoveryPort = 37020,
        std::uint16_t u16ManagementPort = 38020,
        QWidget* pParent = nullptr
    );

private:
    QWidget* pCreateStatusPage();
    QWidget* pCreateFileStatusPage();
    QWidget* pCreateLogPage();
    void refreshStatus();
    void appendLog(const QString& strMessage);
    void appendFileStatus(const QString& strMessage);
    void refreshAuthenticationViews();
    void applyStyle();

    PcNodeNetworkController m_ctlNetwork;
    QLabel*                 m_pServiceValue;
    QLabel*                 m_pTcpValue;
    QLabel*                 m_pUdpValue;
    QLabel*                 m_pSenderValue;
    QLabel*                 m_pReceiverValue;
    QTextEdit*              m_pFileStatusEdit;
    QTextEdit*              m_pLogEdit;
    tesla::gui::AuthenticationMonitorWidget* m_pAuthenticationMonitor;
    PcLocalKeyChainWidget*  m_pKeyChainWidget;
    PcMatrixLocationWidget* m_pMatrixWidget;
};

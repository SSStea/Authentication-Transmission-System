#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>

#include "UavMonitorMainWindow.h"
#include "UavMonitorNetworkController.h"

int main(int nArgc, char* arrArgv[])
{
    QApplication appApplication(nArgc, arrArgv);
    QCoreApplication::setApplicationName(QStringLiteral("tesla_uav_monitor_gui"));

    QCommandLineParser prsCommandLine;
    prsCommandLine.addHelpOption();
    prsCommandLine.addOption({
        QStringLiteral("stage5-smoke-test"),
        QStringLiteral("Open the stage5 window offscreen and exit automatically.")
    });
    prsCommandLine.addOption({
        QStringLiteral("stage5-connection-test"),
        QStringLiteral("Connect as MONITOR and require one valid status response.")
    });
    prsCommandLine.addOption({
        QStringLiteral("host"),
        QStringLiteral("NodeAgent or PC node IPv4 address."),
        QStringLiteral("address"),
        QStringLiteral("127.0.0.1")
    });
    prsCommandLine.addOption({
        QStringLiteral("management-port"),
        QStringLiteral("Override the target management port."),
        QStringLiteral("port"),
        QStringLiteral("38020")
    });
    prsCommandLine.process(appApplication);

    bool bPortValid = false;
    const int nManagementPort = prsCommandLine.value(
        QStringLiteral("management-port")
    ).toInt(&bPortValid);
    if (!bPortValid || nManagementPort <= 0 || nManagementPort > 65535)
    {
        return 2;
    }

    if (prsCommandLine.isSet(QStringLiteral("stage5-connection-test")))
    {
        UavMonitorNetworkController ctlNetwork;
        QObject::connect(
            &ctlNetwork,
            &UavMonitorNetworkController::statusUpdated,
            &appApplication,
            [&appApplication, &ctlNetwork]()
            {
                appApplication.exit(
                    ctlNetwork.stateConnection()
                            == UavMonitorConnectionState::Connected
                        && !ctlNetwork.strNodeName().isEmpty()
                        && ctlNetwork.bReceiverRunning()
                        ? 0
                        : 1
                );
            }
        );
        ctlNetwork.connectToNode(
            prsCommandLine.value(QStringLiteral("host")),
            static_cast<std::uint16_t>(nManagementPort)
        );
        QTimer::singleShot(
            5000,
            &appApplication,
            [&appApplication]()
            {
                appApplication.exit(1);
            }
        );
        return appApplication.exec();
    }

    UavMonitorMainWindow wndMain(
        static_cast<std::uint16_t>(nManagementPort)
    );
    wndMain.show();

    if (prsCommandLine.isSet(QStringLiteral("stage5-smoke-test")))
    {
        QTimer::singleShot(250, &appApplication, &QCoreApplication::quit);
    }

    return appApplication.exec();
}

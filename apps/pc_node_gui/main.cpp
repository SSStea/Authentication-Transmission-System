#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>

#include "PcNodeMainWindow.h"
#include "PcNodeNetworkController.h"

#include <iostream>

int main(int nArgc, char* arrArgv[])
{
    QApplication appApplication(nArgc, arrArgv);
    QCoreApplication::setApplicationName(QStringLiteral("tesla_pc_node_gui"));

    QCommandLineParser prsCommandLine;
    prsCommandLine.addHelpOption();
    prsCommandLine.addOption({
        QStringLiteral("stage5-smoke-test"),
        QStringLiteral("Open the stage5 window offscreen and exit automatically.")
    });
    prsCommandLine.addOption({
        QStringLiteral("stage5-service-test"),
        QStringLiteral("Run only the PC node stage5 network service.")
    });
    prsCommandLine.addOption({
        QStringLiteral("discovery-port"),
        QStringLiteral("Override the internal discovery port."),
        QStringLiteral("port"),
        QStringLiteral("37020")
    });
    prsCommandLine.addOption({
        QStringLiteral("management-port"),
        QStringLiteral("Override the PC node management port."),
        QStringLiteral("port"),
        QStringLiteral("38020")
    });
    prsCommandLine.process(appApplication);

    bool bDiscoveryPortValid = false;
    bool bManagementPortValid = false;
    const int nDiscoveryPort = prsCommandLine.value(
        QStringLiteral("discovery-port")
    ).toInt(&bDiscoveryPortValid);
    const int nManagementPort = prsCommandLine.value(
        QStringLiteral("management-port")
    ).toInt(&bManagementPortValid);
    if (!bDiscoveryPortValid || !bManagementPortValid
        || nDiscoveryPort <= 0 || nDiscoveryPort > 65535
        || nManagementPort <= 0 || nManagementPort > 65535)
    {
        return 2;
    }

    if (prsCommandLine.isSet(QStringLiteral("stage5-service-test")))
    {
        PcNodeNetworkController ctlNetwork(
            static_cast<std::uint16_t>(nDiscoveryPort),
            static_cast<std::uint16_t>(nManagementPort)
        );
        QObject::connect(
            &ctlNetwork,
            &PcNodeNetworkController::logMessage,
            [](const QString& strMessage)
            {
                std::cerr << strMessage.toStdString() << std::endl;
            }
        );
        if (!ctlNetwork.bStart())
        {
            return 1;
        }

        QTimer::singleShot(30000, &appApplication, &QCoreApplication::quit);
        return appApplication.exec();
    }

    PcNodeMainWindow wndMain(
        static_cast<std::uint16_t>(nDiscoveryPort),
        static_cast<std::uint16_t>(nManagementPort)
    );
    wndMain.show();

    if (prsCommandLine.isSet(QStringLiteral("stage5-smoke-test")))
    {
        QTimer::singleShot(250, &appApplication, &QCoreApplication::quit);
    }

    return appApplication.exec();
}

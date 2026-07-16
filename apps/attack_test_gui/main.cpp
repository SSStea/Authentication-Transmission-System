#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>

#include "AttackTestMainWindow.h"
#include "AttackTestNetworkController.h"

#include <iostream>

int main(int nArgc, char* arrArgv[])
{
    QApplication appApplication(nArgc, arrArgv);
    QCoreApplication::setApplicationName(QStringLiteral("tesla_attack_test_gui"));

    QCommandLineParser prsCommandLine;
    prsCommandLine.addHelpOption();
    prsCommandLine.addOption({
        QStringLiteral("stage5-smoke-test"),
        QStringLiteral("Open the stage5 window offscreen and exit automatically.")
    });
    prsCommandLine.addOption({
        QStringLiteral("stage5-service-test"),
        QStringLiteral("Run only the attack endpoint stage5 services.")
    });
    prsCommandLine.addOption({
        QStringLiteral("discovery-port"),
        QStringLiteral("Override the internal discovery port."),
        QStringLiteral("port"),
        QStringLiteral("37020")
    });
    prsCommandLine.addOption({
        QStringLiteral("control-port"),
        QStringLiteral("Override the attack control port."),
        QStringLiteral("port"),
        QStringLiteral("38030")
    });
    prsCommandLine.addOption({
        QStringLiteral("multicast-port"),
        QStringLiteral("Override the TESLA multicast listening port."),
        QStringLiteral("port"),
        QStringLiteral("39020")
    });
    prsCommandLine.process(appApplication);

    bool bDiscoveryPortValid = false;
    bool bControlPortValid = false;
    bool bMulticastPortValid = false;
    const int nDiscoveryPort = prsCommandLine.value(
        QStringLiteral("discovery-port")
    ).toInt(&bDiscoveryPortValid);
    const int nControlPort = prsCommandLine.value(
        QStringLiteral("control-port")
    ).toInt(&bControlPortValid);
    const int nMulticastPort = prsCommandLine.value(
        QStringLiteral("multicast-port")
    ).toInt(&bMulticastPortValid);
    if (!bDiscoveryPortValid || !bControlPortValid || !bMulticastPortValid
        || nDiscoveryPort <= 0 || nDiscoveryPort > 65535
        || nControlPort <= 0 || nControlPort > 65535
        || nMulticastPort <= 0 || nMulticastPort > 65535)
    {
        return 2;
    }

    if (prsCommandLine.isSet(QStringLiteral("stage5-service-test")))
    {
        AttackTestNetworkController ctlNetwork(
            static_cast<std::uint16_t>(nDiscoveryPort),
            static_cast<std::uint16_t>(nControlPort),
            QStringLiteral("239.10.10.10"),
            static_cast<std::uint16_t>(nMulticastPort)
        );
        QObject::connect(
            &ctlNetwork,
            &AttackTestNetworkController::logMessage,
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

    AttackTestMainWindow wndMain(
        static_cast<std::uint16_t>(nDiscoveryPort),
        static_cast<std::uint16_t>(nControlPort),
        static_cast<std::uint16_t>(nMulticastPort)
    );
    wndMain.show();

    if (prsCommandLine.isSet(QStringLiteral("stage5-smoke-test")))
    {
        QTimer::singleShot(250, &appApplication, &QCoreApplication::quit);
    }

    return appApplication.exec();
}

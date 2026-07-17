#include <QApplication>
#include <QCommandLineParser>
#include <QTimer>

#include "ManagerMainWindow.h"
#include "ManagerNetworkController.h"

#include <iostream>

int main(int nArgc, char* arrArgv[])
{
    QApplication appApplication(nArgc, arrArgv);
    QCoreApplication::setApplicationName(QStringLiteral("tesla_manager_gui"));

    QCommandLineParser prsCommandLine;
    prsCommandLine.addHelpOption();
    prsCommandLine.addOption({
        QStringLiteral("stage5-smoke-test"),
        QStringLiteral("Open the stage5 window offscreen and exit automatically.")
    });
    prsCommandLine.addOption({
        QStringLiteral("stage5-connection-test"),
        QStringLiteral("Discover and connect one PC node and one attack endpoint.")
    });
    prsCommandLine.addOption({
        QStringLiteral("discovery-port"),
        QStringLiteral("Override the internal discovery port for an isolated test."),
        QStringLiteral("port"),
        QStringLiteral("37020")
    });
    prsCommandLine.addOption({
        QStringLiteral("additional-discovery-port"),
        QStringLiteral("Scan one additional discovery port during an isolated test."),
        QStringLiteral("port")
    });
    prsCommandLine.process(appApplication);

    bool bPortValid = false;
    const int nDiscoveryPort = prsCommandLine.value(
        QStringLiteral("discovery-port")
    ).toInt(&bPortValid);
    if (!bPortValid || nDiscoveryPort <= 0 || nDiscoveryPort > 65535)
    {
        return 2;
    }

    if (prsCommandLine.isSet(QStringLiteral("stage5-connection-test")))
    {
        ManagerNetworkController ctlNetwork(
            static_cast<std::uint16_t>(nDiscoveryPort)
        );
        if (prsCommandLine.isSet(QStringLiteral("additional-discovery-port")))
        {
            bool bAdditionalPortValid = false;
            const int nAdditionalDiscoveryPort = prsCommandLine.value(
                QStringLiteral("additional-discovery-port")
            ).toInt(&bAdditionalPortValid);
            if (!bAdditionalPortValid
                || nAdditionalDiscoveryPort <= 0
                || nAdditionalDiscoveryPort > 65535)
            {
                return 2;
            }

            // Windows同机进程无法可靠共享单播发现报文，隔离测试使用第二扫描端口。
            ctlNetwork.addDiscoveryScanPort(
                static_cast<std::uint16_t>(nAdditionalDiscoveryPort)
            );
        }
        QObject::connect(
            &ctlNetwork,
            &ManagerNetworkController::logMessage,
            [](const QString& strMessage)
            {
                std::cerr << strMessage.toStdString() << std::endl;
            }
        );
        ctlNetwork.start();
        ctlNetwork.scanNodes();

        QTimer::singleShot(
            800,
            &ctlNetwork,
            &ManagerNetworkController::connectAll
        );
        QTimer::singleShot(
            2200,
            &ctlNetwork,
            &ManagerNetworkController::refreshStatus
        );
        QTimer::singleShot(
            4500,
            &appApplication,
            [&appApplication, &ctlNetwork]()
            {
                bool bPcConnected = false;
                bool bAttackConnected = false;
                for (const ManagerNodeSnapshot& snpNode
                    : ctlNetwork.vecNodeSnapshots())
                {
                    std::cerr
                        << "role=" << static_cast<int>(snpNode.roleNode())
                        << " ip=" << snpNode.strIpAddress().toStdString()
                        << " port=" << snpNode.u16ManagementPort()
                        << " state=" << static_cast<int>(snpNode.stateConnection())
                        << " receiver=" << snpNode.bReceiverRunning()
                        << " multicast=" << snpNode.bMulticastListening()
                        << std::endl;

                    if (snpNode.roleNode() == tesla::protocol::NodeRole::PcBroadcast
                        && snpNode.stateConnection()
                            == ManagerConnectionState::Connected
                        && snpNode.bReceiverRunning())
                    {
                        bPcConnected = true;
                    }
                    else if (snpNode.roleNode()
                            == tesla::protocol::NodeRole::Attacker
                        && snpNode.stateConnection()
                            == ManagerConnectionState::Connected
                        && snpNode.bMulticastListening())
                    {
                        bAttackConnected = true;
                    }
                }

                appApplication.exit(bPcConnected && bAttackConnected ? 0 : 1);
            }
        );
        return appApplication.exec();
    }

    ManagerMainWindow wndMain(static_cast<std::uint16_t>(nDiscoveryPort));
    wndMain.show();

    if (prsCommandLine.isSet(QStringLiteral("stage5-smoke-test")))
    {
        QTimer::singleShot(250, &appApplication, &QCoreApplication::quit);
    }

    return appApplication.exec();
}

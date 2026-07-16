#include <QCommandLineParser>
#include <QCoreApplication>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>
#include <QThread>

#include <iostream>

namespace
{
bool bRunProcess(
    const QString& strExecutable,
    const QStringList& listArguments,
    int nTimeoutMilliseconds,
    QString& strFailure
)
{
    QProcess prcProcess;
    prcProcess.setProcessEnvironment(QProcessEnvironment::systemEnvironment());
    prcProcess.start(strExecutable, listArguments);
    if (!prcProcess.waitForStarted(5000))
    {
        strFailure = QStringLiteral("Unable to start %1: %2")
            .arg(strExecutable, prcProcess.errorString());
        return false;
    }

    if (!prcProcess.waitForFinished(nTimeoutMilliseconds))
    {
        prcProcess.kill();
        prcProcess.waitForFinished(3000);
        strFailure = QStringLiteral("Process timed out: %1").arg(strExecutable);
        return false;
    }

    if (prcProcess.exitStatus() != QProcess::NormalExit
        || prcProcess.exitCode() != 0)
    {
        strFailure = QStringLiteral("%1 exited with code %2: %3")
            .arg(strExecutable)
            .arg(prcProcess.exitCode())
            .arg(QString::fromLocal8Bit(prcProcess.readAllStandardError()));
        return false;
    }

    return true;
}

bool bStartService(
    QProcess& prcProcess,
    const QString& strExecutable,
    const QStringList& listArguments,
    QString& strFailure
)
{
    prcProcess.setProcessEnvironment(QProcessEnvironment::systemEnvironment());
    prcProcess.start(strExecutable, listArguments);
    if (!prcProcess.waitForStarted(5000))
    {
        strFailure = QStringLiteral("Unable to start service %1: %2")
            .arg(strExecutable, prcProcess.errorString());
        return false;
    }

    return true;
}

void stopService(QProcess& prcProcess)
{
    if (prcProcess.state() == QProcess::NotRunning)
    {
        return;
    }

    prcProcess.terminate();
    if (!prcProcess.waitForFinished(1500))
    {
        prcProcess.kill();
        prcProcess.waitForFinished(3000);
    }
}
}

int main(int nArgc, char* arrArgv[])
{
    QCoreApplication appApplication(nArgc, arrArgv);
    QCommandLineParser prsCommandLine;
    prsCommandLine.addHelpOption();
    prsCommandLine.addOption({
        QStringLiteral("manager"),
        QStringLiteral("Path to tesla_manager_gui."),
        QStringLiteral("path")
    });
    prsCommandLine.addOption({
        QStringLiteral("pc-node"),
        QStringLiteral("Path to tesla_pc_node_gui."),
        QStringLiteral("path")
    });
    prsCommandLine.addOption({
        QStringLiteral("uav-monitor"),
        QStringLiteral("Path to tesla_uav_monitor_gui."),
        QStringLiteral("path")
    });
    prsCommandLine.addOption({
        QStringLiteral("attack-test"),
        QStringLiteral("Path to tesla_attack_test_gui."),
        QStringLiteral("path")
    });
    prsCommandLine.process(appApplication);

    const QString strManager = prsCommandLine.value(QStringLiteral("manager"));
    const QString strPcNode = prsCommandLine.value(QStringLiteral("pc-node"));
    const QString strUavMonitor = prsCommandLine.value(
        QStringLiteral("uav-monitor")
    );
    const QString strAttackTest = prsCommandLine.value(
        QStringLiteral("attack-test")
    );
    if (!QFileInfo::exists(strManager)
        || !QFileInfo::exists(strPcNode)
        || !QFileInfo::exists(strUavMonitor)
        || !QFileInfo::exists(strAttackTest))
    {
        std::cerr << "One or more stage5 GUI executables are missing." << std::endl;
        return 1;
    }

    const int nPortBase = 42000
        + static_cast<int>(QCoreApplication::applicationPid() % 5000);
    const QString strDiscoveryPort = QString::number(nPortBase);
    const QString strPcPort = QString::number(nPortBase + 1);
    const QString strAttackPort = QString::number(nPortBase + 2);
    const QString strMulticastPort = QString::number(nPortBase + 3);
    QString strFailure;

    // 先验证四套主窗口都能在无显示器环境中完成构造和安全退出。
    if (!bRunProcess(
            strManager,
            {
                QStringLiteral("--stage5-smoke-test"),
                QStringLiteral("--discovery-port"),
                strDiscoveryPort
            },
            5000,
            strFailure
        )
        || !bRunProcess(
            strPcNode,
            {
                QStringLiteral("--stage5-smoke-test"),
                QStringLiteral("--discovery-port"),
                strDiscoveryPort,
                QStringLiteral("--management-port"),
                strPcPort
            },
            5000,
            strFailure
        )
        || !bRunProcess(
            strUavMonitor,
            {
                QStringLiteral("--stage5-smoke-test"),
                QStringLiteral("--management-port"),
                strPcPort
            },
            5000,
            strFailure
        )
        || !bRunProcess(
            strAttackTest,
            {
                QStringLiteral("--stage5-smoke-test"),
                QStringLiteral("--discovery-port"),
                strDiscoveryPort,
                QStringLiteral("--control-port"),
                strAttackPort,
                QStringLiteral("--multicast-port"),
                strMulticastPort
            },
            5000,
            strFailure
        ))
    {
        std::cerr << strFailure.toStdString() << std::endl;
        return 1;
    }

    QProcess prcPcNode;
    QProcess prcAttackTest;
    const bool bPcStarted = bStartService(
        prcPcNode,
        strPcNode,
        {
            QStringLiteral("--stage5-service-test"),
            QStringLiteral("--discovery-port"),
            strDiscoveryPort,
            QStringLiteral("--management-port"),
            strPcPort
        },
        strFailure
    );
    const bool bAttackStarted = bStartService(
        prcAttackTest,
        strAttackTest,
        {
            QStringLiteral("--stage5-service-test"),
            QStringLiteral("--discovery-port"),
            strDiscoveryPort,
            QStringLiteral("--control-port"),
            strAttackPort,
            QStringLiteral("--multicast-port"),
            strMulticastPort
        },
        strFailure
    );
    if (!bPcStarted || !bAttackStarted)
    {
        stopService(prcPcNode);
        stopService(prcAttackTest);
        std::cerr << strFailure.toStdString() << std::endl;
        return 1;
    }

    QThread::msleep(800);
    const bool bManagerConnected = bRunProcess(
        strManager,
        {
            QStringLiteral("--stage5-connection-test"),
            QStringLiteral("--discovery-port"),
            strDiscoveryPort
        },
        10000,
        strFailure
    );
    const bool bMonitorConnected = bRunProcess(
        strUavMonitor,
        {
            QStringLiteral("--stage5-connection-test"),
            QStringLiteral("--host"),
            QStringLiteral("127.0.0.1"),
            QStringLiteral("--management-port"),
            strPcPort
        },
        8000,
        strFailure
    );

    stopService(prcPcNode);
    stopService(prcAttackTest);
    if (!bManagerConnected || !bMonitorConnected)
    {
        std::cerr << strFailure.toStdString() << std::endl;
        return 1;
    }

    std::cout << "All stage5 GUI and local connection tests passed." << std::endl;
    return 0;
}
